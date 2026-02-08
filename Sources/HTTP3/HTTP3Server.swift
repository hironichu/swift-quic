/// HTTP/3 Server (RFC 9114)
///
/// A server that listens for incoming QUIC connections and handles
/// HTTP/3 requests. The server manages multiple concurrent HTTP/3
/// connections and dispatches incoming requests to a user-provided
/// request handler.
///
/// ## Architecture
///
/// The server operates in layers:
/// 1. **QUIC Listener** — Accepts incoming QUIC connections
/// 2. **HTTP/3 Connection** — Manages HTTP/3 state per QUIC connection
/// 3. **Request Handler** — User-provided closure for processing requests
///
/// ## Usage
///
/// ```swift
/// let server = HTTP3Server(settings: HTTP3Settings())
///
/// // Register a request handler
/// server.onRequest { context in
///     let response = HTTP3Response(
///         status: 200,
///         headers: [("content-type", "text/plain")],
///         body: Data("Hello, HTTP/3!".utf8)
///     )
///     try await context.respond(response)
/// }
///
/// // Start listening
/// try await server.listen(
///     quicConnection: quicListener,
///     address: SocketAddress(ipAddress: "0.0.0.0", port: 443)
/// )
///
/// // Later, stop the server
/// await server.stop()
/// ```
///
/// ## Thread Safety
///
/// `HTTP3Server` is an `actor`, ensuring all mutable state is
/// accessed serially. Incoming connections and requests are handled
/// concurrently via structured `Task`s.

import Foundation
import QUICCore
import QPACK
import QUIC  // For ManagedConnection type and handshake state checking

// MARK: - HTTP/3 Server

/// HTTP/3 server for handling incoming requests over QUIC
///
/// Accepts QUIC connections, establishes HTTP/3 sessions, and
/// dispatches incoming requests to a registered handler.
public actor HTTP3Server {

    // MARK: - Types

    /// Request handler closure type
    ///
    /// Called for each incoming HTTP/3 request. The handler receives
    /// an `HTTP3RequestContext` that includes the request and a method
    /// to send back a response.
    public typealias RequestHandler = @Sendable (HTTP3RequestContext) async throws -> Void

    /// Server state
    public enum State: Sendable, Hashable, CustomStringConvertible {
        /// Server created but not listening
        case idle

        /// Server is listening for connections
        case listening

        /// Server is shutting down (draining connections)
        case stopping

        /// Server has stopped
        case stopped

        public var description: String {
            switch self {
            case .idle: return "idle"
            case .listening: return "listening"
            case .stopping: return "stopping"
            case .stopped: return "stopped"
            }
        }
    }

    // MARK: - Properties

    /// Local HTTP/3 settings to use for all connections
    public let settings: HTTP3Settings

    /// Current server state
    public private(set) var state: State = .idle

    /// The registered request handler
    private var handler: RequestHandler?

    /// Active HTTP/3 connections managed by this server
    private var connections: [ObjectIdentifier: HTTP3Connection] = [:]

    /// Counter for tracking total connections accepted
    private var totalConnectionsAccepted: UInt64 = 0

    /// Counter for tracking total requests handled
    private var totalRequestsHandled: UInt64 = 0

    /// Maximum concurrent connections (0 = unlimited)
    private let maxConnections: Int

    /// Task for the listener loop
    private var listenerTask: Task<Void, Never>?

    // MARK: - Initialization

    /// Creates an HTTP/3 server.
    ///
    /// - Parameters:
    ///   - settings: HTTP/3 settings for all connections (default: literal-only QPACK)
    ///   - maxConnections: Maximum concurrent connections, 0 for unlimited (default: 0)
    public init(
        settings: HTTP3Settings = HTTP3Settings(),
        maxConnections: Int = 0
    ) {
        self.settings = settings
        self.maxConnections = maxConnections
    }

    // MARK: - Configuration

    /// Registers a request handler.
    ///
    /// The handler is called for each incoming HTTP/3 request across
    /// all connections. Only one handler can be registered at a time;
    /// calling this again replaces the previous handler.
    ///
    /// - Parameter handler: The closure to handle incoming requests
    ///
    /// ## Example
    ///
    /// ```swift
    /// server.onRequest { context in
    ///     switch context.request.path {
    ///     case "/":
    ///         try await context.respond(HTTP3Response(
    ///             status: 200,
    ///             headers: [("content-type", "text/html")],
    ///             body: Data("<h1>Home</h1>".utf8)
    ///         ))
    ///     case "/api/health":
    ///         try await context.respond(HTTP3Response(
    ///             status: 200,
    ///             headers: [("content-type", "application/json")],
    ///             body: Data("{\"status\":\"ok\"}".utf8)
    ///         ))
    ///     default:
    ///         try await context.respond(HTTP3Response(status: 404))
    ///     }
    /// }
    /// ```
    public func onRequest(_ handler: @escaping RequestHandler) {
        self.handler = handler
    }

    // MARK: - Server Lifecycle

    /// Starts accepting HTTP/3 connections from a QUIC connection source.
    ///
    /// This method accepts incoming QUIC connections from the provided
    /// async stream and initializes HTTP/3 sessions for each one.
    /// It runs until `stop()` is called or the connection source ends.
    ///
    /// - Parameter connectionSource: An async stream of incoming QUIC connections
    /// - Throws: `HTTP3Error` if the server cannot start
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Using with a QUIC listener's incoming connections
    /// try await server.serve(connectionSource: listener.incomingConnections)
    /// ```
    public func serve(
        connectionSource: AsyncStream<any QUICConnectionProtocol>
    ) async throws {
        guard state == .idle else {
            throw HTTP3Error(
                code: .internalError,
                reason: "Server already started (state: \(state))"
            )
        }

        guard handler != nil else {
            throw HTTP3Error(
                code: .internalError,
                reason: "No request handler registered. Call onRequest() first."
            )
        }

        state = .listening

        for await quicConnection in connectionSource {
            // Check if we're stopping
            if state == .stopping || state == .stopped {
                break
            }

            // Check connection limit
            if maxConnections > 0 && connections.count >= maxConnections {
                // Reject the connection — close it immediately
                await quicConnection.close(
                    applicationError: HTTP3ErrorCode.excessiveLoad.rawValue,
                    reason: "Server connection limit reached"
                )
                continue
            }

            totalConnectionsAccepted += 1

            // Handle the connection in a background task
            Task { [weak self] in
                await self?.handleConnection(quicConnection)
            }
        }

        // Connection source ended
        if state == .listening {
            state = .stopped
        }
    }

    /// Starts accepting connections using a single QUIC connection.
    ///
    /// This is a convenience method for testing or single-connection
    /// scenarios where you already have a QUIC connection established.
    ///
    /// - Parameter quicConnection: The QUIC connection to serve HTTP/3 on
    /// - Throws: `HTTP3Error` if initialization fails
    public func serveConnection(_ quicConnection: any QUICConnectionProtocol) async throws {
        guard handler != nil else {
            throw HTTP3Error(
                code: .internalError,
                reason: "No request handler registered. Call onRequest() first."
            )
        }

        state = .listening
        await handleConnection(quicConnection)
    }

    /// Stops the server gracefully.
    ///
    /// Sends GOAWAY to all active connections and waits for them
    /// to drain before closing.
    ///
    /// - Parameter gracePeriod: Maximum time to wait for connections to drain
    ///   (default: 5 seconds)
    public func stop(gracePeriod: Duration = .seconds(5)) async {
        guard state == .listening else { return }

        state = .stopping

        // Cancel the listener task if running
        listenerTask?.cancel()
        listenerTask = nil

        // Send GOAWAY to all active connections
        for (_, connection) in connections {
            await connection.close(error: .noError)
        }

        // Wait briefly for connections to drain
        let deadline = ContinuousClock.now + gracePeriod
        while !connections.isEmpty && ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }

        // Force-close any remaining connections
        for (_, connection) in connections {
            await connection.close(error: .noError)
        }

        connections.removeAll()
        state = .stopped
    }

    // MARK: - Connection Handling

    /// Handles a single QUIC connection's HTTP/3 lifecycle.
    ///
    /// Creates an HTTP/3 connection, initializes it (control streams,
    /// SETTINGS exchange), and processes incoming requests.
    ///
    /// - Parameter quicConnection: The QUIC connection to handle
    private func handleConnection(_ quicConnection: any QUICConnectionProtocol) async {
        let h3Connection = HTTP3Connection(
            quicConnection: quicConnection,
            role: .server,
            settings: settings
        )

        // Track the connection
        let connectionID = ObjectIdentifier(quicConnection as AnyObject)
        connections[connectionID] = h3Connection

        defer {
            // Clean up when the connection ends
            Task { [weak self] in
                await self?.removeConnection(connectionID)
            }
        }

        do {
            // Wait for QUIC handshake to complete before initializing HTTP/3
            // This ensures transport parameters are exchanged and streams can be opened
            try await waitForHandshakeComplete(quicConnection, timeout: .seconds(10))
            
            // Initialize HTTP/3 (open control + QPACK streams, send SETTINGS)
            print("[HTTP3Server] Calling h3Connection.initialize() for \(quicConnection.remoteAddress)")
            try await h3Connection.initialize()
            print("[HTTP3Server] h3Connection.initialize() complete")

            // Process incoming requests
            for await context in await h3Connection.incomingRequests {
                // Check server state
                if state == .stopping || state == .stopped {
                    break
                }

                totalRequestsHandled += 1

                // Dispatch to handler in a separate task for concurrency
                if let handler = self.handler {
                    let capturedHandler = handler
                    Task {
                        do {
                            try await capturedHandler(context)
                        } catch {
                            // Handler threw an error — send 500 if possible
                            try? await context.respond(HTTP3Response(
                                status: 500,
                                headers: [("content-type", "text/plain")],
                                body: Data("Internal Server Error".utf8)
                            ))
                        }
                    }
                }
            }
        } catch {
            // Connection initialization or processing failed
            // Close the connection with an appropriate error
            await h3Connection.close(error: .internalError)
        }
    }

    /// Waits for the QUIC handshake to complete
    ///
    /// Polls the connection's handshake state until it reaches .established
    /// or the timeout expires.
    ///
    /// - Parameters:
    ///   - connection: The QUIC connection
    ///   - timeout: Maximum time to wait (default: 10 seconds)
    /// - Throws: HTTP3Error if handshake doesn't complete in time or connection is wrong type
    private func waitForHandshakeComplete(
        _ connection: any QUICConnectionProtocol,
        timeout: Duration = .seconds(10)
    ) async throws {
        print("[HTTP3Server] waitForHandshakeComplete STARTED")
        
        // Ensure we have a ManagedConnection (fail fast if wrong type)
        guard let managedConn = connection as? ManagedConnection else {
            print("[HTTP3Server] ERROR: Connection is not ManagedConnection!")
            throw HTTP3Error(
                code: .internalError,
                reason: "Connection must be a ManagedConnection to check handshake state"
            )
        }
        
        print("[HTTP3Server] Initial handshake state: \(managedConn.handshakeState)")
        
        let deadline = ContinuousClock.now + timeout
        
        // Poll with exponential backoff to reduce CPU usage
        var sleepDuration: Duration = .milliseconds(1)
        let maxSleep: Duration = .milliseconds(50)
        var iterations = 0
        
        while ContinuousClock.now < deadline {
            iterations += 1
            
            // Check if handshake is complete
            let currentState = managedConn.handshakeState
            if iterations <= 5 || iterations % 20 == 0 {
                print("[HTTP3Server] Polling handshake state (iteration \(iterations)): \(currentState)")
            }
            
            switch currentState {
            case .established:
                print("[HTTP3Server] Handshake established after \(iterations) iterations!")
                return
                
            case .closed, .closing:
                print("[HTTP3Server] Connection closed/closing!")
                throw HTTP3Error(
                    code: .internalError,
                    reason: "Connection closed before handshake completed"
                )
                
            case .idle, .connecting, .handshakeInProgress:
                // Still in progress, continue waiting
                break
            }
            
            // Wait before checking again with exponential backoff
            try await Task.sleep(for: sleepDuration)
            
            // Increase sleep duration for next iteration (max 50ms)
            sleepDuration = min(sleepDuration * 2, maxSleep)
        }
        
        print("[HTTP3Server] Handshake TIMEOUT after \(iterations) iterations, final state: \(managedConn.handshakeState)")
        throw HTTP3Error(
            code: .internalError,
            reason: "Handshake timeout - connection not established within \(timeout.components.seconds)s"
        )
    }

    /// Removes a connection from the active connections set.
    ///
    /// - Parameter id: The connection's object identifier
    private func removeConnection(_ id: ObjectIdentifier) {
        connections.removeValue(forKey: id)
    }

    // MARK: - Server Info

    /// The number of currently active connections
    public var activeConnectionCount: Int {
        connections.count
    }

    /// Total number of connections accepted since the server started
    public var totalConnections: UInt64 {
        totalConnectionsAccepted
    }

    /// Total number of requests handled since the server started
    public var totalRequests: UInt64 {
        totalRequestsHandled
    }

    /// Whether the server is currently listening
    public var isListening: Bool {
        state == .listening
    }

    /// Whether the server has been stopped
    public var isStopped: Bool {
        state == .stopped
    }

    /// A summary of the server's current state
    public var debugDescription: String {
        var parts = [String]()
        parts.append("state=\(state)")
        parts.append("connections=\(connections.count)")
        parts.append("totalAccepted=\(totalConnectionsAccepted)")
        parts.append("totalRequests=\(totalRequestsHandled)")
        parts.append("settings=\(settings)")
        return "HTTP3Server(\(parts.joined(separator: ", ")))"
    }
}

// MARK: - Simple Router

/// A simple path-based router for HTTP/3 servers.
///
/// Provides a convenient way to register handlers for specific
/// path patterns without a full routing framework.
///
/// ## Usage
///
/// ```swift
/// let router = HTTP3Router()
/// router.get("/") { context in
///     try await context.respond(HTTP3Response(
///         status: 200,
///         body: Data("Home".utf8)
///     ))
/// }
/// router.post("/api/data") { context in
///     // handle POST
/// }
///
/// server.onRequest(router.handler)
/// ```
public final class HTTP3Router: Sendable {

    /// Route entry
    private struct Route: Sendable {
        let method: HTTPMethod?  // nil = any method
        let path: String
        let handler: HTTP3Server.RequestHandler
    }

    /// Registered routes
    private let routes: LockedBox<[Route]>

    /// Handler for unmatched routes (default: 404)
    private let notFoundHandler: LockedBox<HTTP3Server.RequestHandler>

    /// Creates a new HTTP/3 router.
    public init() {
        self.routes = LockedBox([])
        self.notFoundHandler = LockedBox({ context in
            try await context.respond(HTTP3Response(
                status: 404,
                headers: [("content-type", "text/plain")],
                body: Data("Not Found".utf8)
            ))
        })
    }

    /// Registers a route for any HTTP method.
    ///
    /// - Parameters:
    ///   - path: The URL path to match
    ///   - handler: The request handler
    public func route(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: nil, path: path, handler: handler)) }
    }

    /// Registers a GET route.
    public func get(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: .get, path: path, handler: handler)) }
    }

    /// Registers a POST route.
    public func post(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: .post, path: path, handler: handler)) }
    }

    /// Registers a PUT route.
    public func put(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: .put, path: path, handler: handler)) }
    }

    /// Registers a DELETE route.
    public func delete(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: .delete, path: path, handler: handler)) }
    }

    /// Registers a PATCH route.
    public func patch(_ path: String, handler: @escaping HTTP3Server.RequestHandler) {
        routes.withLock { $0.append(Route(method: .patch, path: path, handler: handler)) }
    }

    /// Sets the handler for unmatched routes.
    ///
    /// - Parameter handler: The fallback handler (default returns 404)
    public func setNotFound(_ handler: @escaping HTTP3Server.RequestHandler) {
        notFoundHandler.withLock { $0 = handler }
    }

    /// The combined request handler suitable for `HTTP3Server.onRequest()`.
    ///
    /// This handler matches incoming requests against registered routes
    /// and dispatches to the appropriate handler. Unmatched requests are
    /// forwarded to the not-found handler.
    public var handler: HTTP3Server.RequestHandler {
        return { [self] context in
            let matchingRoute = self.routes.withLock { routes -> Route? in
                for route in routes {
                    // Check method (nil matches any)
                    if let method = route.method, method != context.request.method {
                        continue
                    }
                    // Check path (exact match)
                    if route.path == context.request.path {
                        return route
                    }
                }
                return nil
            }

            if let route = matchingRoute {
                try await route.handler(context)
            } else {
                let fallback = self.notFoundHandler.withLock { $0 }
                try await fallback(context)
            }
        }
    }
}

// MARK: - LockedBox (Thread-safe container)

/// A simple thread-safe container for mutable values.
///
/// Uses `NSLock` for synchronization. This is a minimal utility
/// for the router's route table.
internal final class LockedBox<Value>: @unchecked Sendable {
    private var _value: Value
    private let lock = NSLock()

    init(_ value: Value) {
        self._value = value
    }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&_value)
    }
}
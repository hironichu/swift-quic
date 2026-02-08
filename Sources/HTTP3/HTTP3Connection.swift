/// HTTP/3 Connection Manager (RFC 9114, RFC 9218)
///
/// Manages the HTTP/3-specific aspects of a QUIC connection:
///
/// 1. **Control stream** — Opens one unidirectional stream in each direction,
///    exchanges SETTINGS frames
/// 2. **QPACK streams** — Opens encoder/decoder unidirectional streams
/// 3. **Request streams** — Bidirectional streams for HTTP request/response
/// 4. **Stream type identification** — Reads stream type byte from incoming
///    unidirectional streams
/// 5. **GOAWAY** — Graceful shutdown coordination
///
/// ## Connection Establishment Flow
///
/// ```
/// Client                                     Server
///   |                                          |
///   |  === QUIC connection established ===     |
///   |  === ALPN: "h3" negotiated ===           |
///   |                                          |
///   |  Open uni stream: Control (type=0x00)    |
///   |  Send SETTINGS frame                     |
///   |----------------------------------------->|
///   |                                          |
///   |  Open uni stream: QPACK Encoder (0x02)   |
///   |----------------------------------------->|
///   |                                          |
///   |  Open uni stream: QPACK Decoder (0x03)   |
///   |----------------------------------------->|
///   |                                          |
///   |  (Server also opens same 3 uni streams)  |
///   |<-----------------------------------------|
///   |                                          |
///   |  === HTTP/3 connection ready ===         |
///   |                                          |
/// ```
///
/// ## Thread Safety
///
/// `HTTP3Connection` is an `actor`, ensuring all mutable state is
/// accessed serially. This is consistent with Swift 6 concurrency
/// requirements and the project's design principles.

import Foundation
import QUICCore
import QUICStream
import QPACK

// MARK: - HTTP/3 Connection

/// HTTP/3 connection wrapping a QUIC connection (RFC 9114 Section 3)
///
/// Manages the HTTP/3 layer on top of a QUIC connection, including
/// control stream setup, SETTINGS exchange, request multiplexing,
/// and graceful shutdown via GOAWAY.
///
/// ## Usage
///
/// ```swift
/// // Client-side
/// let h3conn = HTTP3Connection(
///     quicConnection: quicConn,
///     role: .client,
///     settings: HTTP3Settings()
/// )
/// try await h3conn.initialize()
/// let response = try await h3conn.sendRequest(request)
///
/// // Server-side
/// let h3conn = HTTP3Connection(
///     quicConnection: quicConn,
///     role: .server,
///     settings: HTTP3Settings()
/// )
/// try await h3conn.initialize()
/// for await context in h3conn.incomingRequests {
///     try await context.respond(response)
/// }
/// ```
public actor HTTP3Connection {

    // MARK: - Types

    /// The role of this endpoint in the HTTP/3 connection
    public enum Role: Sendable {
        /// Client role — initiates requests
        case client
        /// Server role — receives and responds to requests
        case server
    }

    /// Connection state
    public enum State: Sendable, Hashable {
        /// Connection created but not yet initialized
        case idle
        /// Control streams opened, SETTINGS sent, waiting for peer SETTINGS
        case initializing
        /// SETTINGS exchanged, connection ready for requests
        case ready
        /// GOAWAY sent or received, draining in-flight requests
        case goingAway(lastStreamID: UInt64)
        /// Connection is closed
        case closed
    }

    // MARK: - Properties

    /// The underlying QUIC connection
    private let quicConnection: any QUICConnectionProtocol

    /// This endpoint's role (client or server)
    public let role: Role

    /// Local HTTP/3 settings
    public let localSettings: HTTP3Settings

    /// Peer's HTTP/3 settings (available after SETTINGS exchange)
    public private(set) var peerSettings: HTTP3Settings?

    /// Current connection state
    public private(set) var state: State = .idle

    /// QPACK encoder (for encoding outgoing headers)
    public let qpackEncoder: QPACKEncoder

    /// QPACK decoder (for decoding incoming headers)
    public let qpackDecoder: QPACKDecoder

    // MARK: - Stream State

    /// Our control stream (outgoing)
    private var localControlStream: (any QUICStreamProtocol)?

    /// Peer's control stream (incoming)
    private var peerControlStream: (any QUICStreamProtocol)?

    /// Our QPACK encoder stream
    private var localQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Our QPACK decoder stream
    private var localQPACKDecoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK encoder stream
    private var peerQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK decoder stream
    private var peerQPACKDecoderStream: (any QUICStreamProtocol)?

    /// The last stream ID from a received GOAWAY
    private var goawayStreamID: UInt64?

    /// The next client-initiated bidirectional stream ID to use
    /// Client bidi streams: 0, 4, 8, 12, ...
    /// Server bidi streams: 1, 5, 9, 13, ...
    private var nextStreamID: UInt64

    /// Whether the peer's control stream has been received
    private var peerControlStreamReceived: Bool = false

    /// Whether the peer's QPACK encoder stream has been received
    private var peerQPACKEncoderStreamReceived: Bool = false

    /// Whether the peer's QPACK decoder stream has been received
    private var peerQPACKDecoderStreamReceived: Bool = false

    // MARK: - Priority Tracking (RFC 9218)

    /// Stream priorities received via PRIORITY_UPDATE frames.
    ///
    /// Maps stream IDs to their dynamically-updated priorities.
    /// These override the initial priority from the Priority header.
    private var streamPriorities: [UInt64: StreamPriority] = [:]

    /// Pending PRIORITY_UPDATE frames for streams not yet created.
    ///
    /// Per RFC 9218 Section 7, a client can send PRIORITY_UPDATE for
    /// a stream ID before that stream is opened. The server stores
    /// these and applies them when the stream is created.
    private var pendingPriorityUpdates: [UInt64: StreamPriority] = [:]

    // MARK: - Incoming Request Handling

    /// Continuation for the incoming requests stream
    private var incomingRequestsContinuation: AsyncStream<HTTP3RequestContext>.Continuation?

    /// The async stream of incoming requests (server-side)
    public private(set) var incomingRequests: AsyncStream<HTTP3RequestContext>

    // MARK: - Initialization

    /// Creates an HTTP/3 connection manager.
    ///
    /// - Parameters:
    ///   - quicConnection: The underlying QUIC connection
    ///   - role: The role of this endpoint (client or server)
    ///   - settings: Local HTTP/3 settings (default: literal-only QPACK)
    public init(
        quicConnection: any QUICConnectionProtocol,
        role: Role,
        settings: HTTP3Settings = HTTP3Settings()
    ) {
        self.quicConnection = quicConnection
        self.role = role
        self.localSettings = settings
        self.qpackEncoder = QPACKEncoder()
        self.qpackDecoder = QPACKDecoder()

        // Client bidi streams start at 0, server at 1
        self.nextStreamID = (role == .client) ? 0 : 1

        // Create the incoming requests stream
        var continuation: AsyncStream<HTTP3RequestContext>.Continuation!
        self.incomingRequests = AsyncStream { cont in
            continuation = cont
        }
        self.incomingRequestsContinuation = continuation
    }

    deinit {
        incomingRequestsContinuation?.finish()
    }

    // MARK: - Connection Lifecycle

    /// Initializes the HTTP/3 connection.
    ///
    /// This performs the following steps:
    /// 1. Opens the local control stream and sends SETTINGS
    /// 2. Opens QPACK encoder and decoder streams
    /// 3. Starts processing incoming unidirectional streams
    ///
    /// After this returns, the connection may not yet be fully ready
    /// (peer SETTINGS may not have arrived). Use `waitForReady()` to
    /// wait for the peer's SETTINGS if needed.
    ///
    /// - Throws: `HTTP3Error` if stream creation or SETTINGS send fails
    public func initialize() async throws {
        guard state == .idle else {
            throw HTTP3Error(code: .internalError, reason: "Connection already initialized")
        }

        state = .initializing

        // 1. Open control stream and send SETTINGS
        try await openControlStream()

        // 2. Open QPACK encoder and decoder streams (required even in literal-only mode)
        try await openQPACKStreams()

        // 3. Start background task to process incoming streams
        let connection = self.quicConnection
        Task { [weak self] in
            await self?.processIncomingStreams(from: connection)
        }
    }

    /// Waits until the connection is ready (peer SETTINGS received).
    ///
    /// This polls for the ready state with a timeout. In practice,
    /// SETTINGS should arrive very quickly after connection establishment.
    ///
    /// - Parameter timeout: Maximum time to wait (default: 10 seconds)
    /// - Throws: `HTTP3Error` if the connection doesn't become ready in time
    public func waitForReady(timeout: Duration = .seconds(10)) async throws {
        let deadline = ContinuousClock.now + timeout

        while ContinuousClock.now < deadline {
            if state == .ready || peerSettings != nil {
                state = .ready
                return
            }
            if case .closed = state {
                throw HTTP3Error(code: .internalError, reason: "Connection closed before ready")
            }
            try await Task.sleep(for: .milliseconds(10))
        }

        throw HTTP3Error(code: .missingSettings, reason: "Timed out waiting for peer SETTINGS")
    }

    /// Sends a GOAWAY frame to initiate graceful shutdown.
    ///
    /// For a client, `lastStreamID` is the last push ID to accept.
    /// For a server, `lastStreamID` is the last client-initiated
    /// stream ID that was or might be processed.
    ///
    /// - Parameter lastStreamID: The last stream/push ID to process
    /// - Throws: `HTTP3Error` if the GOAWAY frame cannot be sent
    public func goaway(lastStreamID: UInt64) async throws {
        guard let controlStream = localControlStream else {
            throw HTTP3Error(code: .closedCriticalStream, reason: "Control stream not open")
        }

        let frame = HTTP3Frame.goaway(streamID: lastStreamID)
        let encoded = HTTP3FrameCodec.encode(frame)
        try await controlStream.write(encoded)

        state = .goingAway(lastStreamID: lastStreamID)
    }

    /// Closes the HTTP/3 connection.
    ///
    /// Sends a GOAWAY if not already sent, then closes the underlying
    /// QUIC connection.
    ///
    /// - Parameter error: Optional HTTP/3 error code (default: no error)
    public func close(error: HTTP3ErrorCode = .noError) async {
        // Send GOAWAY if we haven't already
        if case .ready = state {
            let lastID: UInt64 = (role == .server) ? nextStreamID : 0
            try? await goaway(lastStreamID: lastID)
        }

        state = .closed
        incomingRequestsContinuation?.finish()

        // Close the QUIC connection
        await quicConnection.close(applicationError: error.rawValue, reason: error.reason)
    }

    // MARK: - Request Handling (Client)

    /// Sends an HTTP/3 request and receives the response.
    ///
    /// Opens a new bidirectional QUIC stream, sends HEADERS and optional
    /// DATA frames, then reads the response HEADERS and DATA frames.
    ///
    /// - Parameter request: The HTTP/3 request to send
    /// - Returns: The HTTP/3 response
    /// - Throws: `HTTP3Error` if the request fails
    ///
    /// ## Example
    ///
    /// ```swift
    /// let request = HTTP3Request(method: .get, url: "https://example.com/")
    /// let response = try await connection.sendRequest(request)
    /// print("Status: \(response.status)")
    /// ```
    public func sendRequest(_ request: HTTP3Request) async throws -> HTTP3Response {
        guard state == .ready || state == .initializing else {
            throw HTTP3Error(code: .internalError, reason: "Connection not ready (state: \(state))")
        }

        // Check GOAWAY — don't send new requests past the goaway point
        if let goawayID = goawayStreamID, nextStreamID > goawayID {
            throw HTTP3Error(code: .requestRejected, reason: "Stream ID exceeds GOAWAY limit")
        }

        // Open a new bidirectional stream
        let stream = try await quicConnection.openStream()

        // Encode headers using QPACK
        let headerList = request.toHeaderList()
        let encodedHeaders = qpackEncoder.encode(headerList)

        // Send HEADERS frame
        let headersFrame = HTTP3Frame.headers(encodedHeaders)
        let headersData = HTTP3FrameCodec.encode(headersFrame)
        try await stream.write(headersData)

        // Send DATA frame if there's a body
        if let body = request.body, !body.isEmpty {
            let dataFrame = HTTP3Frame.data(body)
            let dataData = HTTP3FrameCodec.encode(dataFrame)
            try await stream.write(dataData)
        }

        // Close the write side (FIN)
        try await stream.closeWrite()

        // Read response
        return try await readResponse(from: stream)
    }

    // MARK: - Response Reading (Client)

    /// Reads an HTTP/3 response from a stream.
    ///
    /// Reads HEADERS and DATA frames from the stream until FIN.
    /// The first frame MUST be a HEADERS frame containing the response
    /// status and headers. DATA frames contain the response body.
    ///
    /// - Parameter stream: The QUIC stream to read from
    /// - Returns: The decoded HTTP/3 response
    /// - Throws: `HTTP3Error` if the response is malformed
    private func readResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
        var responseHeaders: [(name: String, value: String)]?
        var bodyData = Data()
        var headersReceived = false

        // Read frames from the stream
        while true {
            let data: Data
            do {
                data = try await stream.read()
            } catch {
                // Stream ended (FIN received) or error
                break
            }

            if data.isEmpty {
                // FIN received
                break
            }

            // Decode frames from the received data
            let (frames, _) = try HTTP3FrameCodec.decodeAll(from: data)

            for frame in frames {
                switch frame {
                case .headers(let headerBlock):
                    if headersReceived {
                        // Trailers — we ignore them for now
                        continue
                    }
                    responseHeaders = try qpackDecoder.decode(headerBlock)
                    headersReceived = true

                case .data(let payload):
                    guard headersReceived else {
                        throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                    }
                    bodyData.append(payload)

                case .unknown:
                    // Ignore unknown frames (forward compatibility)
                    continue

                default:
                    // Other frame types on request streams are errors
                    if !frame.isAllowedOnRequestStream {
                        throw HTTP3Error.frameUnexpected(
                            "Frame type 0x\(String(frame.frameType, radix: 16)) not allowed on request stream"
                        )
                    }
                }
            }
        }

        guard let headers = responseHeaders else {
            throw HTTP3Error.messageError("No HEADERS frame received in response")
        }

        var response = try HTTP3Response.fromHeaderList(headers)
        response.body = bodyData
        return response
    }

    // MARK: - Control Stream

    /// Opens the local control stream and sends SETTINGS.
    ///
    /// Per RFC 9114 Section 6.2.1, the first frame on the control stream
    /// MUST be a SETTINGS frame.
    private func openControlStream() async throws {
        let stream = try await quicConnection.openUniStream()
        localControlStream = stream

        // Write stream type (Control = 0x00)
        let streamTypeData = HTTP3StreamType.control.encode()
        try await stream.write(streamTypeData)

        // Write SETTINGS frame
        let settingsFrame = HTTP3Frame.settings(localSettings)
        let settingsData = HTTP3FrameCodec.encode(settingsFrame)
        try await stream.write(settingsData)
    }

    /// Opens QPACK encoder and decoder unidirectional streams.
    ///
    /// These streams are required even in literal-only mode (RFC 9204 Section 4.2).
    /// In literal-only mode, no instructions are sent on these streams.
    private func openQPACKStreams() async throws {
        // Open QPACK encoder stream
        let encoderStream = try await quicConnection.openUniStream()
        localQPACKEncoderStream = encoderStream
        let encoderTypeData = HTTP3StreamType.qpackEncoder.encode()
        try await encoderStream.write(encoderTypeData)

        // Open QPACK decoder stream
        let decoderStream = try await quicConnection.openUniStream()
        localQPACKDecoderStream = decoderStream
        let decoderTypeData = HTTP3StreamType.qpackDecoder.encode()
        try await decoderStream.write(decoderTypeData)
    }

    // MARK: - Incoming Stream Processing

    /// Processes incoming QUIC streams (both bidirectional and unidirectional).
    ///
    /// Bidirectional streams are request streams. Unidirectional streams
    /// are classified by their stream type byte and routed accordingly.
    private func processIncomingStreams(from connection: any QUICConnectionProtocol) async {
        for await stream in connection.incomingStreams {
            if stream.isUnidirectional {
                Task { [weak self] in
                    await self?.handleIncomingUniStream(stream)
                }
            } else {
                // Bidirectional stream = request stream
                Task { [weak self] in
                    await self?.handleIncomingRequestStream(stream)
                }
            }
        }
    }

    /// Handles an incoming unidirectional stream.
    ///
    /// Reads the stream type byte and routes the stream to the
    /// appropriate handler.
    private func handleIncomingUniStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read the stream type (first varint on the stream)
            let typeData = try await stream.read(maxBytes: 8)
            guard !typeData.isEmpty else { return }

            guard let (streamTypeValue, _) = try HTTP3StreamType.decode(from: typeData) else {
                return
            }

            let classification = HTTP3StreamClassification.classify(streamTypeValue)

            switch classification {
            case .known(let streamType):
                switch streamType {
                case .control:
                    try await handleIncomingControlStream(stream, remainingData: typeData)
                case .qpackEncoder:
                    await handleIncomingQPACKEncoderStream(stream)
                case .qpackDecoder:
                    await handleIncomingQPACKDecoderStream(stream)
                case .push:
                    if role == .server {
                        // Servers don't receive push streams
                        await stream.reset(
                            errorCode: HTTP3ErrorCode.streamCreationError.rawValue
                        )
                    }
                    // Client-side push handling not implemented
                }

            case .grease:
                // GREASE streams must be silently ignored
                // Drain and discard the stream
                _ = try? await stream.read()

            case .unknown:
                // Unknown stream types must be silently ignored
                _ = try? await stream.read()
            }
        } catch {
            // Stream read error — log and ignore
        }
    }

    /// Handles the peer's incoming control stream.
    ///
    /// Validates that only one control stream exists, reads the SETTINGS
    /// frame, and then continues reading control frames (GOAWAY, etc.).
    private func handleIncomingControlStream(
        _ stream: any QUICStreamProtocol,
        remainingData: Data
    ) async throws {
        // Only one control stream per peer
        guard !peerControlStreamReceived else {
            throw HTTP3Error(
                code: .streamCreationError,
                reason: "Duplicate peer control stream"
            )
        }

        peerControlStreamReceived = true
        peerControlStream = stream

        // Read the first frame — MUST be SETTINGS
        let firstFrameData = try await stream.read()
        guard !firstFrameData.isEmpty else {
            throw HTTP3Error.missingSettings
        }

        let (frame, _) = try HTTP3FrameCodec.decode(from: firstFrameData)

        guard case .settings(let settings) = frame else {
            throw HTTP3Error.missingSettings
        }

        peerSettings = settings

        // Transition to ready state
        if state == .initializing {
            state = .ready
        }

        // Continue reading control frames
        await readControlFrames(from: stream)
    }

    /// Reads and processes control frames from the peer's control stream.
    ///
    /// This runs for the lifetime of the connection, processing GOAWAY
    /// and other control frames as they arrive.
    private func readControlFrames(from stream: any QUICStreamProtocol) async {
        while true {
            do {
                let data = try await stream.read()
                if data.isEmpty {
                    // Control stream closed — this is a connection error
                    await close(error: .closedCriticalStream)
                    return
                }

                let (frames, _) = try HTTP3FrameCodec.decodeAll(from: data)

                for frame in frames {
                    switch frame {
                    case .goaway(let streamID):
                        goawayStreamID = streamID
                        state = .goingAway(lastStreamID: streamID)

                    case .settings:
                        // Duplicate SETTINGS is a connection error
                        await close(error: .frameUnexpected)
                        return

                    case .maxPushID:
                        // Only valid if we're a server
                        if role != .server {
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .priorityUpdateRequest(let streamID, let priority):
                        // RFC 9218: Dynamic reprioritization of request streams
                        // Only valid from a client (received by server)
                        if role == .server {
                            handlePriorityUpdate(streamID: streamID, priority: priority)
                        } else {
                            // Clients shouldn't receive request PRIORITY_UPDATE
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .priorityUpdatePush(let pushID, let priority):
                        // RFC 9218: Dynamic reprioritization of push streams
                        // Only valid from a client (received by server)
                        if role == .server {
                            handlePriorityUpdate(streamID: pushID, priority: priority)
                        } else {
                            // Clients shouldn't receive push PRIORITY_UPDATE
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .cancelPush:
                        // Push cancellation — not implemented yet
                        break

                    case .data, .headers, .pushPromise:
                        // These frames are NOT allowed on control streams
                        await close(error: .frameUnexpected)
                        return

                    case .unknown:
                        // Unknown frames on control stream are allowed
                        break
                    }
                }
            } catch {
                // Error reading from control stream
                await close(error: .closedCriticalStream)
                return
            }
        }
    }

    /// Handles the peer's QPACK encoder stream.
    ///
    /// In literal-only mode, no encoder instructions should arrive.
    /// We keep the stream open (closing it would be a connection error).
    private func handleIncomingQPACKEncoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKEncoderStreamReceived else {
            await close(error: .streamCreationError)
            return
        }

        peerQPACKEncoderStreamReceived = true
        peerQPACKEncoderStream = stream

        // In literal-only mode, we don't expect any encoder instructions.
        // Keep the stream alive by reading (and discarding) any data.
        while true {
            do {
                let data = try await stream.read()
                if data.isEmpty {
                    // QPACK encoder stream closed — connection error
                    await close(error: .closedCriticalStream)
                    return
                }
                // In literal-only mode, any instructions are unexpected
                // but we silently ignore them for forward compatibility
            } catch {
                // If the stream errors, that's a connection error
                await close(error: .closedCriticalStream)
                return
            }
        }
    }

    /// Handles the peer's QPACK decoder stream.
    ///
    /// In literal-only mode, no decoder instructions should arrive.
    /// We keep the stream open (closing it would be a connection error).
    private func handleIncomingQPACKDecoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKDecoderStreamReceived else {
            await close(error: .streamCreationError)
            return
        }

        peerQPACKDecoderStreamReceived = true
        peerQPACKDecoderStream = stream

        // In literal-only mode, we don't expect any decoder instructions.
        // Keep the stream alive by reading (and discarding) any data.
        while true {
            do {
                let data = try await stream.read()
                if data.isEmpty {
                    // QPACK decoder stream closed — connection error
                    await close(error: .closedCriticalStream)
                    return
                }
                // Silently ignore any instructions in literal-only mode
            } catch {
                await close(error: .closedCriticalStream)
                return
            }
        }
    }

    // MARK: - Incoming Request Stream Processing (Server)

    /// Handles an incoming bidirectional (request) stream.
    ///
    /// Reads HEADERS and optional DATA frames, constructs an HTTP3Request,
    /// and delivers it via the `incomingRequests` async stream.
    ///
    /// Also extracts the Priority header (RFC 9218) from the request
    /// headers to set the initial stream priority, and checks for any
    /// pending PRIORITY_UPDATE that may have arrived before the stream.
    private func handleIncomingRequestStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read frames from the request stream
            var requestHeaders: [(name: String, value: String)]?
            var bodyData = Data()
            var headersReceived = false

            // Accumulate data until FIN
            while true {
                let data: Data
                do {
                    data = try await stream.read()
                } catch {
                    break
                }

                if data.isEmpty {
                    break
                }

                let (frames, _) = try HTTP3FrameCodec.decodeAll(from: data)

                for frame in frames {
                    switch frame {
                    case .headers(let headerBlock):
                        if headersReceived {
                            // Trailers — skip for now
                            continue
                        }
                        requestHeaders = try qpackDecoder.decode(headerBlock)
                        headersReceived = true

                    case .data(let payload):
                        guard headersReceived else {
                            throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                        }
                        bodyData.append(payload)

                    case .unknown:
                        // Ignore unknown frames
                        continue

                    default:
                        if !frame.isAllowedOnRequestStream {
                            throw HTTP3Error.frameUnexpected(
                                "Frame type 0x\(String(frame.frameType, radix: 16)) on request stream"
                            )
                        }
                    }
                }
            }

            guard let headers = requestHeaders else {
                // No HEADERS frame received — incomplete request
                await stream.reset(errorCode: HTTP3ErrorCode.requestIncomplete.rawValue)
                return
            }

            // Extract Priority header (RFC 9218 Section 5.1)
            let priorityHeaderValue = headers.first(where: { $0.name.lowercased() == "priority" })?.value
            let initialPriority = StreamPriority.fromHeader(priorityHeaderValue)

            // Check for pending PRIORITY_UPDATE (may have arrived before the stream)
            let effectivePriority: StreamPriority
            if let pendingPriority = pendingPriorityUpdates.removeValue(forKey: stream.id) {
                // PRIORITY_UPDATE overrides the header
                effectivePriority = pendingPriority
            } else if let dynamicPriority = streamPriorities[stream.id] {
                // Already received a PRIORITY_UPDATE for this stream
                effectivePriority = dynamicPriority
            } else {
                effectivePriority = initialPriority
            }

            // Track the stream priority
            streamPriorities[stream.id] = effectivePriority

            // Construct the request
            var request = try HTTP3Request.fromHeaderList(headers)
            request.body = bodyData.isEmpty ? nil : bodyData

            // Create the response handler
            let respondClosure: @Sendable (HTTP3Response) async throws -> Void = { [weak self] response in
                guard let self = self else { return }
                await self.sendResponse(response, on: stream)
            }

            let context = HTTP3RequestContext(
                request: request,
                streamID: stream.id,
                respond: respondClosure
            )

            // Deliver to the incoming requests stream
            incomingRequestsContinuation?.yield(context)

        } catch {
            // Error processing request — reset the stream
            await stream.reset(errorCode: HTTP3ErrorCode.messageError.rawValue)
        }
    }

    // MARK: - Priority Management (RFC 9218)

    /// Handles a received PRIORITY_UPDATE frame.
    ///
    /// If the target stream exists, its priority is updated immediately.
    /// If the stream hasn't been created yet, the update is stored as pending.
    ///
    /// - Parameters:
    ///   - streamID: The stream or push ID being reprioritized
    ///   - priority: The new priority
    private func handlePriorityUpdate(streamID: UInt64, priority: StreamPriority) {
        // Update the tracked priority
        streamPriorities[streamID] = priority

        // Also store as pending in case the stream hasn't been opened yet
        // (the stream will pick this up in handleIncomingRequestStream)
        pendingPriorityUpdates[streamID] = priority
    }

    /// Sends a PRIORITY_UPDATE frame for a request stream.
    ///
    /// Only clients should call this method. The frame is sent on the
    /// control stream to dynamically reprioritize a request.
    ///
    /// - Parameters:
    ///   - streamID: The request stream ID to reprioritize
    ///   - priority: The new priority
    /// - Throws: `HTTP3Error` if the control stream is not open or write fails
    public func sendPriorityUpdate(streamID: UInt64, priority: StreamPriority) async throws {
        guard role == .client else {
            throw HTTP3Error(code: .internalError, reason: "Only clients can send PRIORITY_UPDATE")
        }

        guard let controlStream = localControlStream else {
            throw HTTP3Error(code: .closedCriticalStream, reason: "Control stream not open")
        }

        let frame = HTTP3Frame.priorityUpdateRequest(streamID: streamID, priority: priority)
        let encoded = HTTP3FrameCodec.encode(frame)
        try await controlStream.write(encoded)

        // Track locally
        streamPriorities[streamID] = priority
    }

    /// Returns the current priority for a stream.
    ///
    /// Checks dynamic priorities (from PRIORITY_UPDATE) first,
    /// then falls back to the default priority.
    ///
    /// - Parameter streamID: The stream ID to query
    /// - Returns: The effective priority, or `.default` if not tracked
    public func priority(for streamID: UInt64) -> StreamPriority {
        streamPriorities[streamID] ?? .default
    }

    /// Cleans up priority tracking for a closed stream.
    ///
    /// - Parameter streamID: The stream ID to clean up
    private func cleanupStreamPriority(_ streamID: UInt64) {
        streamPriorities.removeValue(forKey: streamID)
        pendingPriorityUpdates.removeValue(forKey: streamID)
    }

    // MARK: - Response Sending (Server)

    /// Sends an HTTP/3 response on a request stream.
    ///
    /// Encodes the response headers with QPACK, sends a HEADERS frame,
    /// then sends a DATA frame with the body, and closes the stream.
    ///
    /// - Parameters:
    ///   - response: The HTTP/3 response to send
    ///   - stream: The QUIC stream to send on
    private func sendResponse(_ response: HTTP3Response, on stream: any QUICStreamProtocol) async {
        do {
            // Encode response headers using QPACK
            let headerList = response.toHeaderList()
            let encodedHeaders = qpackEncoder.encode(headerList)

            // Send HEADERS frame
            let headersFrame = HTTP3Frame.headers(encodedHeaders)
            let headersData = HTTP3FrameCodec.encode(headersFrame)
            try await stream.write(headersData)

            // Send DATA frame if there's a body
            if !response.body.isEmpty {
                let dataFrame = HTTP3Frame.data(response.body)
                let dataData = HTTP3FrameCodec.encode(dataFrame)
                try await stream.write(dataData)
            }

            // Close the write side (FIN)
            try await stream.closeWrite()

        } catch {
            // Error sending response — reset the stream
            await stream.reset(errorCode: HTTP3ErrorCode.internalError.rawValue)
        }
    }

    // MARK: - Connection Info

    /// Whether the connection is ready for requests
    public var isReady: Bool {
        state == .ready
    }

    /// Whether the connection is in the process of shutting down
    public var isGoingAway: Bool {
        if case .goingAway = state { return true }
        return false
    }

    /// Whether the connection is closed
    public var isClosed: Bool {
        state == .closed
    }

    /// The remote address of the underlying QUIC connection
    public var remoteAddress: SocketAddress {
        quicConnection.remoteAddress
    }

    /// The local address of the underlying QUIC connection
    public var localAddress: SocketAddress? {
        quicConnection.localAddress
    }

    /// A summary of the connection's current state
    public var debugDescription: String {
        var parts = [String]()
        parts.append("role=\(role)")
        parts.append("state=\(state)")
        if let peer = peerSettings {
            parts.append("peerSettings=\(peer)")
        }
        parts.append("localSettings=\(localSettings)")
        return "HTTP3Connection(\(parts.joined(separator: ", ")))"
    }
}

// MARK: - QUICConnectionProtocol Import

// Re-export the QUIC types that HTTP3Connection depends on
// so that consumers of the HTTP3 module can use them without
// importing QUIC separately.
@_exported import QUIC
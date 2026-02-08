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
import QUIC
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
        /// Server role — responds to requests
        case server
    }

    /// Connection states
    enum State: Sendable, Hashable {
        /// Connection not yet initialized
        case idle
        /// Initialization in progress (control streams being opened)
        case initializing
        /// Connection is ready for requests
        case ready
        /// GOAWAY received/sent — no new requests
        case goingAway(lastStreamID: UInt64)
        /// Connection is closed
        case closed
    }

    // MARK: - Properties

    /// The underlying QUIC connection
    let quicConnection: any QUICConnectionProtocol

    /// Our role (client or server)
    let role: Role

    /// Local HTTP/3 settings
    let localSettings: HTTP3Settings

    /// Peer's HTTP/3 settings (set after SETTINGS received)
    var peerSettings: HTTP3Settings?

    /// Connection state
    var state: State = .idle

    /// QPACK encoder (for outgoing headers)
    let qpackEncoder: QPACKEncoder

    /// QPACK decoder (for incoming headers)
    let qpackDecoder: QPACKDecoder

    // MARK: - Streams

    /// Our local control stream
    var localControlStream: (any QUICStreamProtocol)?

    /// Peer's control stream
    var peerControlStream: (any QUICStreamProtocol)?

    /// Our local QPACK encoder stream
    var localQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Our local QPACK decoder stream
    var localQPACKDecoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK encoder stream
    var peerQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK decoder stream
    var peerQPACKDecoderStream: (any QUICStreamProtocol)?

    /// GOAWAY stream ID (last stream/push ID to process)
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
    /// Opens the control stream (with SETTINGS), QPACK encoder and decoder
    /// streams, and starts processing incoming streams in the background.
    ///
    /// - Throws: `HTTP3Error` if initialization fails
    public func initialize() async throws {
        guard state == .idle else {
            throw HTTP3Error(code: .internalError, reason: "Connection already initialized")
        }

        state = .initializing

        // 0. Wait for QUIC handshake to complete before opening streams.
        //    Peer transport parameters (including stream limits) are only
        //    available after the handshake finishes.  Without this wait,
        //    openUniStream() will fail with streamLimitReached because the
        //    peer's max_streams values are still 0.
        let handshakeDeadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !quicConnection.isEstablished {
            if ContinuousClock.now >= handshakeDeadline {
                state = .closed
                throw HTTP3Error(
                    code: .internalError,
                    reason: "QUIC handshake did not complete within timeout"
                )
            }
            try await Task.sleep(for: .milliseconds(10))
        }

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

    /// Waits until the connection transitions to the ready state.
    ///
    /// The connection is ready once peer SETTINGS have been received.
    /// This typically happens during the initial stream exchange.
    ///
    /// - Parameter timeout: Maximum time to wait (default: 10 seconds)
    /// - Throws: `HTTP3Error` if the timeout expires or connection closes
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

    // MARK: - Request/Response (Client)

    /// Sends an HTTP/3 request and waits for the response.
    ///
    /// Opens a new bidirectional QUIC stream, sends the HEADERS and
    /// optional DATA frames, closes the write side, and reads the
    /// response frames.
    ///
    /// - Parameter request: The HTTP/3 request to send
    /// - Returns: The HTTP/3 response
    /// - Throws: `HTTP3Error` if the request fails
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

        // Track the stream ID and advance to the next one
        // Client bidi streams: 0, 4, 8, 12, ... (increment by 4)
        // Server bidi streams: 1, 5, 9, 13, ... (increment by 4)
        nextStreamID += 4

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

    /// Reads an HTTP/3 response from a request stream with buffered framing.
    ///
    /// Accumulates data across multiple reads and parses complete HTTP/3
    /// frames from the buffer, tolerating fragmentation at frame boundaries.
    private func readResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
        var responseHeaders: [(name: String, value: String)]?
        var bodyData = Data()
        var headersReceived = false
        var buffer = Data()

        // Read frames from the stream with buffering
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

            buffer.append(data)

            // Decode as many complete frames as possible from the buffer
            let (frames, _) = try decodeFramesFromBuffer(&buffer)

            for frame in frames {
                // Check for reserved HTTP/2 frame types (RFC 9114 Section 7.2.8)
                if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                    throw HTTP3Error.frameUnexpected(
                        "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                    )
                }

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

    // MARK: - Control Stream Setup

    /// Opens our local control stream and sends the initial SETTINGS frame.
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
        print("[HTTP3Connection] processIncomingStreams started (role=\(role))")
        for await stream in connection.incomingStreams {
            print("[HTTP3Connection] Received incoming stream id=\(stream.id), isUni=\(stream.isUnidirectional) (role=\(role))")
            if stream.isUnidirectional {
                Task { [weak self] in
                    print("[HTTP3Connection] handleIncomingUniStream task starting for stream \(stream.id)")
                    await self?.handleIncomingUniStream(stream)
                    print("[HTTP3Connection] handleIncomingUniStream task finished for stream \(stream.id)")
                }
            } else {
                // Bidirectional stream = request stream
                Task { [weak self] in
                    print("[HTTP3Connection] handleIncomingRequestStream task starting for stream \(stream.id)")
                    await self?.handleIncomingRequestStream(stream)
                    print("[HTTP3Connection] handleIncomingRequestStream task finished for stream \(stream.id)")
                }
            }
        }
        print("[HTTP3Connection] processIncomingStreams ended (role=\(role))")
    }

    // MARK: - Unidirectional Stream Handling

    /// Handles an incoming unidirectional stream by reading its type byte
    /// and routing it to the appropriate handler.
    ///
    /// The stream type is sent as the first varint on the stream. Any
    /// remaining bytes after the type varint are forwarded to the handler
    /// as initial buffered data to avoid data loss.
    private func handleIncomingUniStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read the stream type (first varint on the stream)
            // We read a small amount — the varint is typically 1 byte,
            // but the read may also contain subsequent frame data.
            print("[HTTP3Connection] handleIncomingUniStream: reading type from stream \(stream.id)")
            let typeData = try await stream.read()
            print("[HTTP3Connection] handleIncomingUniStream: got \(typeData.count) bytes from stream \(stream.id): \(typeData.map { String(format: "%02x", $0) }.joined())")
            guard !typeData.isEmpty else {
                print("[HTTP3Connection] handleIncomingUniStream: empty data from stream \(stream.id), returning")
                return
            }

            guard let (streamTypeValue, consumed) = try HTTP3StreamType.decode(from: typeData) else {
                print("[HTTP3Connection] handleIncomingUniStream: failed to decode stream type from stream \(stream.id)")
                return
            }

            // Extract any remaining data after the stream type varint.
            // This data belongs to the first frame on the stream and
            // must NOT be discarded.
            let remainingData: Data
            if consumed < typeData.count {
                remainingData = Data(typeData.dropFirst(consumed))
            } else {
                remainingData = Data()
            }

            let classification = HTTP3StreamClassification.classify(streamTypeValue)
            print("[HTTP3Connection] handleIncomingUniStream: stream \(stream.id) classified as \(classification), remainingData=\(remainingData.count) bytes")

            switch classification {
            case .known(let streamType):
                switch streamType {
                case .control:
                    print("[HTTP3Connection] handleIncomingUniStream: stream \(stream.id) is CONTROL stream, calling handleIncomingControlStream")
                    try await handleIncomingControlStream(stream, remainingData: remainingData)
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
    /// frame (with buffering to tolerate fragmentation), and then continues
    /// reading control frames (GOAWAY, etc.).
    ///
    /// - Parameters:
    ///   - stream: The QUIC stream for the peer's control stream
    ///   - remainingData: Any data read after the stream type varint
    ///     (may contain part or all of the first SETTINGS frame)
    private func handleIncomingControlStream(
        _ stream: any QUICStreamProtocol,
        remainingData: Data
    ) async throws {
        print("[HTTP3Connection] handleIncomingControlStream: stream \(stream.id), remainingData=\(remainingData.count) bytes: \(remainingData.map { String(format: "%02x", $0) }.joined())")
        // Only one control stream per peer
        guard !peerControlStreamReceived else {
            throw HTTP3Error(
                code: .streamCreationError,
                reason: "Duplicate peer control stream"
            )
        }

        peerControlStreamReceived = true
        peerControlStream = stream

        // Start a buffer with any leftover data from the stream type read
        var buffer = remainingData

        // Read the first frame — MUST be SETTINGS (RFC 9114 Section 6.2.1)
        // The SETTINGS frame may arrive across multiple reads, so we buffer
        // until a complete frame is available.
        print("[HTTP3Connection] handleIncomingControlStream: reading SETTINGS frame (buffer=\(buffer.count) bytes)")
        let settingsFrame = try await readNextFrame(from: stream, buffer: &buffer)
        print("[HTTP3Connection] handleIncomingControlStream: got frame: \(settingsFrame)")

        guard case .settings(let settings) = settingsFrame else {
            print("[HTTP3Connection] handleIncomingControlStream: first frame is NOT settings: \(settingsFrame)")
            throw HTTP3Error.missingSettings
        }

        print("[HTTP3Connection] handleIncomingControlStream: received peer SETTINGS: \(settings)")
        peerSettings = settings

        // Transition to ready state
        if state == .initializing {
            state = .ready
            print("[HTTP3Connection] handleIncomingControlStream: state -> ready")
        }

        // Continue reading control frames
        await readControlFrames(from: stream, initialBuffer: buffer)
    }

    /// Reads and processes control frames from the peer's control stream.
    ///
    /// This runs for the lifetime of the connection, processing GOAWAY
    /// and other control frames as they arrive. Uses buffered reading
    /// to tolerate frame fragmentation across QUIC stream reads.
    ///
    /// - Parameters:
    ///   - stream: The peer's control stream
    ///   - initialBuffer: Any unconsumed bytes from previous reads
    private func readControlFrames(
        from stream: any QUICStreamProtocol,
        initialBuffer: Data = Data()
    ) async {
        var buffer = initialBuffer

        while true {
            // First, try to decode frames already in the buffer
            do {
                let (frames, _) = try decodeFramesFromBuffer(&buffer)

                for frame in frames {
                    // Check for reserved HTTP/2 frame types
                    if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                        await close(error: .frameUnexpected)
                        return
                    }

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
                // Malformed frame on control stream
                await close(error: .frameError)
                return
            }

            // Read more data from the stream
            do {
                let data = try await stream.read()
                if data.isEmpty {
                    // Control stream closed — this is a connection error
                    await close(error: .closedCriticalStream)
                    return
                }
                buffer.append(data)
            } catch {
                // Error reading from control stream
                await close(error: .closedCriticalStream)
                return
            }
        }
    }

    // MARK: - QPACK Stream Handling

    /// Handles the peer's incoming QPACK encoder stream.
    ///
    /// In literal-only mode, no instructions are expected. The stream
    /// is drained and discarded.
    private func handleIncomingQPACKEncoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKEncoderStreamReceived else {
            // Duplicate — connection error
            await close(error: .streamCreationError)
            return
        }

        peerQPACKEncoderStreamReceived = true
        peerQPACKEncoderStream = stream

        // In literal-only mode, drain the stream
        do {
            while true {
                let data = try await stream.read()
                if data.isEmpty { break }
                // In full QPACK mode, we'd process encoder instructions here
            }
        } catch {
            // Stream closed or error — for critical streams this is an error
            // but in literal-only mode we tolerate it
        }
    }

    /// Handles the peer's incoming QPACK decoder stream.
    ///
    /// In literal-only mode, no instructions are expected. The stream
    /// is drained and discarded.
    private func handleIncomingQPACKDecoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKDecoderStreamReceived else {
            // Duplicate — connection error
            await close(error: .streamCreationError)
            return
        }

        peerQPACKDecoderStreamReceived = true
        peerQPACKDecoderStream = stream

        // In literal-only mode, drain the stream
        do {
            while true {
                let data = try await stream.read()
                if data.isEmpty { break }
                // In full QPACK mode, we'd process decoder instructions here
            }
        } catch {
            // Stream closed or error
        }
    }

    // MARK: - Request Stream Handling (Server)

    /// Handles an incoming bidirectional (request) stream from a client.
    ///
    /// Reads HEADERS and DATA frames using buffered framing to tolerate
    /// fragmentation, constructs the HTTP/3 request, and delivers it
    /// to the incoming requests stream.
    private func handleIncomingRequestStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read frames from the request stream with buffering
            var requestHeaders: [(name: String, value: String)]?
            var bodyData = Data()
            var headersReceived = false
            var buffer = Data()

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

                buffer.append(data)

                // Decode as many complete frames as possible from the buffer
                let (frames, _) = try decodeFramesFromBuffer(&buffer)

                for frame in frames {
                    // Check for reserved HTTP/2 frame types (RFC 9114 Section 7.2.8)
                    if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                        throw HTTP3Error.frameUnexpected(
                            "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                        )
                    }

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

    /// Handles a PRIORITY_UPDATE frame received on the control stream.
    ///
    /// Updates the priority for the specified stream. If the stream
    /// hasn't been created yet, the priority is stored as pending.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID being reprioritized
    ///   - priority: The new priority
    private func handlePriorityUpdate(streamID: UInt64, priority: StreamPriority) {
        streamPriorities[streamID] = priority

        // If the stream hasn't been created yet, store as pending
        // (will be applied when the stream is opened)
        if !streamPriorities.keys.contains(streamID) {
            pendingPriorityUpdates[streamID] = priority
        }
    }

    /// Sends a PRIORITY_UPDATE frame for a request stream.
    ///
    /// RFC 9218 Section 7.1: PRIORITY_UPDATE frames are sent on the
    /// control stream to dynamically change the priority of a stream.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID to reprioritize
    ///   - priority: The new priority
    /// - Throws: `HTTP3Error` if the control stream is not available
    public func sendPriorityUpdate(streamID: UInt64, priority: StreamPriority) async throws {
        guard let controlStream = localControlStream else {
            throw HTTP3Error(code: .closedCriticalStream, reason: "Control stream not open")
        }

        let frame = HTTP3Frame.priorityUpdateRequest(streamID: streamID, priority: priority)
        let encoded = HTTP3FrameCodec.encode(frame)
        try await controlStream.write(encoded)

        // Track locally
        streamPriorities[streamID] = priority
    }

    /// Returns the effective priority for a stream.
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

    // MARK: - Buffered Frame Helpers

    /// Reads the next complete HTTP/3 frame from a stream, buffering across
    /// multiple reads if necessary.
    ///
    /// This is used for the first SETTINGS frame on the control stream where
    /// we need exactly one complete frame and must tolerate fragmentation.
    ///
    /// - Parameters:
    ///   - stream: The QUIC stream to read from
    ///   - buffer: A mutable buffer that accumulates unconsumed bytes.
    ///     On entry it may contain leftover data from a previous read;
    ///     on exit it contains any bytes remaining after the decoded frame.
    /// - Returns: The decoded HTTP/3 frame
    /// - Throws: `HTTP3Error` if the stream ends before a complete frame
    ///   is available, or if the frame is malformed
    private func readNextFrame(
        from stream: any QUICStreamProtocol,
        buffer: inout Data
    ) async throws -> HTTP3Frame {
        // Try to decode from what we already have
        while true {
            if !buffer.isEmpty {
                do {
                    var offset = 0
                    let frame = try HTTP3FrameCodec.decode(from: buffer, offset: &offset)
                    // Successfully decoded — remove consumed bytes from buffer
                    buffer = Data(buffer.dropFirst(offset))
                    return frame
                } catch HTTP3FrameCodecError.insufficientData {
                    // Need more data — fall through to read
                } catch {
                    // Malformed frame
                    throw error
                }
            }

            // Read more data from the stream
            let data = try await stream.read()
            if data.isEmpty {
                throw HTTP3Error.missingSettings
            }
            buffer.append(data)
        }
    }

    /// Decodes as many complete HTTP/3 frames as possible from the buffer,
    /// removing consumed bytes.
    ///
    /// Uses `HTTP3FrameCodec.decodeAll` which stops at the first incomplete
    /// frame boundary. The unconsumed bytes remain in the buffer for the
    /// next read cycle.
    ///
    /// - Parameter buffer: A mutable buffer of accumulated stream data.
    ///   Consumed bytes are removed; unconsumed bytes remain.
    /// - Returns: A tuple of (decoded frames, bytes consumed)
    /// - Throws: `HTTP3FrameCodecError` for malformed frames (not for
    ///   insufficient data at the boundary — that's handled internally)
    private func decodeFramesFromBuffer(_ buffer: inout Data) throws -> ([HTTP3Frame], Int) {
        guard !buffer.isEmpty else { return ([], 0) }

        let (frames, consumed) = try HTTP3FrameCodec.decodeAll(from: buffer)

        if consumed > 0 {
            buffer = Data(buffer.dropFirst(consumed))
        }

        return (frames, consumed)
    }
}

// MARK: - Re-export QUIC types for consumers of the HTTP3 module

// Other files in the HTTP3 module (HTTP3Client, HTTP3Server, etc.) use
// QUICConnectionProtocol / QUICStreamProtocol without importing QUIC
// directly. This re-export makes those types available transitively.
@_exported import QUIC
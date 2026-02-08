# HTTP/3 Implementation Plan + Security Hardening

> **Project**: swift-quic
> **Date**: 2025-01-20
> **Status**: Implementation Ready
> **RFCs**: RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 9000/9001/9002 (QUIC)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Security Audit Results](#security-audit-results)
3. [Phase 1: Security Hardening](#phase-1-security-hardening)
4. [Phase 2: HTTP/3 Core](#phase-2-http3-core)
5. [Phase 3: QPACK](#phase-3-qpack)
6. [Phase 4: HTTP/3 Client/Server API](#phase-4-http3-clientserver-api)
7. [Phase 5: Integration & Testing](#phase-5-integration--testing)
8. [Module Structure](#module-structure)
9. [Implementation Details](#implementation-details)

---

## Executive Summary

This plan covers two major work streams:

1. **Security Hardening** — Fix 5 identified security gaps in the existing QUIC stack
2. **HTTP/3 Implementation** — Add RFC 9114 HTTP/3 and RFC 9204 QPACK on top of QUIC

The existing QUIC stack is substantial (~108 source files, 7 modules) with a complete TLS 1.3 implementation, stream multiplexing, congestion control, and loss detection. HTTP/3 builds naturally on top of QUIC streams.

---

## Security Audit Results

### Already Secure ✅

| Component | Details |
|-----------|---------|
| Client X.509 validation | `ClientStateMachine.processCertificate()` invokes `X509Validator` with EKU (serverAuth), SAN/hostname, chain building, name constraints |
| CertificateVerify | Both client and server verify signatures properly |
| Anti-amplification | `AntiAmplificationLimiter` enforces 3x limit with overflow protection |
| ACK range DoS | Fixed — uses binary search over `sentPackets` keys, not range iteration |
| MockTLS in production | `SecurityMode.testing` only compiles in DEBUG builds |
| ChaCha20 endianness | Fixed with explicit `UInt32(littleEndian:)` |
| MAX_STREAMS guard | Fixed — zero-value check prevents unwanted auto-extension |
| Session resumption | PSK/0-RTT with `ReplayProtection` for anti-replay |
| PEM loading | `PEMLoader.loadCertificateAndKey()` handles file-based cert/key |

### Security Gaps Found 🔴

#### GAP-1: Server-side mTLS Missing X.509 Chain Validation (CRITICAL)

**File**: `Sources/QUICCrypto/TLS/TLS13Handler.swift` — `ServerStateMachine.processClientCertificate()`

**Problem**: When the server receives a client certificate during mTLS, it parses the X.509 certificate and extracts the public key, but does NOT run `X509Validator`. This means:
- No chain-of-trust validation
- No EKU `clientAuth` check
- No time validity check
- No name constraints enforcement
- Any self-signed cert would be accepted

**Fix**: Add `X509Validator` invocation with `requiredEKU: .clientAuth` in `processClientCertificate()`, mirroring the client-side validation in `ClientStateMachine.processCertificate()`.

#### GAP-2: No ACK Range Count Limit (WARNING)

**File**: `Sources/QUICCore/Frame/FrameCodec.swift`

**Problem**: When decoding ACK frames, there's no limit on the number of ACK ranges. A malicious peer could send an ACK frame with millions of ranges, causing excessive memory allocation.

**Fix**: Add a constant `ProtocolLimits.maxAckRanges = 256` and reject ACK frames exceeding this limit during decoding.

#### GAP-3: Header Validation Not Called After HP Removal (WARNING)

**File**: `Sources/QUICCore/Packet/PacketCodec.swift`

**Problem**: `LongHeader.validate()` and `ShortHeader.validate()` exist (checking reserved bits, version, CID lengths) but are not called after header protection removal in the packet decode path.

**Fix**: Call `validate()` in `PacketDecoder.decodePacket()` after header protection is removed and before frame parsing.

#### GAP-4: `verifyPeer=false` Silently Disables All Validation (INFO)

**File**: `Sources/QUICCrypto/TLS/TLS13Provider.swift` — `TLSConfiguration`

**Problem**: Setting `verifyPeer = false` silently skips all certificate validation. In production mode, this should at minimum log a warning.

**Fix**: In `QUICEndpoint.createTLSProvider()`, when `securityMode == .production`, check if the TLS configuration has `verifyPeer = false` and log a prominent warning or throw.

#### GAP-5: STREAM Frame Overhead Approximation (INFO)

**File**: `Sources/QUICStream/StreamManager.swift:491-498`

**Problem**: Uses fixed 11-byte overhead for STREAM frames instead of computing actual varint sizes. Could cause packets to exceed MTU.

**Fix**: Compute overhead using `Varint.encodedSize()` for streamID and offset.

---

## Phase 1: Security Hardening

**Priority**: CRITICAL — Must complete before HTTP/3
**Estimated Effort**: 2-3 days

### Task 1.1: Server-side mTLS X.509 Validation

**File to modify**: `Sources/QUICCrypto/TLS/TLS13Handler.swift`

```swift
// In ServerStateMachine.processClientCertificate(), after parsing the cert:
// ADD X.509 validation (mirroring ClientStateMachine.processCertificate)

if configuration.verifyPeer {
    var validationOptions = X509ValidationOptions()
    validationOptions.allowSelfSigned = configuration.allowSelfSigned
    validationOptions.requiredEKU = .clientAuth  // RFC 5280: clientAuth for mTLS

    let validator = X509Validator(
        trustedRoots: configuration.trustedRootCertificates ?? [],
        options: validationOptions
    )

    let intermediates = try certificate.certificates.dropFirst().compactMap {
        try X509Certificate.parse(from: $0)
    }

    try validator.validate(certificate: leafCert, intermediates: Array(intermediates))
}
```

**Tests to add**:
- `testServerRejectsInvalidClientCertificate`
- `testServerAcceptsValidClientCertificate`
- `testServerRejectsExpiredClientCertificate`
- `testServerRejectsWrongEKUClientCertificate`

### Task 1.2: ACK Range Count Limit

**File to modify**: `Sources/QUICCore/Frame/FrameCodec.swift`

```swift
// In FrameCodec.decodeAckFrame(), after reading ackRangeCount:
guard ackRangeCount <= ProtocolLimits.maxAckRanges else {
    throw FrameCodecError.tooManyAckRanges(Int(ackRangeCount))
}
```

**File to modify**: `Sources/QUICCore/ProtocolLimits.swift`

```swift
/// Maximum number of ACK ranges in a single ACK frame (DoS prevention)
public static let maxAckRanges: UInt64 = 256
```

### Task 1.3: Header Validation After HP Removal

**File to modify**: `Sources/QUICCore/Packet/PacketCodec.swift`

```swift
// In PacketDecoder.decodePacket(), after header protection removal:
switch header {
case .long(let longHeader):
    try longHeader.validate()
case .short(let shortHeader):
    try shortHeader.validate()
}
```

### Task 1.4: Production Mode verifyPeer Warning

**File to modify**: `Sources/QUIC/QUICEndpoint.swift`

```swift
// In createTLSProvider(), when securityMode == .production:
if case .production = securityMode {
    // Warn if common insecure patterns are detected
    logger.critical(
        "Production mode with verifyPeer=false is a security risk",
        metadata: ["recommendation": "Set verifyPeer=true for production deployments"]
    )
}
```

### Task 1.5: STREAM Frame Overhead Accuracy

**File to modify**: `Sources/QUICStream/StreamManager.swift`

```swift
// Replace fixed 11-byte overhead with computed value
let overhead = 1  // frame type byte
    + Varint.encodedSize(UInt64(streamID))
    + Varint.encodedSize(UInt64(offset))
    + 2  // length field (typical varint size for data < 16384)
```

---

## Phase 2: HTTP/3 Core

**Priority**: HIGH
**Estimated Effort**: 5-7 days
**RFC Reference**: RFC 9114

### Module: `HTTP3`

New module containing HTTP/3 frame types, codec, and stream management.

### Task 2.1: HTTP/3 Frame Types

**New file**: `Sources/HTTP3/Frame/HTTP3Frame.swift`

```swift
/// HTTP/3 frame types (RFC 9114 Section 7.2)
public enum HTTP3FrameType: UInt64, Sendable {
    case data           = 0x00
    case headers        = 0x01
    case cancelPush     = 0x03
    case settings       = 0x04
    case pushPromise    = 0x05
    case goaway         = 0x07
    case maxPushID      = 0x0d
}

/// An HTTP/3 frame
public enum HTTP3Frame: Sendable {
    case data(Data)
    case headers(Data)           // QPACK-encoded header block
    case cancelPush(pushID: UInt64)
    case settings(HTTP3Settings)
    case pushPromise(pushID: UInt64, headerBlock: Data)
    case goaway(streamID: UInt64)
    case maxPushID(pushID: UInt64)
    case unknown(type: UInt64, payload: Data)  // For forward compatibility
}
```

### Task 2.2: HTTP/3 Frame Codec

**New file**: `Sources/HTTP3/Frame/HTTP3FrameCodec.swift`

Encode/decode HTTP/3 frames. Each frame is:
```
HTTP/3 Frame {
  Type (i),       // varint
  Length (i),      // varint
  Payload (..)
}
```

### Task 2.3: HTTP/3 Settings

**New file**: `Sources/HTTP3/HTTP3Settings.swift`

```swift
/// HTTP/3 Settings (RFC 9114 Section 7.2.4.1)
public struct HTTP3Settings: Sendable, Hashable {
    /// Maximum size of the dynamic table for QPACK (default: 0)
    public var maxTableCapacity: UInt64 = 0

    /// Maximum number of fields in a header section (default: unlimited)
    public var maxFieldSectionSize: UInt64 = UInt64.max

    /// Maximum number of streams that can be blocked by QPACK (default: 0)
    public var qpackBlockedStreams: UInt64 = 0
}
```

### Task 2.4: HTTP/3 Error Codes

**New file**: `Sources/HTTP3/HTTP3Error.swift`

```swift
/// HTTP/3 error codes (RFC 9114 Section 8.1)
public enum HTTP3ErrorCode: UInt64, Sendable {
    case noError                 = 0x0100
    case generalProtocolError    = 0x0101
    case internalError           = 0x0102
    case streamCreationError     = 0x0103
    case closedCriticalStream    = 0x0104
    case frameUnexpected         = 0x0105
    case frameError              = 0x0106
    case excessiveLoad           = 0x0107
    case idError                 = 0x0108
    case settingsError           = 0x0109
    case missingSettings         = 0x010a
    case requestRejected         = 0x010b
    case requestCancelled        = 0x010c
    case requestIncomplete       = 0x010d
    case messageError            = 0x010e
    case connectError            = 0x010f
    case versionFallback         = 0x0110
}
```

### Task 2.5: HTTP/3 Unidirectional Stream Types

**New file**: `Sources/HTTP3/Stream/HTTP3StreamType.swift`

```swift
/// HTTP/3 unidirectional stream types (RFC 9114 Section 6.2)
public enum HTTP3StreamType: UInt64, Sendable {
    case control       = 0x00
    case pushStream    = 0x01
    case qpackEncoder  = 0x02
    case qpackDecoder  = 0x03
}
```

### Task 2.6: HTTP/3 Connection Manager

**New file**: `Sources/HTTP3/HTTP3Connection.swift`

Manages the HTTP/3-specific aspects of a QUIC connection:

1. **Control stream** — Opens one uni stream in each direction, exchanges SETTINGS
2. **QPACK streams** — Opens encoder/decoder uni streams
3. **Request streams** — Bidirectional streams for HTTP requests
4. **Stream type identification** — Reads stream type byte from incoming uni streams

```swift
/// HTTP/3 connection wrapping a QUIC connection
public actor HTTP3Connection {
    private let quicConnection: any QUICConnectionProtocol
    private var localSettings: HTTP3Settings
    private var peerSettings: HTTP3Settings?
    private var controlStreamID: UInt64?
    private var peerControlStreamID: UInt64?
    private let qpackEncoder: QPACKEncoder
    private let qpackDecoder: QPACKDecoder

    public init(
        quicConnection: any QUICConnectionProtocol,
        settings: HTTP3Settings = HTTP3Settings()
    )

    /// Initialize HTTP/3 connection (open control + QPACK streams, send SETTINGS)
    public func initialize() async throws

    /// Send an HTTP request and receive the response
    public func sendRequest(_ request: HTTP3Request) async throws -> HTTP3Response

    /// Receive incoming requests (server mode)
    public var incomingRequests: AsyncStream<HTTP3RequestContext>

    /// Send GOAWAY
    public func goaway(lastStreamID: UInt64) async throws

    /// Close the HTTP/3 connection
    public func close() async
}
```

---

## Phase 3: QPACK

**Priority**: HIGH
**Estimated Effort**: 3-5 days
**RFC Reference**: RFC 9204

### Module: `QPACK`

Initially implement **literal-only mode** (no dynamic table) for simplicity and security.
This is fully RFC-compliant — dynamic table size 0 is a valid configuration.

### Task 3.1: QPACK Static Table

**New file**: `Sources/QPACK/StaticTable.swift`

The QPACK static table (RFC 9204 Appendix A) contains 99 entries of common header name/value pairs.

```swift
/// QPACK Static Table (RFC 9204 Appendix A)
public struct QPACKStaticTable {
    public struct Entry: Sendable {
        public let name: String
        public let value: String
    }

    /// All 99 static table entries (0-indexed)
    public static let entries: [Entry] = [
        Entry(name: ":authority", value: ""),                   // 0
        Entry(name: ":path", value: "/"),                       // 1
        Entry(name: "age", value: "0"),                         // 2
        // ... (all 99 entries from RFC 9204 Appendix A)
        Entry(name: "x-frame-options", value: "sameorigin"),    // 98
    ]

    /// Find index by exact name+value match
    public static func findExact(name: String, value: String) -> Int?

    /// Find index by name-only match
    public static func findName(_ name: String) -> Int?
}
```

### Task 3.2: QPACK Encoder (Literal-Only)

**New file**: `Sources/QPACK/QPACKEncoder.swift`

```swift
/// QPACK encoder using literal-only mode (no dynamic table)
///
/// This is the simplest compliant implementation. We use:
/// - Static table references where possible
/// - Literal with name reference (to static table) where name matches
/// - Literal without name reference otherwise
///
/// RFC 9204 Section 4.5: Encoded Field Section prefix
/// Required Insert Count = 0, Delta Base = 0 (no dynamic table)
public struct QPACKEncoder: Sendable {
    public init()

    /// Encode a list of header fields into a QPACK field section
    public func encode(_ headers: [(name: String, value: String)]) -> Data
}
```

### Task 3.3: QPACK Decoder (Literal-Only)

**New file**: `Sources/QPACK/QPACKDecoder.swift`

```swift
/// QPACK decoder supporting static table references and literals
public struct QPACKDecoder: Sendable {
    public init()

    /// Decode a QPACK field section into header fields
    public func decode(_ data: Data) throws -> [(name: String, value: String)]
}
```

### Task 3.4: QPACK Integer Encoding

**New file**: `Sources/QPACK/QPACKInteger.swift`

QPACK uses a prefix-based integer encoding (RFC 9204 Section 4.1.1, based on RFC 7541 Section 5.1).

```swift
/// QPACK integer encoding/decoding (RFC 9204 Section 4.1.1)
public enum QPACKInteger {
    /// Encode an integer with the given prefix bit count
    public static func encode(_ value: UInt64, prefix: Int) -> Data

    /// Decode an integer with the given prefix bit count
    public static func decode(from data: Data, offset: inout Int, prefix: Int) throws -> UInt64
}
```

### Task 3.5: QPACK String Encoding

**New file**: `Sources/QPACK/QPACKString.swift`

```swift
/// QPACK string literal encoding (RFC 9204 Section 4.1.2)
/// Supports both raw and Huffman-encoded strings
public enum QPACKString {
    /// Encode a string (raw, no Huffman for simplicity in v1)
    public static func encode(_ string: String) -> Data

    /// Decode a string (supports both raw and Huffman)
    public static func decode(from data: Data, offset: inout Int) throws -> String
}
```

### Task 3.6: Huffman Codec (Optional, Phase 3b)

**New file**: `Sources/QPACK/HuffmanCodec.swift`

The Huffman table from RFC 7541 Appendix B. This can be deferred — raw string encoding is always valid.

---

## Phase 4: HTTP/3 Client/Server API

**Priority**: MEDIUM
**Estimated Effort**: 4-6 days

### Task 4.1: HTTP Request/Response Types

**New file**: `Sources/HTTP3/HTTP3Types.swift`

```swift
/// HTTP method
public enum HTTPMethod: String, Sendable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case delete = "DELETE"
    case head = "HEAD"
    case options = "OPTIONS"
    case patch = "PATCH"
    case connect = "CONNECT"
}

/// HTTP/3 request
public struct HTTP3Request: Sendable {
    public var method: HTTPMethod
    public var scheme: String       // "https"
    public var authority: String    // "example.com:443"
    public var path: String         // "/index.html"
    public var headers: [(String, String)]
    public var body: Data?

    public init(
        method: HTTPMethod = .get,
        url: String,
        headers: [(String, String)] = [],
        body: Data? = nil
    )
}

/// HTTP/3 response
public struct HTTP3Response: Sendable {
    public var status: Int
    public var headers: [(String, String)]
    public var body: Data

    public var statusText: String { ... }
}

/// Context for handling an incoming request (server-side)
public struct HTTP3RequestContext: Sendable {
    public let request: HTTP3Request
    public let streamID: UInt64

    /// Send a response back to the client
    public func respond(_ response: HTTP3Response) async throws
}
```

### Task 4.2: HTTP/3 Client

**New file**: `Sources/HTTP3/HTTP3Client.swift`

```swift
/// HTTP/3 client for making requests over QUIC
public actor HTTP3Client {
    private let endpoint: QUICEndpoint
    private var connections: [String: HTTP3Connection]  // authority -> connection

    public init(configuration: QUICConfiguration)

    /// Perform an HTTP/3 request
    /// Reuses connections when possible
    public func request(_ request: HTTP3Request) async throws -> HTTP3Response

    /// Close all connections
    public func close() async
}
```

### Task 4.3: HTTP/3 Server

**New file**: `Sources/HTTP3/HTTP3Server.swift`

```swift
/// HTTP/3 server for handling incoming requests
public actor HTTP3Server {
    public typealias RequestHandler = @Sendable (HTTP3RequestContext) async throws -> Void

    private let endpoint: QUICEndpoint
    private var handler: RequestHandler?

    public init(configuration: QUICConfiguration)

    /// Start listening for HTTP/3 connections
    public func listen(address: SocketAddress) async throws

    /// Register a request handler
    public func onRequest(_ handler: @escaping RequestHandler)

    /// Stop the server
    public func stop() async
}
```

### Task 4.4: Request Stream Handler

**New file**: `Sources/HTTP3/Stream/RequestStreamHandler.swift`

Handles the lifecycle of a single HTTP/3 request stream:

1. **Client side**: Send HEADERS frame → optionally send DATA frames → receive HEADERS + DATA
2. **Server side**: Receive HEADERS + DATA → send HEADERS frame → send DATA frames

```
Client                                   Server
  |                                        |
  |  HEADERS (method, path, headers)       |
  |--------------------------------------->|
  |  DATA (optional body chunks)           |
  |--------------------------------------->|
  |  (FIN if no more data)                 |
  |                                        |
  |  HEADERS (status, headers)             |
  |<---------------------------------------|
  |  DATA (response body chunks)           |
  |<---------------------------------------|
  |  (FIN)                                 |
  |                                        |
```

---

## Phase 5: Integration & Testing

**Priority**: HIGH
**Estimated Effort**: 3-4 days

### Task 5.1: Package.swift Updates

Add new targets:

```swift
// QPACK module
.target(
    name: "QPACK",
    dependencies: ["QUICCore"],
    path: "Sources/QPACK"
),

// HTTP/3 module
.target(
    name: "HTTP3",
    dependencies: ["QUIC", "QPACK", "QUICCore"],
    path: "Sources/HTTP3"
),

// Tests
.testTarget(
    name: "QPACKTests",
    dependencies: ["QPACK"],
    path: "Tests/QPACKTests"
),
.testTarget(
    name: "HTTP3Tests",
    dependencies: ["HTTP3", "QUIC", "QPACK"],
    path: "Tests/HTTP3Tests"
),
```

### Task 5.2: Test Plan

#### Security Tests (Phase 1)
- `QUICCryptoTests/ServerMTLSValidationTests.swift`
  - Server rejects invalid client certificate
  - Server rejects expired client certificate
  - Server rejects wrong EKU (no clientAuth)
  - Server accepts valid client certificate chain
  - Server enforces name constraints on client certs
- `QUICCoreTests/AckRangeLimitTests.swift`
  - ACK frame with > 256 ranges is rejected
  - ACK frame with exactly 256 ranges works
- `QUICCoreTests/HeaderValidationTests.swift`
  - Reserved bits set → validation error
  - Invalid version → validation error

#### QPACK Tests (Phase 3)
- `QPACKTests/StaticTableTests.swift`
  - All 99 entries accessible
  - Exact match lookup works
  - Name-only match lookup works
- `QPACKTests/IntegerCodingTests.swift`
  - Encode/decode round-trip for various prefix lengths
  - Edge cases: 0, max values, boundary values
- `QPACKTests/EncoderDecoderTests.swift`
  - Encode common headers → decode → match original
  - Static table references used when possible
  - Unknown headers encoded as literals

#### HTTP/3 Tests (Phases 2 + 4)
- `HTTP3Tests/FrameCodecTests.swift`
  - Encode/decode each HTTP/3 frame type
  - Unknown frame types pass through (forward compatibility)
  - Settings encode/decode round-trip
- `HTTP3Tests/SettingsTests.swift`
  - Default settings
  - Custom settings encode/decode
  - Unknown settings are ignored (forward compatibility)
- `HTTP3Tests/ConnectionTests.swift`
  - Control stream established on init
  - SETTINGS exchanged
  - GOAWAY handling
- `HTTP3Tests/RequestResponseTests.swift`
  - Simple GET request/response
  - POST with body
  - Multiple concurrent requests
  - Large response body (multi-DATA-frame)

### Task 5.3: Integration Test (End-to-End)

```swift
func testHTTP3EndToEnd() async throws {
    // 1. Create server with TLS certificate
    let serverConfig = QUICConfiguration.development {
        TLS13Handler(configuration: .server(
            signingKey: testSigningKey,
            certificateChain: [testCertDER]
        ))
    }

    let server = HTTP3Server(configuration: serverConfig)
    server.onRequest { ctx in
        let response = HTTP3Response(
            status: 200,
            headers: [("content-type", "text/plain")],
            body: Data("Hello, HTTP/3!".utf8)
        )
        try await ctx.respond(response)
    }
    try await server.listen(address: SocketAddress(ipAddress: "127.0.0.1", port: 4433))

    // 2. Create client
    let clientConfig = QUICConfiguration.development {
        TLS13Handler(configuration: .client(serverName: "localhost"))
    }
    let client = HTTP3Client(configuration: clientConfig)

    // 3. Make request
    let request = HTTP3Request(method: .get, url: "https://127.0.0.1:4433/")
    let response = try await client.request(request)

    XCTAssertEqual(response.status, 200)
    XCTAssertEqual(String(data: response.body, encoding: .utf8), "Hello, HTTP/3!")

    // 4. Cleanup
    await client.close()
    await server.stop()
}
```

---

## Module Structure

```
swift-quic/
├── Sources/
│   ├── QUIC/                        # Existing — high-level QUIC API
│   ├── QUICCore/                    # Existing — core types
│   ├── QUICCrypto/                  # Existing — TLS 1.3 + crypto
│   ├── QUICConnection/              # Existing — connection management
│   ├── QUICRecovery/                # Existing — loss detection
│   ├── QUICStream/                  # Existing — stream management
│   ├── QUICTransport/               # Existing — UDP transport
│   │
│   ├── QPACK/                       # NEW — RFC 9204
│   │   ├── QPACKEncoder.swift
│   │   ├── QPACKDecoder.swift
│   │   ├── QPACKInteger.swift
│   │   ├── QPACKString.swift
│   │   ├── StaticTable.swift
│   │   └── HuffmanCodec.swift       # Phase 3b (optional)
│   │
│   └── HTTP3/                       # NEW — RFC 9114
│       ├── Frame/
│       │   ├── HTTP3Frame.swift
│       │   └── HTTP3FrameCodec.swift
│       ├── Stream/
│       │   ├── HTTP3StreamType.swift
│       │   ├── ControlStream.swift
│       │   └── RequestStreamHandler.swift
│       ├── HTTP3Connection.swift
│       ├── HTTP3Client.swift
│       ├── HTTP3Server.swift
│       ├── HTTP3Settings.swift
│       ├── HTTP3Error.swift
│       └── HTTP3Types.swift
│
├── Tests/
│   ├── QPACKTests/                  # NEW
│   │   ├── StaticTableTests.swift
│   │   ├── IntegerCodingTests.swift
│   │   └── EncoderDecoderTests.swift
│   ├── HTTP3Tests/                  # NEW
│   │   ├── FrameCodecTests.swift
│   │   ├── SettingsTests.swift
│   │   ├── ConnectionTests.swift
│   │   └── RequestResponseTests.swift
│   └── ... (existing test targets)
│
└── Package.swift                    # Updated with new targets
```

---

## Implementation Details

### HTTP/3 Wire Format

#### Frame Format (RFC 9114 Section 7.1)

```
HTTP/3 Frame {
  Type (i),         // QUIC variable-length integer
  Length (i),        // QUIC variable-length integer
  Frame Payload (..) // Length bytes
}
```

All HTTP/3 frames use QUIC varint encoding for type and length fields.
The existing `Varint` module in QUICCore can be reused directly.

#### SETTINGS Frame (RFC 9114 Section 7.2.4)

```
SETTINGS Frame {
  Type (i) = 0x04,
  Length (i),
  Setting {
    Identifier (i),    // varint setting ID
    Value (i),         // varint value
  } ...               // repeated
}
```

Settings identifiers:
- `0x01` — `SETTINGS_MAX_FIELD_SECTION_SIZE`
- `0x06` — `SETTINGS_MAX_TABLE_CAPACITY` (QPACK)
- `0x07` — `SETTINGS_QPACK_BLOCKED_STREAMS` (QPACK)

Unknown settings MUST be ignored (forward compatibility).

#### HEADERS Frame (RFC 9114 Section 7.2.2)

```
HEADERS Frame {
  Type (i) = 0x01,
  Length (i),
  Encoded Field Section (..)   // QPACK-encoded headers
}
```

#### DATA Frame (RFC 9114 Section 7.2.1)

```
DATA Frame {
  Type (i) = 0x00,
  Length (i),
  Data (..)
}
```

### QPACK Wire Format (Literal-Only Mode)

When `SETTINGS_MAX_TABLE_CAPACITY = 0` (our initial implementation):

#### Encoded Field Section Prefix

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|   Required Insert Count (8+)  |   = 0 (no dynamic table)
+---+---+---+---+---+---+---+---+
| S |      Delta Base (7+)      |   = 0
+---+---+---+---+---+---+---+---+
| Encoded Field Lines ...       |
+-------------------------------+
```

#### Indexed Field Line (static table reference)

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 1 | T |     Index (6+)        |   T=1 for static table
+---+---+---+---+---+---+---+---+
```

#### Literal Field Line With Name Reference

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 1 | N | T |  Name Idx(4+)|   T=1 for static table
+---+---+---+---+---+---+---+---+
| H |   Value Length (7+)       |
+---+---+---+---+---+---+---+---+
| Value String (Length bytes)   |
+-------------------------------+
```

#### Literal Field Line With Literal Name

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 1 | N | H | NameLen  |
+---+---+---+---+---+---+---+---+
| Name String (NameLen bytes)   |
+---+---+---+---+---+---+---+---+
| H |   Value Length (7+)       |
+---+---+---+---+---+---+---+---+
| Value String (Length bytes)   |
+-------------------------------+
```

### HTTP/3 Connection Establishment Flow

```
Client                                     Server
  |                                          |
  |  QUIC Initial (ClientHello)              |
  |----------------------------------------->|
  |  QUIC Handshake (ServerHello, etc.)      |
  |<-----------------------------------------|
  |  QUIC Handshake (Finished)               |
  |----------------------------------------->|
  |  HANDSHAKE_DONE                          |
  |<-----------------------------------------|
  |                                          |
  |  === QUIC connection established ===     |
  |  === ALPN: "h3" negotiated ===           |
  |                                          |
  |  Open uni stream: Control (type=0x00)    |
  |  Send SETTINGS frame                     |
  |----------------------------------------->|
  |                                          |
  |  Open uni stream: QPACK Encoder (0x02)   |
  |----------------------------------------->|
  |                                          |
  |  Open uni stream: QPACK Decoder (0x03)   |
  |----------------------------------------->|
  |                                          |
  |  (Server also opens same 3 uni streams)  |
  |<-----------------------------------------|
  |                                          |
  |  === HTTP/3 connection ready ===         |
  |                                          |
  |  Open bidi stream: Request               |
  |  Send HEADERS frame (GET /index.html)    |
  |----------------------------------------->|
  |                                          |
  |  HEADERS frame (200 OK)                  |
  |<-----------------------------------------|
  |  DATA frame (response body)              |
  |<-----------------------------------------|
  |  (FIN)                                   |
  |<-----------------------------------------|
```

### Pseudo-Headers (RFC 9114 Section 4.3)

HTTP/3 requests MUST include these pseudo-headers:
- `:method` — HTTP method (GET, POST, etc.)
- `:scheme` — URI scheme (https)
- `:authority` — Host + optional port
- `:path` — Request path

HTTP/3 responses MUST include:
- `:status` — HTTP status code as string ("200", "404", etc.)

Pseudo-headers MUST appear before regular headers and MUST NOT appear in trailers.

### Key Design Decisions

1. **QPACK literal-only mode first** — Dynamic table adds complexity (encoder/decoder stream synchronization, blocking). Literal-only mode is simpler, fully compliant, and sufficient for most use cases. Can add dynamic table later.

2. **Actor-based HTTP3Connection** — Isolates state management for thread safety, consistent with Swift 6 concurrency.

3. **Reuse existing Varint** — HTTP/3 uses the same variable-length integer encoding as QUIC (RFC 9000 Section 16). The `QUICCore.Varint` module is directly reusable.

4. **Forward compatibility** — Unknown frame types and settings are ignored per RFC 9114 Section 4.1 and 7.2.4.

5. **No server push initially** — Server push (PUSH_PROMISE) is rarely used and being deprecated in practice. Frame type is defined but not implemented in v1.

---

## Implementation Order

```
Week 1: Security Hardening (Phase 1)
  ├── Day 1-2: GAP-1 (mTLS validation) + GAP-2 (ACK limit) + tests
  └── Day 3:   GAP-3 (header validation) + GAP-4 + GAP-5 + tests

Week 2: QPACK (Phase 3) + HTTP/3 Frames (Phase 2 partial)
  ├── Day 1:   QPACK static table + integer/string encoding
  ├── Day 2:   QPACK encoder + decoder
  ├── Day 3:   HTTP/3 frame types + codec
  └── Day 4:   HTTP/3 settings + error codes

Week 3: HTTP/3 Connection + API (Phase 2 + 4)
  ├── Day 1-2: HTTP3Connection (control streams, SETTINGS exchange)
  ├── Day 3:   Request stream handler
  └── Day 4-5: HTTP3Client + HTTP3Server

Week 4: Integration & Polish (Phase 5)
  ├── Day 1-2: End-to-end tests
  ├── Day 3:   Package.swift updates, documentation
  └── Day 4:   Code review, edge cases, cleanup
```

---

## Dependencies

No new external dependencies required. HTTP/3 and QPACK are built entirely on top of existing modules:

- `QUICCore.Varint` — Variable-length integer encoding
- `QUICCore.Frame` — Frame type infrastructure pattern
- `QUIC.QUICConnectionProtocol` — Connection/stream interface
- `QUIC.QUICStreamProtocol` — Stream read/write
- `QUIC.QUICEndpoint` — Client/server endpoint management
- `QUIC.QUICConfiguration` — Configuration with TLS

---

## References

- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9204: QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001: QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9002: QUIC Loss Detection](https://www.rfc-editor.org/rfc/rfc9002.html)
- [RFC 7541: HPACK (Huffman table)](https://www.rfc-editor.org/rfc/rfc7541.html)
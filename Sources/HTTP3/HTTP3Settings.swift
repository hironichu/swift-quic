/// HTTP/3 Settings (RFC 9114 Section 7.2.4)
///
/// SETTINGS parameters convey configuration information that affects how
/// endpoints communicate. Each peer sends a SETTINGS frame as the first
/// frame on the control stream.
///
/// ## Wire Format
///
/// ```
/// SETTINGS Frame {
///   Type (i) = 0x04,
///   Length (i),
///   Setting {
///     Identifier (i),    // varint setting ID
///     Value (i),         // varint value
///   } ...               // repeated
/// }
/// ```
///
/// ## Known Settings
///
/// | Identifier | Name                          | Default    |
/// |------------|-------------------------------|------------|
/// | 0x01       | SETTINGS_MAX_TABLE_CAPACITY   | 0          |
/// | 0x06       | SETTINGS_MAX_FIELD_SECTION_SIZE| unlimited |
/// | 0x07       | SETTINGS_QPACK_BLOCKED_STREAMS| 0          |
///
/// Unknown settings MUST be ignored (forward compatibility per RFC 9114 Section 7.2.4).
///
/// ## HTTP/2 Settings That MUST NOT Appear
///
/// The following HTTP/2 setting identifiers MUST NOT be sent in HTTP/3.
/// Receipt of these is a connection error of type H3_SETTINGS_ERROR:
///
/// - 0x02: SETTINGS_ENABLE_PUSH
/// - 0x03: SETTINGS_MAX_CONCURRENT_STREAMS
/// - 0x04: SETTINGS_INITIAL_WINDOW_SIZE
/// - 0x05: SETTINGS_MAX_FRAME_SIZE
/// - 0x08: SETTINGS_MAX_HEADER_LIST_SIZE

import Foundation

// MARK: - HTTP/3 Settings

/// HTTP/3 connection settings (RFC 9114 Section 7.2.4)
///
/// Settings are exchanged via SETTINGS frames on the control stream.
/// Each peer sends exactly one SETTINGS frame as the first frame on
/// its control stream. A second SETTINGS frame is a connection error.
///
/// ## Usage
///
/// ```swift
/// // Default settings (literal-only QPACK, no dynamic table)
/// let defaults = HTTP3Settings()
///
/// // Custom settings with QPACK dynamic table
/// var settings = HTTP3Settings()
/// settings.maxTableCapacity = 4096
/// settings.qpackBlockedStreams = 100
/// settings.maxFieldSectionSize = 16384
///
/// // Encode into a SETTINGS frame
/// let frame = HTTP3Frame.settings(settings)
/// let encoded = HTTP3FrameCodec.encode(frame)
/// ```
public struct HTTP3Settings: Sendable, Hashable {

    // MARK: - Known Settings

    /// Maximum size of the QPACK dynamic table in bytes.
    ///
    /// Corresponds to `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (identifier 0x01).
    ///
    /// A value of 0 (the default) means no dynamic table is used, which
    /// corresponds to "literal-only" QPACK mode. This is the simplest
    /// configuration and avoids the complexity of dynamic table synchronization.
    ///
    /// - Default: 0
    /// - RFC Reference: RFC 9204 Section 3.2.3
    public var maxTableCapacity: UInt64 = 0

    /// Maximum size of a field section (header block) that this endpoint
    /// is willing to accept, in bytes.
    ///
    /// Corresponds to `SETTINGS_MAX_FIELD_SECTION_SIZE` (identifier 0x06).
    ///
    /// The size of a field section is calculated as the sum of the size of
    /// all header fields, where each field's size is the sum of the field
    /// name length and the field value length, plus 32 bytes of overhead.
    ///
    /// A value of `UInt64.max` means unlimited (the default). Endpoints
    /// should set a reasonable limit to prevent memory exhaustion.
    ///
    /// - Default: `UInt64.max` (unlimited)
    /// - RFC Reference: RFC 9114 Section 7.2.4.1
    public var maxFieldSectionSize: UInt64 = UInt64.max

    /// Maximum number of streams that can be blocked waiting for QPACK
    /// dynamic table updates.
    ///
    /// Corresponds to `SETTINGS_QPACK_BLOCKED_STREAMS` (identifier 0x07).
    ///
    /// A value of 0 (the default) means no streams can be blocked, which
    /// forces the encoder to only reference dynamic table entries that have
    /// already been acknowledged. This is the safest configuration.
    ///
    /// - Default: 0
    /// - RFC Reference: RFC 9204 Section 3.2.3
    public var qpackBlockedStreams: UInt64 = 0

    // MARK: - Forward Compatibility

    /// Additional settings from the peer that are not recognized.
    ///
    /// Per RFC 9114 Section 7.2.4, unknown settings MUST be ignored.
    /// We store them here for debugging, logging, and potential re-encoding.
    ///
    /// Each element is a tuple of (identifier, value).
    public var additionalSettings: [(UInt64, UInt64)] = []

    // MARK: - Initialization

    /// Creates default HTTP/3 settings.
    ///
    /// All known settings are at their default values:
    /// - `maxTableCapacity`: 0 (no dynamic table)
    /// - `maxFieldSectionSize`: unlimited
    /// - `qpackBlockedStreams`: 0 (no blocking)
    public init() {}

    /// Creates HTTP/3 settings with explicit values.
    ///
    /// - Parameters:
    ///   - maxTableCapacity: Maximum QPACK dynamic table size (default: 0)
    ///   - maxFieldSectionSize: Maximum field section size (default: unlimited)
    ///   - qpackBlockedStreams: Maximum blocked streams (default: 0)
    public init(
        maxTableCapacity: UInt64 = 0,
        maxFieldSectionSize: UInt64 = UInt64.max,
        qpackBlockedStreams: UInt64 = 0
    ) {
        self.maxTableCapacity = maxTableCapacity
        self.maxFieldSectionSize = maxFieldSectionSize
        self.qpackBlockedStreams = qpackBlockedStreams
    }

    // MARK: - Validation

    /// Whether these settings use a dynamic table.
    ///
    /// Returns `true` if `maxTableCapacity > 0`, indicating that the
    /// QPACK dynamic table is enabled.
    public var usesDynamicTable: Bool {
        maxTableCapacity > 0
    }

    /// Whether these settings represent literal-only QPACK mode.
    ///
    /// In literal-only mode, both `maxTableCapacity` and `qpackBlockedStreams`
    /// are 0, meaning no dynamic table is used and no streams can be blocked.
    public var isLiteralOnly: Bool {
        maxTableCapacity == 0 && qpackBlockedStreams == 0
    }

    /// Whether these settings have a limited field section size.
    ///
    /// Returns `true` if `maxFieldSectionSize` is not the unlimited default.
    public var hasFieldSectionSizeLimit: Bool {
        maxFieldSectionSize != UInt64.max
    }

    // MARK: - Merging

    /// Applies peer settings to determine effective limits.
    ///
    /// When both sides have sent SETTINGS, the effective configuration
    /// for sending is constrained by the peer's limits.
    ///
    /// - Parameter peerSettings: The settings received from the peer
    /// - Returns: The effective limits for sending to this peer
    public func effectiveSendLimits(peerSettings: HTTP3Settings) -> HTTP3Settings {
        var effective = HTTP3Settings()

        // The peer's maxTableCapacity limits our encoder's dynamic table
        effective.maxTableCapacity = min(maxTableCapacity, peerSettings.maxTableCapacity)

        // The peer's maxFieldSectionSize limits what we can send
        effective.maxFieldSectionSize = peerSettings.maxFieldSectionSize

        // The peer's qpackBlockedStreams limits our encoder's blocking
        effective.qpackBlockedStreams = min(qpackBlockedStreams, peerSettings.qpackBlockedStreams)

        return effective
    }

    // MARK: - Hashable (excluding additionalSettings)

    /// Hashes the known settings values.
    ///
    /// Note: `additionalSettings` is excluded from hashing for simplicity.
    /// Two settings with the same known values but different additional
    /// settings will hash the same way.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(maxTableCapacity)
        hasher.combine(maxFieldSectionSize)
        hasher.combine(qpackBlockedStreams)
    }

    /// Compares known settings for equality.
    ///
    /// Note: `additionalSettings` is included in the comparison.
    public static func == (lhs: HTTP3Settings, rhs: HTTP3Settings) -> Bool {
        guard lhs.maxTableCapacity == rhs.maxTableCapacity,
              lhs.maxFieldSectionSize == rhs.maxFieldSectionSize,
              lhs.qpackBlockedStreams == rhs.qpackBlockedStreams,
              lhs.additionalSettings.count == rhs.additionalSettings.count else {
            return false
        }

        // Compare additional settings
        for (lEntry, rEntry) in zip(lhs.additionalSettings, rhs.additionalSettings) {
            if lEntry.0 != rEntry.0 || lEntry.1 != rEntry.1 {
                return false
            }
        }
        return true
    }
}

// MARK: - CustomStringConvertible

extension HTTP3Settings: CustomStringConvertible {
    public var description: String {
        var parts: [String] = []

        if maxTableCapacity != 0 {
            parts.append("maxTableCapacity=\(maxTableCapacity)")
        }
        if maxFieldSectionSize != UInt64.max {
            parts.append("maxFieldSectionSize=\(maxFieldSectionSize)")
        }
        if qpackBlockedStreams != 0 {
            parts.append("qpackBlockedStreams=\(qpackBlockedStreams)")
        }
        if !additionalSettings.isEmpty {
            parts.append("+\(additionalSettings.count) unknown")
        }

        if parts.isEmpty {
            return "HTTP3Settings(defaults)"
        }
        return "HTTP3Settings(\(parts.joined(separator: ", ")))"
    }
}

// MARK: - Predefined Configurations

extension HTTP3Settings {

    /// Default settings for literal-only QPACK mode.
    ///
    /// This is the simplest and safest configuration:
    /// - No dynamic table (`maxTableCapacity = 0`)
    /// - No blocked streams (`qpackBlockedStreams = 0`)
    /// - Unlimited field section size
    public static let literalOnly = HTTP3Settings()

    /// Settings with a small QPACK dynamic table enabled.
    ///
    /// Suitable for connections with moderate header compression needs:
    /// - 4 KB dynamic table
    /// - Up to 100 blocked streams
    /// - 64 KB max field section size
    public static let smallDynamicTable = HTTP3Settings(
        maxTableCapacity: 4096,
        maxFieldSectionSize: 65536,
        qpackBlockedStreams: 100
    )

    /// Settings with a larger QPACK dynamic table.
    ///
    /// Suitable for high-throughput connections:
    /// - 16 KB dynamic table
    /// - Up to 200 blocked streams
    /// - 256 KB max field section size
    public static let largeDynamicTable = HTTP3Settings(
        maxTableCapacity: 16384,
        maxFieldSectionSize: 262144,
        qpackBlockedStreams: 200
    )
}
/// HTTP/3 Tests
///
/// Tests for HTTP/3 frame codec, settings, types, error codes,
/// and stream type handling (RFC 9114).

import XCTest
import Foundation
@testable import HTTP3
@testable import QUIC
@testable import QUICCore
@testable import QPACK

// MARK: - HTTP/3 Frame Type Tests

final class HTTP3FrameTypeTests: XCTestCase {

    // MARK: - Frame Type Identifiers

    func testFrameTypeRawValues() {
        XCTAssertEqual(HTTP3FrameType.data.rawValue, 0x00)
        XCTAssertEqual(HTTP3FrameType.headers.rawValue, 0x01)
        XCTAssertEqual(HTTP3FrameType.cancelPush.rawValue, 0x03)
        XCTAssertEqual(HTTP3FrameType.settings.rawValue, 0x04)
        XCTAssertEqual(HTTP3FrameType.pushPromise.rawValue, 0x05)
        XCTAssertEqual(HTTP3FrameType.goaway.rawValue, 0x07)
        XCTAssertEqual(HTTP3FrameType.maxPushID.rawValue, 0x0d)
    }

    func testFrameTypeDescriptions() {
        XCTAssertEqual(HTTP3FrameType.data.description, "DATA")
        XCTAssertEqual(HTTP3FrameType.headers.description, "HEADERS")
        XCTAssertEqual(HTTP3FrameType.settings.description, "SETTINGS")
        XCTAssertEqual(HTTP3FrameType.goaway.description, "GOAWAY")
    }

    // MARK: - Frame Properties

    func testFrameTypeProperty() {
        let dataFrame = HTTP3Frame.data(Data([1, 2, 3]))
        XCTAssertEqual(dataFrame.frameType, 0x00)

        let headersFrame = HTTP3Frame.headers(Data([4, 5, 6]))
        XCTAssertEqual(headersFrame.frameType, 0x01)

        let settingsFrame = HTTP3Frame.settings(HTTP3Settings())
        XCTAssertEqual(settingsFrame.frameType, 0x04)

        let goawayFrame = HTTP3Frame.goaway(streamID: 42)
        XCTAssertEqual(goawayFrame.frameType, 0x07)

        let unknownFrame = HTTP3Frame.unknown(type: 0xff, payload: Data())
        XCTAssertEqual(unknownFrame.frameType, 0xff)
    }

    func testControlStreamAllowedFrames() {
        XCTAssertTrue(HTTP3Frame.settings(HTTP3Settings()).isAllowedOnControlStream)
        XCTAssertTrue(HTTP3Frame.goaway(streamID: 0).isAllowedOnControlStream)
        XCTAssertTrue(HTTP3Frame.maxPushID(pushID: 0).isAllowedOnControlStream)
        XCTAssertTrue(HTTP3Frame.cancelPush(pushID: 0).isAllowedOnControlStream)
        XCTAssertTrue(HTTP3Frame.unknown(type: 0xff, payload: Data()).isAllowedOnControlStream)

        XCTAssertFalse(HTTP3Frame.data(Data()).isAllowedOnControlStream)
        XCTAssertFalse(HTTP3Frame.headers(Data()).isAllowedOnControlStream)
        XCTAssertFalse(HTTP3Frame.pushPromise(pushID: 0, headerBlock: Data()).isAllowedOnControlStream)
    }

    func testRequestStreamAllowedFrames() {
        XCTAssertTrue(HTTP3Frame.data(Data()).isAllowedOnRequestStream)
        XCTAssertTrue(HTTP3Frame.headers(Data()).isAllowedOnRequestStream)
        XCTAssertTrue(HTTP3Frame.pushPromise(pushID: 0, headerBlock: Data()).isAllowedOnRequestStream)
        XCTAssertTrue(HTTP3Frame.unknown(type: 0xff, payload: Data()).isAllowedOnRequestStream)

        XCTAssertFalse(HTTP3Frame.settings(HTTP3Settings()).isAllowedOnRequestStream)
        XCTAssertFalse(HTTP3Frame.goaway(streamID: 0).isAllowedOnRequestStream)
        XCTAssertFalse(HTTP3Frame.maxPushID(pushID: 0).isAllowedOnRequestStream)
        XCTAssertFalse(HTTP3Frame.cancelPush(pushID: 0).isAllowedOnRequestStream)
    }

    // MARK: - Frame Equality

    func testFrameEquality() {
        let data1 = HTTP3Frame.data(Data([1, 2, 3]))
        let data2 = HTTP3Frame.data(Data([1, 2, 3]))
        let data3 = HTTP3Frame.data(Data([4, 5, 6]))
        XCTAssertEqual(data1, data2)
        XCTAssertNotEqual(data1, data3)

        let settings1 = HTTP3Frame.settings(HTTP3Settings())
        let settings2 = HTTP3Frame.settings(HTTP3Settings())
        XCTAssertEqual(settings1, settings2)

        let goaway1 = HTTP3Frame.goaway(streamID: 10)
        let goaway2 = HTTP3Frame.goaway(streamID: 10)
        let goaway3 = HTTP3Frame.goaway(streamID: 20)
        XCTAssertEqual(goaway1, goaway2)
        XCTAssertNotEqual(goaway1, goaway3)

        // Different types are never equal
        XCTAssertNotEqual(HTTP3Frame.data(Data()), HTTP3Frame.headers(Data()))
    }

    // MARK: - Reserved Frame Types

    func testReservedFrameTypes() {
        XCTAssertTrue(HTTP3ReservedFrameType.isReserved(0x02))  // PRIORITY
        XCTAssertTrue(HTTP3ReservedFrameType.isReserved(0x06))  // PING
        XCTAssertTrue(HTTP3ReservedFrameType.isReserved(0x08))  // WINDOW_UPDATE
        XCTAssertTrue(HTTP3ReservedFrameType.isReserved(0x09))  // CONTINUATION

        XCTAssertFalse(HTTP3ReservedFrameType.isReserved(0x00))  // DATA
        XCTAssertFalse(HTTP3ReservedFrameType.isReserved(0x01))  // HEADERS
        XCTAssertFalse(HTTP3ReservedFrameType.isReserved(0x04))  // SETTINGS
        XCTAssertFalse(HTTP3ReservedFrameType.isReserved(0x07))  // GOAWAY
    }

    // MARK: - GREASE Frame Types

    func testGreaseFrameTypes() {
        // 0x1f * N + 0x21 for N = 0, 1, 2, ...
        XCTAssertTrue(HTTP3GreaseFrameType.isGrease(0x21))   // N=0
        XCTAssertTrue(HTTP3GreaseFrameType.isGrease(0x40))   // N=1: 0x1f + 0x21 = 0x40
        XCTAssertTrue(HTTP3GreaseFrameType.isGrease(0x5f))   // N=2: 0x3e + 0x21 = 0x5f

        XCTAssertFalse(HTTP3GreaseFrameType.isGrease(0x00))
        XCTAssertFalse(HTTP3GreaseFrameType.isGrease(0x01))
        XCTAssertFalse(HTTP3GreaseFrameType.isGrease(0x04))
        XCTAssertFalse(HTTP3GreaseFrameType.isGrease(0x20))
        XCTAssertFalse(HTTP3GreaseFrameType.isGrease(0x22))
    }
}

// MARK: - HTTP/3 Frame Codec Tests

final class HTTP3FrameCodecTests: XCTestCase {

    // MARK: - DATA Frame

    func testEncodeDecodeDataFrame() throws {
        let payload = Data("Hello, HTTP/3!".utf8)
        let frame = HTTP3Frame.data(payload)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        XCTAssertEqual(decoded, frame)

        if case .data(let decodedPayload) = decoded {
            XCTAssertEqual(decodedPayload, payload)
        } else {
            XCTFail("Expected DATA frame, got \(decoded)")
        }
    }

    func testEncodeDecodeEmptyDataFrame() throws {
        let frame = HTTP3Frame.data(Data())

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        XCTAssertEqual(decoded, frame)

        if case .data(let payload) = decoded {
            XCTAssertTrue(payload.isEmpty)
        } else {
            XCTFail("Expected empty DATA frame")
        }
    }

    // MARK: - HEADERS Frame

    func testEncodeDecodeHeadersFrame() throws {
        let headerBlock = Data([0x00, 0x00, 0xc0 | 17])  // Minimal QPACK encoded
        let frame = HTTP3Frame.headers(headerBlock)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        XCTAssertEqual(decoded, frame)
    }

    // MARK: - SETTINGS Frame

    func testEncodeDecodeDefaultSettings() throws {
        let settings = HTTP3Settings()
        let frame = HTTP3Frame.settings(settings)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .settings(let decodedSettings) = decoded {
            XCTAssertEqual(decodedSettings.maxTableCapacity, 0)
            XCTAssertEqual(decodedSettings.maxFieldSectionSize, UInt64.max)
            XCTAssertEqual(decodedSettings.qpackBlockedStreams, 0)
        } else {
            XCTFail("Expected SETTINGS frame, got \(decoded)")
        }
    }

    func testEncodeDecodeCustomSettings() throws {
        var settings = HTTP3Settings()
        settings.maxTableCapacity = 4096
        settings.maxFieldSectionSize = 16384
        settings.qpackBlockedStreams = 100
        let frame = HTTP3Frame.settings(settings)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .settings(let decodedSettings) = decoded {
            XCTAssertEqual(decodedSettings.maxTableCapacity, 4096)
            XCTAssertEqual(decodedSettings.maxFieldSectionSize, 16384)
            XCTAssertEqual(decodedSettings.qpackBlockedStreams, 100)
        } else {
            XCTFail("Expected SETTINGS frame")
        }
    }

    func testDefaultSettingsProduceEmptyPayload() throws {
        // Default settings have all default values, so the payload should be empty
        let settings = HTTP3Settings()
        let frame = HTTP3Frame.settings(settings)

        let encoded = HTTP3FrameCodec.encode(frame)
        // Frame should be: type varint (0x04 = 1 byte) + length varint (0x00 = 1 byte) = 2 bytes
        XCTAssertEqual(encoded.count, 2)
        XCTAssertEqual(encoded[0], 0x04)  // SETTINGS type
        XCTAssertEqual(encoded[1], 0x00)  // Empty payload
    }

    // MARK: - GOAWAY Frame

    func testEncodeDecodeGoawayFrame() throws {
        let frame = HTTP3Frame.goaway(streamID: 256)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .goaway(let streamID) = decoded {
            XCTAssertEqual(streamID, 256)
        } else {
            XCTFail("Expected GOAWAY frame, got \(decoded)")
        }
    }

    func testEncodeDecodeGoawayZero() throws {
        let frame = HTTP3Frame.goaway(streamID: 0)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, _) = try HTTP3FrameCodec.decode(from: encoded)

        if case .goaway(let streamID) = decoded {
            XCTAssertEqual(streamID, 0)
        } else {
            XCTFail("Expected GOAWAY frame")
        }
    }

    // MARK: - CANCEL_PUSH Frame

    func testEncodeDecodeCancelPushFrame() throws {
        let frame = HTTP3Frame.cancelPush(pushID: 7)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .cancelPush(let pushID) = decoded {
            XCTAssertEqual(pushID, 7)
        } else {
            XCTFail("Expected CANCEL_PUSH frame")
        }
    }

    // MARK: - MAX_PUSH_ID Frame

    func testEncodeDecodeMaxPushIDFrame() throws {
        let frame = HTTP3Frame.maxPushID(pushID: 42)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .maxPushID(let pushID) = decoded {
            XCTAssertEqual(pushID, 42)
        } else {
            XCTFail("Expected MAX_PUSH_ID frame")
        }
    }

    // MARK: - PUSH_PROMISE Frame

    func testEncodeDecodePushPromiseFrame() throws {
        let headerBlock = Data([0x00, 0x00, 0xd1])
        let frame = HTTP3Frame.pushPromise(pushID: 3, headerBlock: headerBlock)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .pushPromise(let pushID, let decodedBlock) = decoded {
            XCTAssertEqual(pushID, 3)
            XCTAssertEqual(decodedBlock, headerBlock)
        } else {
            XCTFail("Expected PUSH_PROMISE frame")
        }
    }

    // MARK: - Unknown Frame Type (Forward Compatibility)

    func testEncodeDecodeUnknownFrameType() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let frame = HTTP3Frame.unknown(type: 0xff, payload: payload)

        let encoded = HTTP3FrameCodec.encode(frame)
        let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)

        XCTAssertEqual(consumed, encoded.count)
        if case .unknown(let type, let decodedPayload) = decoded {
            XCTAssertEqual(type, 0xff)
            XCTAssertEqual(decodedPayload, payload)
        } else {
            XCTFail("Expected unknown frame, got \(decoded)")
        }
    }

    // MARK: - Multiple Frames

    func testDecodeMultipleFrames() throws {
        let frame1 = HTTP3Frame.data(Data("Hello".utf8))
        let frame2 = HTTP3Frame.data(Data(" World".utf8))
        let frame3 = HTTP3Frame.goaway(streamID: 4)

        var buffer = Data()
        HTTP3FrameCodec.encode(frame1, into: &buffer)
        HTTP3FrameCodec.encode(frame2, into: &buffer)
        HTTP3FrameCodec.encode(frame3, into: &buffer)

        let (frames, totalConsumed) = try HTTP3FrameCodec.decodeAll(from: buffer)

        XCTAssertEqual(frames.count, 3)
        XCTAssertEqual(totalConsumed, buffer.count)
        XCTAssertEqual(frames[0], frame1)
        XCTAssertEqual(frames[1], frame2)
        XCTAssertEqual(frames[2], frame3)
    }

    func testEncodeMultipleFrames() throws {
        let frames = [
            HTTP3Frame.data(Data("A".utf8)),
            HTTP3Frame.data(Data("B".utf8)),
        ]
        let encoded = HTTP3FrameCodec.encode(frames)

        let (decoded, _) = try HTTP3FrameCodec.decodeAll(from: encoded)
        XCTAssertEqual(decoded.count, 2)
        XCTAssertEqual(decoded[0], frames[0])
        XCTAssertEqual(decoded[1], frames[1])
    }

    // MARK: - Error Cases

    func testDecodeInsufficientData() {
        let data = Data([0x00])  // Type varint only, no length
        XCTAssertThrowsError(try HTTP3FrameCodec.decode(from: data)) { error in
            XCTAssertTrue(error is HTTP3FrameCodecError)
        }
    }

    func testDecodeInsufficientPayloadData() {
        // Type=DATA(0x00), Length=10, but only 3 bytes of payload
        let data = Data([0x00, 0x0a, 0x01, 0x02, 0x03])
        XCTAssertThrowsError(try HTTP3FrameCodec.decode(from: data)) { error in
            if let codecError = error as? HTTP3FrameCodecError {
                if case .insufficientData = codecError {
                    // Expected
                } else {
                    XCTFail("Expected insufficientData, got \(codecError)")
                }
            }
        }
    }

    func testDecodeEmptyData() {
        let data = Data()
        XCTAssertThrowsError(try HTTP3FrameCodec.decode(from: data))
    }

    func testDecodeAllWithPartialFrameAtEnd() throws {
        let frame1 = HTTP3Frame.data(Data("Complete".utf8))
        var buffer = HTTP3FrameCodec.encode(frame1)
        buffer.append(Data([0x00, 0x0a]))  // Partial frame: type + length but no payload

        let (frames, consumed) = try HTTP3FrameCodec.decodeAll(from: buffer)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0], frame1)
        XCTAssertLessThan(consumed, buffer.count)
    }

    // MARK: - Settings Validation

    func testDuplicateSettingIdentifierRejected() {
        // Manually construct a SETTINGS payload with duplicate identifier
        // Identifier=0x01, Value=100, Identifier=0x01, Value=200
        var payload = Data()
        Varint(0x01).encode(to: &payload)
        Varint(100).encode(to: &payload)
        Varint(0x01).encode(to: &payload)
        Varint(200).encode(to: &payload)

        // Wrap in frame: type=0x04, length, payload
        var frame = Data()
        Varint(0x04).encode(to: &frame)
        Varint(UInt64(payload.count)).encode(to: &frame)
        frame.append(payload)

        XCTAssertThrowsError(try HTTP3FrameCodec.decode(from: frame)) { error in
            if let codecError = error as? HTTP3FrameCodecError {
                if case .duplicateSettingIdentifier(let id) = codecError {
                    XCTAssertEqual(id, 0x01)
                } else {
                    XCTFail("Expected duplicateSettingIdentifier, got \(codecError)")
                }
            }
        }
    }

    func testHTTP2SettingRejected() {
        // Manually construct a SETTINGS payload with an HTTP/2-only setting
        // 0x02 = SETTINGS_ENABLE_PUSH (HTTP/2 only)
        var payload = Data()
        Varint(0x02).encode(to: &payload)
        Varint(1).encode(to: &payload)

        var frame = Data()
        Varint(0x04).encode(to: &frame)
        Varint(UInt64(payload.count)).encode(to: &frame)
        frame.append(payload)

        XCTAssertThrowsError(try HTTP3FrameCodec.decode(from: frame)) { error in
            if let codecError = error as? HTTP3FrameCodecError {
                if case .http2SettingReceived(let id) = codecError {
                    XCTAssertEqual(id, 0x02)
                } else {
                    XCTFail("Expected http2SettingReceived, got \(codecError)")
                }
            }
        }
    }

    func testUnknownSettingsIgnored() throws {
        // Unknown settings should be preserved but not cause errors
        var payload = Data()
        Varint(0x01).encode(to: &payload)  // maxTableCapacity
        Varint(4096).encode(to: &payload)
        Varint(0x99).encode(to: &payload)  // Unknown setting
        Varint(42).encode(to: &payload)

        var frame = Data()
        Varint(0x04).encode(to: &frame)
        Varint(UInt64(payload.count)).encode(to: &frame)
        frame.append(payload)

        let (decoded, _) = try HTTP3FrameCodec.decode(from: frame)
        if case .settings(let settings) = decoded {
            XCTAssertEqual(settings.maxTableCapacity, 4096)
            XCTAssertEqual(settings.additionalSettings.count, 1)
            XCTAssertEqual(settings.additionalSettings[0].0, 0x99)
            XCTAssertEqual(settings.additionalSettings[0].1, 42)
        } else {
            XCTFail("Expected SETTINGS frame")
        }
    }

    // MARK: - Size Calculation

    func testEncodedSizeMatchesActualSize() {
        let frames: [HTTP3Frame] = [
            .data(Data("Hello".utf8)),
            .data(Data()),
            .headers(Data([0x00, 0x00, 0xc0])),
            .settings(HTTP3Settings()),
            .goaway(streamID: 100),
            .cancelPush(pushID: 5),
            .maxPushID(pushID: 999),
            .unknown(type: 0xab, payload: Data([1, 2, 3])),
        ]

        for frame in frames {
            let encoded = HTTP3FrameCodec.encode(frame)
            let calculatedSize = HTTP3FrameCodec.encodedSize(of: frame)
            XCTAssertEqual(
                encoded.count, calculatedSize,
                "Size mismatch for \(frame): encoded=\(encoded.count), calculated=\(calculatedSize)"
            )
        }
    }

    // MARK: - Peek Frame Size

    func testPeekFrameSize() {
        let frame = HTTP3Frame.data(Data("Hello".utf8))
        let encoded = HTTP3FrameCodec.encode(frame)

        let peekedSize = HTTP3FrameCodec.peekFrameSize(from: encoded)
        XCTAssertEqual(peekedSize, encoded.count)
    }

    func testPeekFrameSizeWithInsufficientData() {
        XCTAssertNil(HTTP3FrameCodec.peekFrameSize(from: Data()))
        XCTAssertNil(HTTP3FrameCodec.peekFrameSize(from: Data([0x00])))  // Only type, no length
    }

    // MARK: - Round-Trip for All Frame Types

    func testRoundTripAllFrameTypes() throws {
        let frames: [HTTP3Frame] = [
            .data(Data("test payload".utf8)),
            .headers(Data([0x00, 0x00, 0xd1, 0xd7, 0x51, 0x01, 0x2f])),
            .cancelPush(pushID: 0),
            .cancelPush(pushID: 12345),
            .settings(HTTP3Settings()),
            .settings(HTTP3Settings(maxTableCapacity: 8192, maxFieldSectionSize: 32768, qpackBlockedStreams: 50)),
            .pushPromise(pushID: 1, headerBlock: Data([0x00, 0x00])),
            .goaway(streamID: 0),
            .goaway(streamID: 100),
            .maxPushID(pushID: 0),
            .maxPushID(pushID: 1000),
            .unknown(type: 0x1234, payload: Data([0xca, 0xfe])),
        ]

        for original in frames {
            let encoded = HTTP3FrameCodec.encode(original)
            let (decoded, consumed) = try HTTP3FrameCodec.decode(from: encoded)
            XCTAssertEqual(consumed, encoded.count, "Consumed bytes mismatch for \(original)")
            XCTAssertEqual(decoded, original, "Round-trip failed for \(original)")
        }
    }
}

// MARK: - HTTP/3 Settings Tests

final class HTTP3SettingsTests: XCTestCase {

    func testDefaultSettings() {
        let settings = HTTP3Settings()
        XCTAssertEqual(settings.maxTableCapacity, 0)
        XCTAssertEqual(settings.maxFieldSectionSize, UInt64.max)
        XCTAssertEqual(settings.qpackBlockedStreams, 0)
        XCTAssertTrue(settings.additionalSettings.isEmpty)
    }

    func testCustomSettings() {
        let settings = HTTP3Settings(
            maxTableCapacity: 4096,
            maxFieldSectionSize: 65536,
            qpackBlockedStreams: 100
        )
        XCTAssertEqual(settings.maxTableCapacity, 4096)
        XCTAssertEqual(settings.maxFieldSectionSize, 65536)
        XCTAssertEqual(settings.qpackBlockedStreams, 100)
    }

    func testIsLiteralOnly() {
        let literalOnly = HTTP3Settings()
        XCTAssertTrue(literalOnly.isLiteralOnly)
        XCTAssertFalse(literalOnly.usesDynamicTable)

        let withDynamic = HTTP3Settings(maxTableCapacity: 4096)
        XCTAssertFalse(withDynamic.isLiteralOnly)
        XCTAssertTrue(withDynamic.usesDynamicTable)

        let withBlocked = HTTP3Settings(maxTableCapacity: 0, qpackBlockedStreams: 10)
        XCTAssertFalse(withBlocked.isLiteralOnly)
    }

    func testHasFieldSectionSizeLimit() {
        let unlimited = HTTP3Settings()
        XCTAssertFalse(unlimited.hasFieldSectionSizeLimit)

        let limited = HTTP3Settings(maxFieldSectionSize: 8192)
        XCTAssertTrue(limited.hasFieldSectionSizeLimit)
    }

    func testSettingsEquality() {
        let a = HTTP3Settings(maxTableCapacity: 100, maxFieldSectionSize: 200, qpackBlockedStreams: 10)
        let b = HTTP3Settings(maxTableCapacity: 100, maxFieldSectionSize: 200, qpackBlockedStreams: 10)
        XCTAssertEqual(a, b)

        let c = HTTP3Settings(maxTableCapacity: 100, maxFieldSectionSize: 300, qpackBlockedStreams: 10)
        XCTAssertNotEqual(a, c)
    }

    func testEffectiveSendLimits() {
        let local = HTTP3Settings(maxTableCapacity: 8192, maxFieldSectionSize: 65536, qpackBlockedStreams: 200)
        let peer = HTTP3Settings(maxTableCapacity: 4096, maxFieldSectionSize: 32768, qpackBlockedStreams: 100)

        let effective = local.effectiveSendLimits(peerSettings: peer)
        XCTAssertEqual(effective.maxTableCapacity, 4096)  // min(8192, 4096)
        XCTAssertEqual(effective.maxFieldSectionSize, 32768)  // peer's limit
        XCTAssertEqual(effective.qpackBlockedStreams, 100)  // min(200, 100)
    }

    func testPredefinedConfigurations() {
        let literalOnly = HTTP3Settings.literalOnly
        XCTAssertTrue(literalOnly.isLiteralOnly)
        XCTAssertEqual(literalOnly.maxTableCapacity, 0)

        let small = HTTP3Settings.smallDynamicTable
        XCTAssertEqual(small.maxTableCapacity, 4096)
        XCTAssertEqual(small.maxFieldSectionSize, 65536)
        XCTAssertEqual(small.qpackBlockedStreams, 100)

        let large = HTTP3Settings.largeDynamicTable
        XCTAssertEqual(large.maxTableCapacity, 16384)
        XCTAssertEqual(large.maxFieldSectionSize, 262144)
        XCTAssertEqual(large.qpackBlockedStreams, 200)
    }

    func testSettingsDescription() {
        let defaults = HTTP3Settings()
        XCTAssertEqual(defaults.description, "HTTP3Settings(defaults)")

        let custom = HTTP3Settings(maxTableCapacity: 100)
        XCTAssertTrue(custom.description.contains("maxTableCapacity=100"))
    }
}

// MARK: - HTTP/3 Error Code Tests

final class HTTP3ErrorCodeTests: XCTestCase {

    func testErrorCodeRawValues() {
        XCTAssertEqual(HTTP3ErrorCode.noError.rawValue, 0x0100)
        XCTAssertEqual(HTTP3ErrorCode.generalProtocolError.rawValue, 0x0101)
        XCTAssertEqual(HTTP3ErrorCode.internalError.rawValue, 0x0102)
        XCTAssertEqual(HTTP3ErrorCode.streamCreationError.rawValue, 0x0103)
        XCTAssertEqual(HTTP3ErrorCode.closedCriticalStream.rawValue, 0x0104)
        XCTAssertEqual(HTTP3ErrorCode.frameUnexpected.rawValue, 0x0105)
        XCTAssertEqual(HTTP3ErrorCode.frameError.rawValue, 0x0106)
        XCTAssertEqual(HTTP3ErrorCode.excessiveLoad.rawValue, 0x0107)
        XCTAssertEqual(HTTP3ErrorCode.idError.rawValue, 0x0108)
        XCTAssertEqual(HTTP3ErrorCode.settingsError.rawValue, 0x0109)
        XCTAssertEqual(HTTP3ErrorCode.missingSettings.rawValue, 0x010a)
        XCTAssertEqual(HTTP3ErrorCode.requestRejected.rawValue, 0x010b)
        XCTAssertEqual(HTTP3ErrorCode.requestCancelled.rawValue, 0x010c)
        XCTAssertEqual(HTTP3ErrorCode.requestIncomplete.rawValue, 0x010d)
        XCTAssertEqual(HTTP3ErrorCode.messageError.rawValue, 0x010e)
        XCTAssertEqual(HTTP3ErrorCode.connectError.rawValue, 0x010f)
        XCTAssertEqual(HTTP3ErrorCode.versionFallback.rawValue, 0x0110)
    }

    func testErrorCodeDescriptions() {
        XCTAssertEqual(HTTP3ErrorCode.noError.description, "H3_NO_ERROR")
        XCTAssertEqual(HTTP3ErrorCode.frameError.description, "H3_FRAME_ERROR")
        XCTAssertEqual(HTTP3ErrorCode.settingsError.description, "H3_SETTINGS_ERROR")
    }

    func testErrorCodeReasons() {
        XCTAssertFalse(HTTP3ErrorCode.noError.reason.isEmpty)
        XCTAssertFalse(HTTP3ErrorCode.frameUnexpected.reason.isEmpty)
        XCTAssertFalse(HTTP3ErrorCode.versionFallback.reason.isEmpty)
    }

    func testQPACKErrorCodes() {
        XCTAssertEqual(QPACKErrorCode.decompressionFailed.rawValue, 0x0200)
        XCTAssertEqual(QPACKErrorCode.encoderStreamError.rawValue, 0x0201)
        XCTAssertEqual(QPACKErrorCode.decoderStreamError.rawValue, 0x0202)
    }

    func testHTTP3Error() {
        let error = HTTP3Error(code: .frameUnexpected, reason: "DATA on control stream")
        XCTAssertEqual(error.code, .frameUnexpected)
        XCTAssertEqual(error.reason, "DATA on control stream")
        XCTAssertTrue(error.isConnectionError)
        XCTAssertFalse(error.isRetryable)
    }

    func testHTTP3ErrorConvenienceConstructors() {
        let noError = HTTP3Error.noError
        XCTAssertEqual(noError.code, .noError)

        let proto = HTTP3Error.protocolError("test")
        XCTAssertEqual(proto.code, .generalProtocolError)
        XCTAssertTrue(proto.isConnectionError)

        let missing = HTTP3Error.missingSettings
        XCTAssertEqual(missing.code, .missingSettings)
        XCTAssertTrue(missing.isConnectionError)

        let cancelled = HTTP3Error.requestCancelled
        XCTAssertEqual(cancelled.code, .requestCancelled)
        XCTAssertFalse(cancelled.isConnectionError)
        XCTAssertFalse(cancelled.isRetryable)
    }

    func testHTTP3ErrorRetryable() {
        let rejected = HTTP3Error(code: .requestRejected, reason: "Try again")
        XCTAssertTrue(rejected.isRetryable)

        let cancelled = HTTP3Error(code: .requestCancelled)
        XCTAssertFalse(cancelled.isRetryable)
    }

    func testGreaseErrorCodes() {
        // 0x1f * N + 0x21
        XCTAssertTrue(HTTP3ErrorCode.isGrease(0x21))
        XCTAssertTrue(HTTP3ErrorCode.isGrease(0x40))

        XCTAssertFalse(HTTP3ErrorCode.isGrease(0x0100))
        XCTAssertFalse(HTTP3ErrorCode.isGrease(0x00))
    }
}

// MARK: - HTTP/3 Stream Type Tests

final class HTTP3StreamTypeTests: XCTestCase {

    func testStreamTypeRawValues() {
        XCTAssertEqual(HTTP3StreamType.control.rawValue, 0x00)
        XCTAssertEqual(HTTP3StreamType.push.rawValue, 0x01)
        XCTAssertEqual(HTTP3StreamType.qpackEncoder.rawValue, 0x02)
        XCTAssertEqual(HTTP3StreamType.qpackDecoder.rawValue, 0x03)
    }

    func testCriticalStreams() {
        XCTAssertTrue(HTTP3StreamType.control.isCritical)
        XCTAssertTrue(HTTP3StreamType.qpackEncoder.isCritical)
        XCTAssertTrue(HTTP3StreamType.qpackDecoder.isCritical)
        XCTAssertFalse(HTTP3StreamType.push.isCritical)
    }

    func testServerOnlyStreams() {
        XCTAssertTrue(HTTP3StreamType.push.isServerOnly)
        XCTAssertFalse(HTTP3StreamType.control.isServerOnly)
        XCTAssertFalse(HTTP3StreamType.qpackEncoder.isServerOnly)
        XCTAssertFalse(HTTP3StreamType.qpackDecoder.isServerOnly)
    }

    func testSingletonStreams() {
        XCTAssertTrue(HTTP3StreamType.control.isSingleton)
        XCTAssertTrue(HTTP3StreamType.qpackEncoder.isSingleton)
        XCTAssertTrue(HTTP3StreamType.qpackDecoder.isSingleton)
        XCTAssertFalse(HTTP3StreamType.push.isSingleton)
    }

    func testStreamTypeEncode() {
        let encoded = HTTP3StreamType.control.encode()
        XCTAssertEqual(encoded, Data([0x00]))

        let encoderEncoded = HTTP3StreamType.qpackEncoder.encode()
        XCTAssertEqual(encoderEncoded, Data([0x02]))
    }

    func testStreamTypeDecode() throws {
        let data = Data([0x00])
        let result = try HTTP3StreamType.decode(from: data)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.0, 0x00)
        XCTAssertEqual(result?.1, 1)
    }

    func testStreamClassification() {
        let control = HTTP3StreamClassification.classify(0x00)
        if case .known(let type) = control {
            XCTAssertEqual(type, .control)
        } else {
            XCTFail("Expected known control stream type")
        }

        let grease = HTTP3StreamClassification.classify(0x21)
        if case .grease(let value) = grease {
            XCTAssertEqual(value, 0x21)
        } else {
            XCTFail("Expected grease stream type")
        }

        let unknown = HTTP3StreamClassification.classify(0x99)
        if case .unknown(let value) = unknown {
            XCTAssertEqual(value, 0x99)
        } else {
            XCTFail("Expected unknown stream type")
        }
    }

    func testGreaseStreamTypes() {
        XCTAssertTrue(HTTP3GreaseStreamType.isGrease(0x21))
        XCTAssertTrue(HTTP3GreaseStreamType.isGrease(0x40))

        XCTAssertFalse(HTTP3GreaseStreamType.isGrease(0x00))
        XCTAssertFalse(HTTP3GreaseStreamType.isGrease(0x01))

        XCTAssertEqual(HTTP3GreaseStreamType.greaseValue(for: 0), 0x21)
        XCTAssertEqual(HTTP3GreaseStreamType.greaseValue(for: 1), 0x40)
    }
}

// MARK: - HTTP/3 Types Tests

final class HTTP3TypesTests: XCTestCase {

    // MARK: - HTTPMethod

    func testHTTPMethodRawValues() {
        XCTAssertEqual(HTTPMethod.get.rawValue, "GET")
        XCTAssertEqual(HTTPMethod.post.rawValue, "POST")
        XCTAssertEqual(HTTPMethod.put.rawValue, "PUT")
        XCTAssertEqual(HTTPMethod.delete.rawValue, "DELETE")
        XCTAssertEqual(HTTPMethod.head.rawValue, "HEAD")
        XCTAssertEqual(HTTPMethod.options.rawValue, "OPTIONS")
        XCTAssertEqual(HTTPMethod.patch.rawValue, "PATCH")
        XCTAssertEqual(HTTPMethod.connect.rawValue, "CONNECT")
        XCTAssertEqual(HTTPMethod.trace.rawValue, "TRACE")
    }

    // MARK: - HTTP3Request

    func testRequestFromComponents() {
        let request = HTTP3Request(
            method: .get,
            scheme: "https",
            authority: "example.com",
            path: "/api/data",
            headers: [("accept", "application/json")]
        )

        XCTAssertEqual(request.method, .get)
        XCTAssertEqual(request.scheme, "https")
        XCTAssertEqual(request.authority, "example.com")
        XCTAssertEqual(request.path, "/api/data")
        XCTAssertEqual(request.headers.count, 1)
        XCTAssertEqual(request.headers[0].0, "accept")
        XCTAssertNil(request.body)
    }

    func testRequestFromURL() {
        let request = HTTP3Request(method: .get, url: "https://example.com/index.html")

        XCTAssertEqual(request.method, .get)
        XCTAssertEqual(request.scheme, "https")
        XCTAssertEqual(request.authority, "example.com")
        XCTAssertEqual(request.path, "/index.html")
    }

    func testRequestFromURLWithPort() {
        let request = HTTP3Request(method: .post, url: "https://localhost:4433/api")

        XCTAssertEqual(request.scheme, "https")
        XCTAssertEqual(request.authority, "localhost:4433")
        XCTAssertEqual(request.path, "/api")
    }

    func testRequestFromURLNoPath() {
        let request = HTTP3Request(method: .get, url: "https://example.com")

        XCTAssertEqual(request.authority, "example.com")
        XCTAssertEqual(request.path, "/")
    }

    func testRequestToHeaderList() {
        let request = HTTP3Request(
            method: .get,
            scheme: "https",
            authority: "example.com",
            path: "/",
            headers: [("accept", "*/*"), ("user-agent", "swift-quic")]
        )

        let headers = request.toHeaderList()
        XCTAssertEqual(headers.count, 6)  // 4 pseudo-headers + 2 regular

        // Pseudo-headers must come first
        XCTAssertEqual(headers[0].name, ":method")
        XCTAssertEqual(headers[0].value, "GET")
        XCTAssertEqual(headers[1].name, ":scheme")
        XCTAssertEqual(headers[1].value, "https")
        XCTAssertEqual(headers[2].name, ":authority")
        XCTAssertEqual(headers[2].value, "example.com")
        XCTAssertEqual(headers[3].name, ":path")
        XCTAssertEqual(headers[3].value, "/")

        // Regular headers
        XCTAssertEqual(headers[4].name, "accept")
        XCTAssertEqual(headers[4].value, "*/*")
        XCTAssertEqual(headers[5].name, "user-agent")
        XCTAssertEqual(headers[5].value, "swift-quic")
    }

    func testRequestFromHeaderList() throws {
        let headers: [(name: String, value: String)] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "api.example.com"),
            (":path", "/submit"),
            ("content-type", "application/json"),
        ]

        let request = try HTTP3Request.fromHeaderList(headers)
        XCTAssertEqual(request.method, .post)
        XCTAssertEqual(request.scheme, "https")
        XCTAssertEqual(request.authority, "api.example.com")
        XCTAssertEqual(request.path, "/submit")
        XCTAssertEqual(request.headers.count, 1)
        XCTAssertEqual(request.headers[0].0, "content-type")
    }

    func testRequestFromHeaderListMissingMethod() {
        let headers: [(name: String, value: String)] = [
            (":scheme", "https"),
            (":path", "/"),
        ]

        XCTAssertThrowsError(try HTTP3Request.fromHeaderList(headers)) { error in
            if let typeError = error as? HTTP3TypeError {
                if case .missingPseudoHeader(let name) = typeError {
                    XCTAssertEqual(name, ":method")
                } else {
                    XCTFail("Expected missingPseudoHeader, got \(typeError)")
                }
            }
        }
    }

    func testRequestFromHeaderListDuplicatePseudoHeader() {
        let headers: [(name: String, value: String)] = [
            (":method", "GET"),
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/"),
        ]

        XCTAssertThrowsError(try HTTP3Request.fromHeaderList(headers)) { error in
            if let typeError = error as? HTTP3TypeError {
                if case .duplicatePseudoHeader(let name) = typeError {
                    XCTAssertEqual(name, ":method")
                }
            }
        }
    }

    func testRequestFromHeaderListUnknownPseudoHeader() {
        let headers: [(name: String, value: String)] = [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":unknown", "value"),
        ]

        XCTAssertThrowsError(try HTTP3Request.fromHeaderList(headers)) { error in
            if let typeError = error as? HTTP3TypeError {
                if case .unknownPseudoHeader(let name) = typeError {
                    XCTAssertEqual(name, ":unknown")
                }
            }
        }
    }

    func testRequestDescription() {
        let request = HTTP3Request(method: .get, url: "https://example.com/path")
        XCTAssertEqual(request.description, "GET https://example.com/path")
    }

    // MARK: - HTTP3Response

    func testResponseCreation() {
        let response = HTTP3Response(
            status: 200,
            headers: [("content-type", "text/plain")],
            body: Data("OK".utf8)
        )

        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.headers.count, 1)
        XCTAssertEqual(response.body, Data("OK".utf8))
    }

    func testResponseStatusText() {
        XCTAssertEqual(HTTP3Response(status: 200).statusText, "OK")
        XCTAssertEqual(HTTP3Response(status: 201).statusText, "Created")
        XCTAssertEqual(HTTP3Response(status: 204).statusText, "No Content")
        XCTAssertEqual(HTTP3Response(status: 301).statusText, "Moved Permanently")
        XCTAssertEqual(HTTP3Response(status: 304).statusText, "Not Modified")
        XCTAssertEqual(HTTP3Response(status: 400).statusText, "Bad Request")
        XCTAssertEqual(HTTP3Response(status: 401).statusText, "Unauthorized")
        XCTAssertEqual(HTTP3Response(status: 403).statusText, "Forbidden")
        XCTAssertEqual(HTTP3Response(status: 404).statusText, "Not Found")
        XCTAssertEqual(HTTP3Response(status: 500).statusText, "Internal Server Error")
        XCTAssertEqual(HTTP3Response(status: 502).statusText, "Bad Gateway")
        XCTAssertEqual(HTTP3Response(status: 503).statusText, "Service Unavailable")
        XCTAssertEqual(HTTP3Response(status: 999).statusText, "Unknown")
    }

    func testResponseStatusCategories() {
        XCTAssertTrue(HTTP3Response(status: 100).isInformational)
        XCTAssertFalse(HTTP3Response(status: 100).isSuccess)

        XCTAssertTrue(HTTP3Response(status: 200).isSuccess)
        XCTAssertFalse(HTTP3Response(status: 200).isRedirect)

        XCTAssertTrue(HTTP3Response(status: 301).isRedirect)
        XCTAssertFalse(HTTP3Response(status: 301).isClientError)

        XCTAssertTrue(HTTP3Response(status: 404).isClientError)
        XCTAssertFalse(HTTP3Response(status: 404).isServerError)

        XCTAssertTrue(HTTP3Response(status: 500).isServerError)
        XCTAssertFalse(HTTP3Response(status: 500).isSuccess)
    }

    func testResponseToHeaderList() {
        let response = HTTP3Response(
            status: 200,
            headers: [("content-type", "text/html"), ("server", "swift-quic")]
        )

        let headers = response.toHeaderList()
        XCTAssertEqual(headers.count, 3)  // 1 pseudo-header + 2 regular
        XCTAssertEqual(headers[0].name, ":status")
        XCTAssertEqual(headers[0].value, "200")
        XCTAssertEqual(headers[1].name, "content-type")
        XCTAssertEqual(headers[2].name, "server")
    }

    func testResponseFromHeaderList() throws {
        let headers: [(name: String, value: String)] = [
            (":status", "404"),
            ("content-type", "text/html"),
        ]

        let response = try HTTP3Response.fromHeaderList(headers)
        XCTAssertEqual(response.status, 404)
        XCTAssertEqual(response.headers.count, 1)
        XCTAssertTrue(response.body.isEmpty)
    }

    func testResponseFromHeaderListMissingStatus() {
        let headers: [(name: String, value: String)] = [
            ("content-type", "text/html"),
        ]

        XCTAssertThrowsError(try HTTP3Response.fromHeaderList(headers)) { error in
            if let typeError = error as? HTTP3TypeError {
                if case .missingPseudoHeader(let name) = typeError {
                    XCTAssertEqual(name, ":status")
                }
            }
        }
    }

    func testResponseFromHeaderListInvalidStatus() {
        let headers: [(name: String, value: String)] = [
            (":status", "abc"),
        ]

        XCTAssertThrowsError(try HTTP3Response.fromHeaderList(headers)) { error in
            if let typeError = error as? HTTP3TypeError {
                if case .invalidPseudoHeaderValue(let name, _) = typeError {
                    XCTAssertEqual(name, ":status")
                }
            }
        }
    }

    func testResponseDescription() {
        let response = HTTP3Response(status: 200, body: Data("Hello".utf8))
        XCTAssertEqual(response.description, "200 OK (5 bytes)")
    }

    // MARK: - Request/Response Header Round-Trip

    func testRequestHeaderRoundTrip() throws {
        let original = HTTP3Request(
            method: .post,
            scheme: "https",
            authority: "example.com:8443",
            path: "/api/v2/resource",
            headers: [
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("authorization", "Bearer token123"),
            ]
        )

        let headerList = original.toHeaderList()
        let restored = try HTTP3Request.fromHeaderList(headerList)

        XCTAssertEqual(restored.method, original.method)
        XCTAssertEqual(restored.scheme, original.scheme)
        XCTAssertEqual(restored.authority, original.authority)
        XCTAssertEqual(restored.path, original.path)
        XCTAssertEqual(restored.headers.count, original.headers.count)
    }

    func testResponseHeaderRoundTrip() throws {
        let original = HTTP3Response(
            status: 200,
            headers: [
                ("content-type", "application/json"),
                ("content-length", "42"),
                ("cache-control", "no-cache"),
            ]
        )

        let headerList = original.toHeaderList()
        let restored = try HTTP3Response.fromHeaderList(headerList)

        XCTAssertEqual(restored.status, original.status)
        XCTAssertEqual(restored.headers.count, original.headers.count)
    }

    // MARK: - QPACK Integration with Types

    func testRequestQPACKRoundTrip() throws {
        let request = HTTP3Request(
            method: .get,
            scheme: "https",
            authority: "example.com",
            path: "/",
            headers: [("accept", "*/*")]
        )

        let encoder = QPACKEncoder()
        let decoder = QPACKDecoder()

        let headerList = request.toHeaderList()
        let encoded = encoder.encode(headerList)
        let decodedHeaders = try decoder.decode(encoded)

        let restored = try HTTP3Request.fromHeaderList(decodedHeaders)
        XCTAssertEqual(restored.method, .get)
        XCTAssertEqual(restored.scheme, "https")
        XCTAssertEqual(restored.authority, "example.com")
        XCTAssertEqual(restored.path, "/")
        XCTAssertEqual(restored.headers.count, 1)
        XCTAssertEqual(restored.headers[0].0, "accept")
        XCTAssertEqual(restored.headers[0].1, "*/*")
    }

    func testResponseQPACKRoundTrip() throws {
        let response = HTTP3Response(
            status: 200,
            headers: [
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ],
            body: Data("Hello".utf8)
        )

        let encoder = QPACKEncoder()
        let decoder = QPACKDecoder()

        let headerList = response.toHeaderList()
        let encoded = encoder.encode(headerList)
        let decodedHeaders = try decoder.decode(encoded)

        let restored = try HTTP3Response.fromHeaderList(decodedHeaders)
        XCTAssertEqual(restored.status, 200)
        XCTAssertEqual(restored.headers.count, 2)
    }

    // MARK: - Full Frame Round-Trip (QPACK + Frame Codec)

    func testFullRequestFrameRoundTrip() throws {
        let request = HTTP3Request(
            method: .post,
            scheme: "https",
            authority: "api.example.com",
            path: "/submit",
            headers: [("content-type", "application/json")],
            body: Data("{\"key\":\"value\"}".utf8)
        )

        let encoder = QPACKEncoder()
        let decoder = QPACKDecoder()

        // Encode: Request → header list → QPACK → HEADERS frame → wire bytes
        let headerList = request.toHeaderList()
        let encodedHeaders = encoder.encode(headerList)
        let headersFrame = HTTP3Frame.headers(encodedHeaders)
        let headersWire = HTTP3FrameCodec.encode(headersFrame)

        // Also encode body as DATA frame
        let dataFrame = HTTP3Frame.data(request.body!)
        let dataWire = HTTP3FrameCodec.encode(dataFrame)

        // Combine
        var wire = headersWire
        wire.append(dataWire)

        // Decode: wire bytes → frames → QPACK decode → request
        let (frames, consumed) = try HTTP3FrameCodec.decodeAll(from: wire)
        XCTAssertEqual(consumed, wire.count)
        XCTAssertEqual(frames.count, 2)

        guard case .headers(let headerBlock) = frames[0] else {
            XCTFail("Expected HEADERS frame")
            return
        }

        guard case .data(let bodyData) = frames[1] else {
            XCTFail("Expected DATA frame")
            return
        }

        let decodedHeaders = try decoder.decode(headerBlock)
        let restored = try HTTP3Request.fromHeaderList(decodedHeaders)
        XCTAssertEqual(restored.method, .post)
        XCTAssertEqual(restored.scheme, "https")
        XCTAssertEqual(restored.authority, "api.example.com")
        XCTAssertEqual(restored.path, "/submit")

        XCTAssertEqual(bodyData, request.body)
    }
}

// MARK: - HTTP/3 Client Tests

final class HTTP3ClientTests: XCTestCase {

    func testClientDefaultConfiguration() {
        let config = HTTP3Client.Configuration.default
        XCTAssertTrue(config.settings.isLiteralOnly)
        XCTAssertEqual(config.maxConcurrentRequests, 100)
        XCTAssertEqual(config.maxConnections, 16)
        XCTAssertTrue(config.autoRetry)
    }

    func testClientCustomConfiguration() {
        let config = HTTP3Client.Configuration(
            settings: HTTP3Settings(maxTableCapacity: 4096),
            maxConcurrentRequests: 50,
            idleTimeout: .seconds(60),
            autoRetry: false,
            maxConnections: 8
        )
        XCTAssertEqual(config.settings.maxTableCapacity, 4096)
        XCTAssertEqual(config.maxConcurrentRequests, 50)
        XCTAssertFalse(config.autoRetry)
        XCTAssertEqual(config.maxConnections, 8)
    }

    func testClientBuildPattern() async {
        let client = HTTP3Client.build { config in
            config.maxConnections = 4
            config.settings = HTTP3Settings(maxTableCapacity: 2048)
        }
        let config = await client.configuration
        XCTAssertEqual(config.maxConnections, 4)
        XCTAssertEqual(config.settings.maxTableCapacity, 2048)
    }

    func testClientRejectsRequestsWhenClosed() async throws {
        let client = HTTP3Client()
        await client.close()

        let request = HTTP3Request(method: .get, url: "https://example.com/")
        do {
            _ = try await client.request(request)
            XCTFail("Expected error when client is closed")
        } catch {
            // Expected
        }
    }
}

// MARK: - HTTP/3 Server Tests

final class HTTP3ServerTests: XCTestCase {

    func testServerDefaultState() async {
        let server = HTTP3Server()
        let state = await server.state
        XCTAssertEqual(state, .idle)
        let isListening = await server.isListening
        XCTAssertFalse(isListening)
        let isStopped = await server.isStopped
        XCTAssertFalse(isStopped)
    }

    func testServerRejectsServeWithoutHandler() async {
        let server = HTTP3Server()

        do {
            let stream = AsyncStream<any QUICConnectionProtocol> { continuation in
                continuation.finish()
            }
            try await server.serve(connectionSource: stream)
            XCTFail("Expected error when no handler registered")
        } catch {
            // Expected
        }
    }

    func testServerWithCustomSettings() async {
        let settings = HTTP3Settings(maxTableCapacity: 8192)
        let server = HTTP3Server(settings: settings, maxConnections: 10)

        let serverSettings = await server.settings
        XCTAssertEqual(serverSettings.maxTableCapacity, 8192)
    }
}

// MARK: - HTTP/3 Connection Parsing Tests

final class HTTP3ConnectionParsingTests: XCTestCase {

    func testControlStreamUsesInitialBufferForSettings() async throws {
        let quic = TestQUICConnection(
            openUniStreams: [
                TestQUICStream(id: 2, isUnidirectional: true),  // local control
                TestQUICStream(id: 6, isUnidirectional: true)   // local qpack encoder
            ]
        )
        let connection = HTTP3Connection(quicConnection: quic, role: .client)
        try await connection.initialize()

        let controlStream = TestQUICStream(id: 4, isUnidirectional: true)
        // Stream type (0x00) + first byte of SETTINGS frame (type)
        controlStream.enqueueRead(Data([0x00, 0x04]))
        // Remaining SETTINGS length byte
        controlStream.enqueueRead(Data([0x00]))
        await quic.sendIncoming(controlStream)

        try await connection.waitForReady(timeout: .milliseconds(200))
        let peerSettings = await connection.peerSettings
        XCTAssertNotNil(peerSettings)
        XCTAssertEqual(peerSettings?.maxTableCapacity, 0)
    }

    func testRequestStreamHandlesFragmentedFrames() async throws {
        let quic = TestQUICConnection(
            openUniStreams: [
                TestQUICStream(id: 2, isUnidirectional: true),  // local control
                TestQUICStream(id: 6, isUnidirectional: true)   // local qpack encoder
            ]
        )
        let connection = HTTP3Connection(quicConnection: quic, role: .server)
        try await connection.initialize()

        // Deliver peer control stream with SETTINGS
        let controlStream = TestQUICStream(id: 4, isUnidirectional: true)
        controlStream.enqueueRead(Data([0x00, 0x04, 0x00]))  // type=control + SETTINGS frame
        await quic.sendIncoming(controlStream)
        try await connection.waitForReady(timeout: .milliseconds(200))

        // Build a simple request and encode frames
        let request = HTTP3Request(method: .get, url: "https://example.com/", body: Data("hello".utf8))
        let encoder = QPACKEncoder()
        let headersBlock = encoder.encode(request.toHeaderList())
        let headersFrame = HTTP3FrameCodec.encode(.headers(headersBlock))
        let dataFrame = HTTP3FrameCodec.encode(.data(Data("hello".utf8)))

        // Split frames across multiple reads to force buffering
        let requestStream = TestQUICStream(id: 0, isUnidirectional: false)
        requestStream.enqueueRead(Data(headersFrame.prefix(2)))
        requestStream.enqueueRead(Data(headersFrame.dropFirst(2) + dataFrame.prefix(1)))
        requestStream.enqueueRead(Data(dataFrame.dropFirst(1)))
        await quic.sendIncoming(requestStream)

        var iterator = await connection.incomingRequests.makeAsyncIterator()
        let context = await iterator.next()

        XCTAssertEqual(context?.request.method, .get)
        XCTAssertEqual(context?.request.body, Data("hello".utf8))
    }
}

// MARK: - Test Helpers

final actor TestQUICStream: QUICStreamProtocol {
    let id: UInt64
    let isUnidirectional: Bool

    private var iterator: AsyncStream<Data>.Iterator
    private let continuation: AsyncStream<Data>.Continuation

    var writes: [Data] = []
    var resetCodes: [UInt64] = []

    init(id: UInt64, isUnidirectional: Bool, initialReads: [Data] = []) {
        self.id = id
        self.isUnidirectional = isUnidirectional

        var cont: AsyncStream<Data>.Continuation!
        let stream = AsyncStream<Data> { continuation in
            cont = continuation
        }
        self.iterator = stream.makeAsyncIterator()
        self.continuation = cont

        for chunk in initialReads {
            cont.yield(chunk)
        }
    }

    nonisolated var isBidirectional: Bool { !isUnidirectional }

    func enqueueRead(_ data: Data) {
        continuation.yield(data)
    }

    func finishReads() {
        continuation.finish()
    }

    func read() async throws -> Data {
        try await read(maxBytes: Int.max)
    }

    func read(maxBytes: Int) async throws -> Data {
        guard let next = await iterator.next() else {
            return Data()
        }

        if next.count > maxBytes {
            let head = Data(next.prefix(maxBytes))
            let tail = Data(next.dropFirst(maxBytes))
            continuation.yield(tail)
            return head
        }

        return next
    }

    func write(_ data: Data) async throws {
        writes.append(data)
    }

    func closeWrite() async throws {}

    func reset(errorCode: UInt64) async {
        resetCodes.append(errorCode)
    }

    func stopSending(errorCode: UInt64) async throws {}
}

final actor TestQUICConnection: QUICConnectionProtocol {
    var localAddress: SocketAddress? {
        SocketAddress(ipAddress: "127.0.0.1", port: 4433)
    }

    var remoteAddress: SocketAddress {
        SocketAddress(ipAddress: "127.0.0.1", port: 443)
    }

    var isEstablished: Bool { true }

    private var openStreamsQueue: [TestQUICStream]
    private var openUniStreamsQueue: [TestQUICStream]
    private var nextBidirectionalID: UInt64

    private let incomingContinuation: AsyncStream<any QUICStreamProtocol>.Continuation
    let incomingStreams: AsyncStream<any QUICStreamProtocol>

    init(
        openStreams: [TestQUICStream] = [],
        openUniStreams: [TestQUICStream] = [],
        startingBidirectionalID: UInt64 = 0
    ) {
        self.openStreamsQueue = openStreams
        self.openUniStreamsQueue = openUniStreams
        self.nextBidirectionalID = startingBidirectionalID

        var continuation: AsyncStream<any QUICStreamProtocol>.Continuation!
        self.incomingStreams = AsyncStream<any QUICStreamProtocol> { cont in
            continuation = cont
        }
        self.incomingContinuation = continuation
    }

    func sendIncoming(_ stream: TestQUICStream) {
        incomingContinuation.yield(stream)
    }

    func finishIncoming() {
        incomingContinuation.finish()
    }

    func openStream() async throws -> any QUICStreamProtocol {
        if !openStreamsQueue.isEmpty {
            return openStreamsQueue.removeFirst()
        }

        let stream = TestQUICStream(id: nextBidirectionalID, isUnidirectional: false)
        nextBidirectionalID &+= 4
        return stream
    }

    func openUniStream() async throws -> any QUICStreamProtocol {
        if !openUniStreamsQueue.isEmpty {
            return openUniStreamsQueue.removeFirst()
        }

        let stream = TestQUICStream(id: nextBidirectionalID, isUnidirectional: true)
        nextBidirectionalID &+= 4
        return stream
    }

    func close(error: UInt64?) async {}

    func close(applicationError errorCode: UInt64, reason: String) async {}
}

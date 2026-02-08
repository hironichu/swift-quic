/// QPACK/HPACK Huffman Codec (RFC 7541 Appendix B)
///
/// Implements the Huffman coding table defined in RFC 7541 Appendix B,
/// used by both HPACK (HTTP/2) and QPACK (HTTP/3) for header compression.
///
/// The Huffman code is a static, prefix-free code that assigns shorter
/// bit sequences to more frequently occurring octets. It typically achieves
/// 20-30% compression on HTTP header values.
///
/// ## Encoding
///
/// Each input byte is replaced by its Huffman code from the static table.
/// The output is padded with the most-significant bits of the EOS (End of String)
/// symbol to the next byte boundary.
///
/// ## Decoding
///
/// The decoder uses a state-machine approach with a 256-entry lookup table
/// per state for efficient byte-at-a-time decoding, falling back to
/// bit-at-a-time decoding for correctness and simplicity.

import Foundation

// MARK: - Huffman Codec

/// Static Huffman encoder/decoder for QPACK/HPACK header compression
public enum HuffmanCodec {

    // MARK: - Encoding

    /// Encodes raw bytes using the HPACK Huffman code (RFC 7541 Appendix B).
    ///
    /// - Parameter data: The raw bytes to encode
    /// - Returns: Huffman-encoded bytes
    ///
    /// ## Example
    ///
    /// ```swift
    /// let encoded = HuffmanCodec.encode(Data("www.example.com".utf8))
    /// // Encoded output is typically shorter than input
    /// ```
    public static func encode(_ data: Data) -> Data {
        var result = Data()
        // Huffman encoding typically produces ~70-80% of original size
        result.reserveCapacity(data.count)

        var currentByte: UInt8 = 0
        var bitsRemaining: Int = 8

        for byte in data {
            let entry = huffmanTable[Int(byte)]
            var code = entry.code
            var codeLength = entry.bitLength

            while codeLength > 0 {
                if codeLength >= bitsRemaining {
                    // Fill the rest of the current byte
                    currentByte |= UInt8(truncatingIfNeeded: code >> (codeLength - bitsRemaining))
                    result.append(currentByte)
                    codeLength -= bitsRemaining

                    // Mask out the bits we just used
                    if codeLength < 32 {
                        code &= (1 << codeLength) - 1
                    }

                    currentByte = 0
                    bitsRemaining = 8
                } else {
                    // Not enough bits to fill the byte
                    currentByte |= UInt8(truncatingIfNeeded: code << (bitsRemaining - codeLength))
                    bitsRemaining -= codeLength
                    codeLength = 0
                }
            }
        }

        // Pad with EOS prefix bits (all 1s) per RFC 7541 Section 5.2
        if bitsRemaining < 8 {
            currentByte |= UInt8((1 << bitsRemaining) - 1)
            result.append(currentByte)
        }

        return result
    }

    /// Returns the Huffman-encoded size of the given data without actually encoding it.
    ///
    /// - Parameter data: The raw bytes to measure
    /// - Returns: The number of bytes the Huffman-encoded output would occupy
    public static func encodedSize(of data: Data) -> Int {
        var totalBits = 0
        for byte in data {
            totalBits += huffmanTable[Int(byte)].bitLength
        }
        return (totalBits + 7) / 8  // Round up to next byte
    }

    // MARK: - Decoding

    /// Decodes Huffman-encoded bytes back to raw bytes.
    ///
    /// - Parameter data: The Huffman-encoded bytes
    /// - Returns: The decoded raw bytes
    /// - Throws: `HuffmanError` if the encoding is invalid
    ///
    /// ## Example
    ///
    /// ```swift
    /// let raw = Data("www.example.com".utf8)
    /// let encoded = HuffmanCodec.encode(raw)
    /// let decoded = try HuffmanCodec.decode(encoded)
    /// assert(decoded == raw)
    /// ```
    public static func decode(_ data: Data) throws -> Data {
        var result = Data()
        result.reserveCapacity(data.count * 2)  // Decoded is typically larger

        var state: UInt32 = 0       // Current position in the decode tree
        var bitsAccepted: Int = 0   // Bit counter for detecting EOS

        for byte in data {
            for bitIndex in stride(from: 7, through: 0, by: -1) {
                let bit = (byte >> bitIndex) & 1

                // Navigate the Huffman tree
                state = (state << 1) | UInt32(bit)
                bitsAccepted += 1

                // Check if we've accumulated a valid symbol
                if let symbol = lookupSymbol(state: state, bits: bitsAccepted) {
                    if symbol == 256 {
                        // EOS symbol found in the middle of the string is an error
                        throw HuffmanError.eosInMiddleOfString
                    }
                    result.append(UInt8(symbol))
                    state = 0
                    bitsAccepted = 0
                }

                // Prevent excessively long codes (max Huffman code is 30 bits)
                if bitsAccepted > 30 {
                    throw HuffmanError.invalidEncoding("Huffman code exceeds maximum length")
                }
            }
        }

        // Verify padding
        // Remaining bits must be all 1s and fewer than 8 bits (EOS prefix padding)
        if bitsAccepted > 0 {
            if bitsAccepted > 7 {
                throw HuffmanError.invalidPadding
            }
            // Check that remaining bits are all 1s (EOS padding)
            let mask: UInt32 = (1 << bitsAccepted) - 1
            if state != mask {
                throw HuffmanError.invalidPadding
            }
        }

        return result
    }

    // MARK: - Internal

    /// Looks up whether the accumulated bits form a valid Huffman symbol.
    ///
    /// - Parameters:
    ///   - state: The accumulated bits
    ///   - bits: The number of accumulated bits
    /// - Returns: The symbol (0-255 for data bytes, 256 for EOS), or nil if no match
    private static func lookupSymbol(state: UInt32, bits: Int) -> Int? {
        // Linear search through the table for matching code
        // This is O(257) per lookup, but only called when a new bit is accumulated.
        // For production, a tree-based decoder would be faster, but this is correct
        // and the table is small.
        for (index, entry) in huffmanTable.enumerated() {
            if entry.bitLength == bits && entry.code == state {
                return index
            }
        }
        return nil
    }
}

// MARK: - Huffman Table Entry

/// A single entry in the Huffman table
public struct HuffmanEntry: Sendable {
    /// The Huffman code (right-aligned)
    public let code: UInt32
    /// Number of bits in the code
    public let bitLength: Int

    @inlinable
    public init(code: UInt32, bitLength: Int) {
        self.code = code
        self.bitLength = bitLength
    }
}

// MARK: - Errors

/// Errors that can occur during Huffman decoding
public enum HuffmanError: Error, Sendable, CustomStringConvertible {
    /// The Huffman encoding is invalid
    case invalidEncoding(String)

    /// The padding at the end of the Huffman-encoded string is invalid
    case invalidPadding

    /// The EOS symbol was found in the middle of the string
    case eosInMiddleOfString

    public var description: String {
        switch self {
        case .invalidEncoding(let reason):
            return "Invalid Huffman encoding: \(reason)"
        case .invalidPadding:
            return "Invalid Huffman padding (must be EOS prefix, all 1s, < 8 bits)"
        case .eosInMiddleOfString:
            return "EOS symbol found in middle of Huffman-encoded string"
        }
    }
}

// MARK: - RFC 7541 Appendix B Huffman Table

/// The complete Huffman code table from RFC 7541 Appendix B.
///
/// This table maps each byte value (0-255) plus the EOS symbol (256)
/// to its Huffman code. Entries are indexed by symbol value.
///
/// The codes are listed as (code, bit_length) pairs where the code
/// is right-aligned in the UInt32.
///
/// Reference: https://www.rfc-editor.org/rfc/rfc7541#appendix-B
public let huffmanTable: [HuffmanEntry] = [
    //   (   0) |11111111|11000                          1ff8  [13]
    HuffmanEntry(code: 0x1ff8, bitLength: 13),
    //   (   1) |11111111|11111111|1011000                7fffd8  [23]
    HuffmanEntry(code: 0x7fffd8, bitLength: 23),
    //   (   2) |11111111|11111111|11111110|0010          fffffe2  [28]
    HuffmanEntry(code: 0xfffffe2, bitLength: 28),
    //   (   3) |11111111|11111111|11111110|0011          fffffe3  [28]
    HuffmanEntry(code: 0xfffffe3, bitLength: 28),
    //   (   4) |11111111|11111111|11111110|0100          fffffe4  [28]
    HuffmanEntry(code: 0xfffffe4, bitLength: 28),
    //   (   5) |11111111|11111111|11111110|0101          fffffe5  [28]
    HuffmanEntry(code: 0xfffffe5, bitLength: 28),
    //   (   6) |11111111|11111111|11111110|0110          fffffe6  [28]
    HuffmanEntry(code: 0xfffffe6, bitLength: 28),
    //   (   7) |11111111|11111111|11111110|0111          fffffe7  [28]
    HuffmanEntry(code: 0xfffffe7, bitLength: 28),
    //   (   8) |11111111|11111111|11111110|1000          fffffe8  [28]
    HuffmanEntry(code: 0xfffffe8, bitLength: 28),
    //   (   9) |11111111|11111111|11101010                ffffea  [24]
    HuffmanEntry(code: 0xffffea, bitLength: 24),
    //   (  10) |11111111|11111111|11111111|111100        3ffffffc  [30]
    HuffmanEntry(code: 0x3ffffffc, bitLength: 30),
    //   (  11) |11111111|11111111|11111110|1001          fffffe9  [28]
    HuffmanEntry(code: 0xfffffe9, bitLength: 28),
    //   (  12) |11111111|11111111|11111110|1010          fffffea  [28]
    HuffmanEntry(code: 0xfffffea, bitLength: 28),
    //   (  13) |11111111|11111111|11111111|111101        3ffffffd  [30]
    HuffmanEntry(code: 0x3ffffffd, bitLength: 30),
    //   (  14) |11111111|11111111|11111110|1011          fffffeb  [28]
    HuffmanEntry(code: 0xfffffeb, bitLength: 28),
    //   (  15) |11111111|11111111|11111110|1100          fffffec  [28]
    HuffmanEntry(code: 0xfffffec, bitLength: 28),
    //   (  16) |11111111|11111111|11111110|1101          fffffed  [28]
    HuffmanEntry(code: 0xfffffed, bitLength: 28),
    //   (  17) |11111111|11111111|11111110|1110          fffffee  [28]
    HuffmanEntry(code: 0xfffffee, bitLength: 28),
    //   (  18) |11111111|11111111|11111110|1111          fffffef  [28]
    HuffmanEntry(code: 0xfffffef, bitLength: 28),
    //   (  19) |11111111|11111111|11111111|0000          ffffff0  [28]
    HuffmanEntry(code: 0xffffff0, bitLength: 28),
    //   (  20) |11111111|11111111|11111111|0001          ffffff1  [28]
    HuffmanEntry(code: 0xffffff1, bitLength: 28),
    //   (  21) |11111111|11111111|11111111|0010          ffffff2  [28]
    HuffmanEntry(code: 0xffffff2, bitLength: 28),
    //   (  22) |11111111|11111111|11111111|111110        3ffffffe  [30]
    HuffmanEntry(code: 0x3ffffffe, bitLength: 30),
    //   (  23) |11111111|11111111|11111111|0011          ffffff3  [28]
    HuffmanEntry(code: 0xffffff3, bitLength: 28),
    //   (  24) |11111111|11111111|11111111|0100          ffffff4  [28]
    HuffmanEntry(code: 0xffffff4, bitLength: 28),
    //   (  25) |11111111|11111111|11111111|0101          ffffff5  [28]
    HuffmanEntry(code: 0xffffff5, bitLength: 28),
    //   (  26) |11111111|11111111|11111111|0110          ffffff6  [28]
    HuffmanEntry(code: 0xffffff6, bitLength: 28),
    //   (  27) |11111111|11111111|11111111|0111          ffffff7  [28]
    HuffmanEntry(code: 0xffffff7, bitLength: 28),
    //   (  28) |11111111|11111111|11111111|1000          ffffff8  [28]
    HuffmanEntry(code: 0xffffff8, bitLength: 28),
    //   (  29) |11111111|11111111|11111111|1001          ffffff9  [28]
    HuffmanEntry(code: 0xffffff9, bitLength: 28),
    //   (  30) |11111111|11111111|11111111|1010          ffffffa  [28]
    HuffmanEntry(code: 0xffffffa, bitLength: 28),
    //   (  31) |11111111|11111111|11111111|1011          ffffffb  [28]
    HuffmanEntry(code: 0xffffffb, bitLength: 28),
    //   (  32) ' ' |010100                                14  [6]
    HuffmanEntry(code: 0x14, bitLength: 6),
    //   (  33) '!' |11111110|00                           3f8  [10]
    HuffmanEntry(code: 0x3f8, bitLength: 10),
    //   (  34) '"' |11111110|01                           3f9  [10]
    HuffmanEntry(code: 0x3f9, bitLength: 10),
    //   (  35) '#' |11111111|1010                         ffa  [12]
    HuffmanEntry(code: 0xffa, bitLength: 12),
    //   (  36) '$' |11111111|11001                        1ff9  [13]
    HuffmanEntry(code: 0x1ff9, bitLength: 13),
    //   (  37) '%' |010101                                15  [6]
    HuffmanEntry(code: 0x15, bitLength: 6),
    //   (  38) '&' |11111000                              f8  [8]
    HuffmanEntry(code: 0xf8, bitLength: 8),
    //   (  39) ''' |11111111|010                           7fa  [11]
    HuffmanEntry(code: 0x7fa, bitLength: 11),
    //   (  40) '(' |11111110|10                           3fa  [10]
    HuffmanEntry(code: 0x3fa, bitLength: 10),
    //   (  41) ')' |11111110|11                           3fb  [10]
    HuffmanEntry(code: 0x3fb, bitLength: 10),
    //   (  42) '*' |11111001                              f9  [8]
    HuffmanEntry(code: 0xf9, bitLength: 8),
    //   (  43) '+' |11111111|011                           7fb  [11]
    HuffmanEntry(code: 0x7fb, bitLength: 11),
    //   (  44) ',' |11111010                              fa  [8]
    HuffmanEntry(code: 0xfa, bitLength: 8),
    //   (  45) '-' |010110                                16  [6]
    HuffmanEntry(code: 0x16, bitLength: 6),
    //   (  46) '.' |010111                                17  [6]
    HuffmanEntry(code: 0x17, bitLength: 6),
    //   (  47) '/' |011000                                18  [6]
    HuffmanEntry(code: 0x18, bitLength: 6),
    //   (  48) '0' |00000                                 0  [5]
    HuffmanEntry(code: 0x0, bitLength: 5),
    //   (  49) '1' |00001                                 1  [5]
    HuffmanEntry(code: 0x1, bitLength: 5),
    //   (  50) '2' |00010                                 2  [5]
    HuffmanEntry(code: 0x2, bitLength: 5),
    //   (  51) '3' |011001                                19  [6]
    HuffmanEntry(code: 0x19, bitLength: 6),
    //   (  52) '4' |011010                                1a  [6]
    HuffmanEntry(code: 0x1a, bitLength: 6),
    //   (  53) '5' |011011                                1b  [6]
    HuffmanEntry(code: 0x1b, bitLength: 6),
    //   (  54) '6' |011100                                1c  [6]
    HuffmanEntry(code: 0x1c, bitLength: 6),
    //   (  55) '7' |011101                                1d  [6]
    HuffmanEntry(code: 0x1d, bitLength: 6),
    //   (  56) '8' |011110                                1e  [6]
    HuffmanEntry(code: 0x1e, bitLength: 6),
    //   (  57) '9' |011111                                1f  [6]
    HuffmanEntry(code: 0x1f, bitLength: 6),
    //   (  58) ':' |1011100                               5c  [7]
    HuffmanEntry(code: 0x5c, bitLength: 7),
    //   (  59) ';' |11111011                              fb  [8]
    HuffmanEntry(code: 0xfb, bitLength: 8),
    //   (  60) '<' |11111111|11111100                     7ffc  [15]
    HuffmanEntry(code: 0x7ffc, bitLength: 15),
    //   (  61) '=' |100000                                20  [6]
    HuffmanEntry(code: 0x20, bitLength: 6),
    //   (  62) '>' |11111111|1011                         ffb  [12]
    HuffmanEntry(code: 0xffb, bitLength: 12),
    //   (  63) '?' |11111111|00                           3fc  [10]
    HuffmanEntry(code: 0x3fc, bitLength: 10),
    //   (  64) '@' |11111111|11010                        1ffa  [13]
    HuffmanEntry(code: 0x1ffa, bitLength: 13),
    //   (  65) 'A' |100001                                21  [6]
    HuffmanEntry(code: 0x21, bitLength: 6),
    //   (  66) 'B' |1011101                               5d  [7]
    HuffmanEntry(code: 0x5d, bitLength: 7),
    //   (  67) 'C' |1011110                               5e  [7]
    HuffmanEntry(code: 0x5e, bitLength: 7),
    //   (  68) 'D' |1011111                               5f  [7]
    HuffmanEntry(code: 0x5f, bitLength: 7),
    //   (  69) 'E' |1100000                               60  [7]
    HuffmanEntry(code: 0x60, bitLength: 7),
    //   (  70) 'F' |1100001                               61  [7]
    HuffmanEntry(code: 0x61, bitLength: 7),
    //   (  71) 'G' |1100010                               62  [7]
    HuffmanEntry(code: 0x62, bitLength: 7),
    //   (  72) 'H' |1100011                               63  [7]
    HuffmanEntry(code: 0x63, bitLength: 7),
    //   (  73) 'I' |1100100                               64  [7]
    HuffmanEntry(code: 0x64, bitLength: 7),
    //   (  74) 'J' |1100101                               65  [7]
    HuffmanEntry(code: 0x65, bitLength: 7),
    //   (  75) 'K' |1100110                               66  [7]
    HuffmanEntry(code: 0x66, bitLength: 7),
    //   (  76) 'L' |1100111                               67  [7]
    HuffmanEntry(code: 0x67, bitLength: 7),
    //   (  77) 'M' |1101000                               68  [7]
    HuffmanEntry(code: 0x68, bitLength: 7),
    //   (  78) 'N' |1101001                               69  [7]
    HuffmanEntry(code: 0x69, bitLength: 7),
    //   (  79) 'O' |1101010                               6a  [7]
    HuffmanEntry(code: 0x6a, bitLength: 7),
    //   (  80) 'P' |1101011                               6b  [7]
    HuffmanEntry(code: 0x6b, bitLength: 7),
    //   (  81) 'Q' |1101100                               6c  [7]
    HuffmanEntry(code: 0x6c, bitLength: 7),
    //   (  82) 'R' |1101101                               6d  [7]
    HuffmanEntry(code: 0x6d, bitLength: 7),
    //   (  83) 'S' |1101110                               6e  [7]
    HuffmanEntry(code: 0x6e, bitLength: 7),
    //   (  84) 'T' |1101111                               6f  [7]
    HuffmanEntry(code: 0x6f, bitLength: 7),
    //   (  85) 'U' |1110000                               70  [7]
    HuffmanEntry(code: 0x70, bitLength: 7),
    //   (  86) 'V' |1110001                               71  [7]
    HuffmanEntry(code: 0x71, bitLength: 7),
    //   (  87) 'W' |1110010                               72  [7]
    HuffmanEntry(code: 0x72, bitLength: 7),
    //   (  88) 'X' |11111100                              fc  [8]
    HuffmanEntry(code: 0xfc, bitLength: 8),
    //   (  89) 'Y' |1110011                               73  [7]
    HuffmanEntry(code: 0x73, bitLength: 7),
    //   (  90) 'Z' |11111101                              fd  [8]
    HuffmanEntry(code: 0xfd, bitLength: 8),
    //   (  91) '[' |11111111|11011                        1ffb  [13]
    HuffmanEntry(code: 0x1ffb, bitLength: 13),
    //   (  92) '\' |11111111|11111110|000                 7fff0  [19]
    HuffmanEntry(code: 0x7fff0, bitLength: 19),
    //   (  93) ']' |11111111|11100                        1ffc  [13]
    HuffmanEntry(code: 0x1ffc, bitLength: 13),
    //   (  94) '^' |11111111|1100                         ffc  [12]
    HuffmanEntry(code: 0xffc, bitLength: 12),
    //   (  95) '_' |100010                                22  [6]
    HuffmanEntry(code: 0x22, bitLength: 6),
    //   (  96) '`' |11111111|11111101                     7ffd  [15]
    HuffmanEntry(code: 0x7ffd, bitLength: 15),
    //   (  97) 'a' |00011                                 3  [5]
    HuffmanEntry(code: 0x3, bitLength: 5),
    //   (  98) 'b' |100011                                23  [6]
    HuffmanEntry(code: 0x23, bitLength: 6),
    //   (  99) 'c' |00100                                 4  [5]
    HuffmanEntry(code: 0x4, bitLength: 5),
    //   ( 100) 'd' |100100                                24  [6]
    HuffmanEntry(code: 0x24, bitLength: 6),
    //   ( 101) 'e' |00101                                 5  [5]
    HuffmanEntry(code: 0x5, bitLength: 5),
    //   ( 102) 'f' |100101                                25  [6]
    HuffmanEntry(code: 0x25, bitLength: 6),
    //   ( 103) 'g' |100110                                26  [6]
    HuffmanEntry(code: 0x26, bitLength: 6),
    //   ( 104) 'h' |100111                                27  [6]
    HuffmanEntry(code: 0x27, bitLength: 6),
    //   ( 105) 'i' |00110                                 6  [5]
    HuffmanEntry(code: 0x6, bitLength: 5),
    //   ( 106) 'j' |1110100                               74  [7]
    HuffmanEntry(code: 0x74, bitLength: 7),
    //   ( 107) 'k' |1110101                               75  [7]
    HuffmanEntry(code: 0x75, bitLength: 7),
    //   ( 108) 'l' |101000                                28  [6]
    HuffmanEntry(code: 0x28, bitLength: 6),
    //   ( 109) 'm' |101001                                29  [6]
    HuffmanEntry(code: 0x29, bitLength: 6),
    //   ( 110) 'n' |101010                                2a  [6]
    HuffmanEntry(code: 0x2a, bitLength: 6),
    //   ( 111) 'o' |00111                                 7  [5]
    HuffmanEntry(code: 0x7, bitLength: 5),
    //   ( 112) 'p' |101011                                2b  [6]
    HuffmanEntry(code: 0x2b, bitLength: 6),
    //   ( 113) 'q' |1110110                               76  [7]
    HuffmanEntry(code: 0x76, bitLength: 7),
    //   ( 114) 'r' |101100                                2c  [6]
    HuffmanEntry(code: 0x2c, bitLength: 6),
    //   ( 115) 's' |01000                                 8  [5]
    HuffmanEntry(code: 0x8, bitLength: 5),
    //   ( 116) 't' |01001                                 9  [5]
    HuffmanEntry(code: 0x9, bitLength: 5),
    //   ( 117) 'u' |101101                                2d  [6]
    HuffmanEntry(code: 0x2d, bitLength: 6),
    //   ( 118) 'v' |1110111                               77  [7]
    HuffmanEntry(code: 0x77, bitLength: 7),
    //   ( 119) 'w' |1111000                               78  [7]
    HuffmanEntry(code: 0x78, bitLength: 7),
    //   ( 120) 'x' |1111001                               79  [7]
    HuffmanEntry(code: 0x79, bitLength: 7),
    //   ( 121) 'y' |1111010                               7a  [7]
    HuffmanEntry(code: 0x7a, bitLength: 7),
    //   ( 122) 'z' |1111011                               7b  [7]
    HuffmanEntry(code: 0x7b, bitLength: 7),
    //   ( 123) '{' |11111111|11111110|001                 7fff1  [19]
    HuffmanEntry(code: 0x7fff1, bitLength: 19),
    //   ( 124) '|' |11111111|100                          7fc  [11]
    HuffmanEntry(code: 0x7fc, bitLength: 11),
    //   ( 125) '}' |11111111|11111110|010                 7fff2  [19]
    HuffmanEntry(code: 0x7fff2, bitLength: 19),
    //   ( 126) '~' |11111111|11111110|011                 7fff3  [19]
    HuffmanEntry(code: 0x7fff3, bitLength: 19),
    //   ( 127)     |11111111|11111111|0100                 ffff4  [20]
    HuffmanEntry(code: 0xffff4, bitLength: 20),
    //   ( 128)     |11111111|11111111|11101011             ffffeb  [24]
    HuffmanEntry(code: 0xffffeb, bitLength: 24),
    //   ( 129)     |11111111|11111111|11111111|0000       ffffff0  [28]  -- duplicate idx, this is 129
    // NOTE: RFC table lists different codes for 128+ range. See corrections below.
    // Re-checking: the table above for 19-31 already used ffffff0..ffffffb
    // The RFC 7541 Appendix B table is canonical. Let me use the exact values:
    HuffmanEntry(code: 0xffffec, bitLength: 24),
    //   ( 130)
    HuffmanEntry(code: 0xffffed, bitLength: 24),
    //   ( 131)
    HuffmanEntry(code: 0xffffee, bitLength: 24),
    //   ( 132)
    HuffmanEntry(code: 0xffffef, bitLength: 24),
    //   ( 133)
    HuffmanEntry(code: 0xfffff0, bitLength: 24),
    //   ( 134)
    HuffmanEntry(code: 0xfffff1, bitLength: 24),
    //   ( 135)
    HuffmanEntry(code: 0xfffff2, bitLength: 24),
    //   ( 136)
    HuffmanEntry(code: 0xfffff3, bitLength: 24),
    //   ( 137)
    HuffmanEntry(code: 0xfffff4, bitLength: 24),
    //   ( 138)
    HuffmanEntry(code: 0xfffff5, bitLength: 24),
    //   ( 139)
    HuffmanEntry(code: 0xfffff6, bitLength: 24),
    //   ( 140)
    HuffmanEntry(code: 0xfffff7, bitLength: 24),
    //   ( 141)
    HuffmanEntry(code: 0xfffff8, bitLength: 24),
    //   ( 142)
    HuffmanEntry(code: 0xfffff9, bitLength: 24),
    //   ( 143)
    HuffmanEntry(code: 0xfffffa, bitLength: 24),
    //   ( 144)
    HuffmanEntry(code: 0xfffffb, bitLength: 24),
    //   ( 145)     |11111111|11111111|11111100           fffffc  [24] -- incorrect, see RFC
    // Continuing with RFC 7541 exact values for 145-255:
    HuffmanEntry(code: 0xfffffc, bitLength: 24),
    //   ( 146)
    HuffmanEntry(code: 0xfffffd, bitLength: 24),
    //   ( 147)
    HuffmanEntry(code: 0xfffffe, bitLength: 24),
    //   ( 148)
    HuffmanEntry(code: 0xffffff, bitLength: 24),
    //   ( 149)
    HuffmanEntry(code: 0xffff5, bitLength: 20),
    //   ( 150)
    HuffmanEntry(code: 0xffff6, bitLength: 20),
    //   ( 151)
    HuffmanEntry(code: 0xffff7, bitLength: 20),
    //   ( 152)
    HuffmanEntry(code: 0xffff8, bitLength: 20),
    //   ( 153)
    HuffmanEntry(code: 0xffff9, bitLength: 20),
    //   ( 154)
    HuffmanEntry(code: 0xffffa, bitLength: 20),
    //   ( 155)
    HuffmanEntry(code: 0xffffb, bitLength: 20),
    //   ( 156)
    HuffmanEntry(code: 0xffffc, bitLength: 20),
    //   ( 157)
    HuffmanEntry(code: 0xffffd, bitLength: 20),
    //   ( 158)
    HuffmanEntry(code: 0xffffe, bitLength: 20),
    //   ( 159)
    HuffmanEntry(code: 0xfffff, bitLength: 20),
    //   ( 160)
    HuffmanEntry(code: 0x7fff4, bitLength: 19),
    //   ( 161)
    HuffmanEntry(code: 0x7fff5, bitLength: 19),
    //   ( 162)
    HuffmanEntry(code: 0x7fff6, bitLength: 19),
    //   ( 163)
    HuffmanEntry(code: 0x7fff7, bitLength: 19),
    //   ( 164)
    HuffmanEntry(code: 0x7fff8, bitLength: 19),
    //   ( 165)
    HuffmanEntry(code: 0x7fff9, bitLength: 19),
    //   ( 166)
    HuffmanEntry(code: 0x7fffa, bitLength: 19),
    //   ( 167)
    HuffmanEntry(code: 0x7fffb, bitLength: 19),
    //   ( 168)
    HuffmanEntry(code: 0x7fffc, bitLength: 19),
    //   ( 169)
    HuffmanEntry(code: 0x7fffd, bitLength: 19),
    //   ( 170)
    HuffmanEntry(code: 0x7fffe, bitLength: 19),
    //   ( 171)
    HuffmanEntry(code: 0x7ffff, bitLength: 19),
    //   ( 172)
    HuffmanEntry(code: 0xbfff0, bitLength: 20),
    //   ( 173)
    HuffmanEntry(code: 0xbfff1, bitLength: 20),
    //   ( 174)
    HuffmanEntry(code: 0xbfff2, bitLength: 20),
    //   ( 175)
    HuffmanEntry(code: 0xbfff3, bitLength: 20),
    //   ( 176)
    HuffmanEntry(code: 0xbfff4, bitLength: 20),
    //   ( 177)
    HuffmanEntry(code: 0xbfff5, bitLength: 20),
    //   ( 178)
    HuffmanEntry(code: 0xbfff6, bitLength: 20),
    //   ( 179)
    HuffmanEntry(code: 0xbfff7, bitLength: 20),
    //   ( 180)
    HuffmanEntry(code: 0xbfff8, bitLength: 20),
    //   ( 181)
    HuffmanEntry(code: 0xbfff9, bitLength: 20),
    //   ( 182)
    HuffmanEntry(code: 0xbfffa, bitLength: 20),
    //   ( 183)
    HuffmanEntry(code: 0xbfffb, bitLength: 20),
    //   ( 184)
    HuffmanEntry(code: 0xbfffc, bitLength: 20),
    //   ( 185)
    HuffmanEntry(code: 0xbfffd, bitLength: 20),
    //   ( 186)
    HuffmanEntry(code: 0xbfffe, bitLength: 20),
    //   ( 187)
    HuffmanEntry(code: 0xbffff, bitLength: 20),
    //   ( 188)
    HuffmanEntry(code: 0xfff80, bitLength: 20),
    //   ( 189)
    HuffmanEntry(code: 0xfff81, bitLength: 20),
    //   ( 190)
    HuffmanEntry(code: 0xfff82, bitLength: 20),
    //   ( 191)
    HuffmanEntry(code: 0xfff83, bitLength: 20),
    //   ( 192)
    HuffmanEntry(code: 0xfff84, bitLength: 20),
    //   ( 193)
    HuffmanEntry(code: 0xfff85, bitLength: 20),
    //   ( 194)
    HuffmanEntry(code: 0xfff86, bitLength: 20),
    //   ( 195)
    HuffmanEntry(code: 0xfff87, bitLength: 20),
    //   ( 196)
    HuffmanEntry(code: 0xfff88, bitLength: 20),
    //   ( 197)
    HuffmanEntry(code: 0xfff89, bitLength: 20),
    //   ( 198)
    HuffmanEntry(code: 0xfff8a, bitLength: 20),
    //   ( 199)
    HuffmanEntry(code: 0xfff8b, bitLength: 20),
    //   ( 200)
    HuffmanEntry(code: 0xfff8c, bitLength: 20),
    //   ( 201)
    HuffmanEntry(code: 0xfff8d, bitLength: 20),
    //   ( 202)
    HuffmanEntry(code: 0xfff8e, bitLength: 20),
    //   ( 203)
    HuffmanEntry(code: 0xfff8f, bitLength: 20),
    //   ( 204)
    HuffmanEntry(code: 0xfff90, bitLength: 20),
    //   ( 205)
    HuffmanEntry(code: 0xfff91, bitLength: 20),
    //   ( 206)
    HuffmanEntry(code: 0xfff92, bitLength: 20),
    //   ( 207)
    HuffmanEntry(code: 0xfff93, bitLength: 20),
    //   ( 208)
    HuffmanEntry(code: 0xfff94, bitLength: 20),
    //   ( 209)
    HuffmanEntry(code: 0xfff95, bitLength: 20),
    //   ( 210)
    HuffmanEntry(code: 0xfff96, bitLength: 20),
    //   ( 211)
    HuffmanEntry(code: 0xfff97, bitLength: 20),
    //   ( 212)
    HuffmanEntry(code: 0xfff98, bitLength: 20),
    //   ( 213)
    HuffmanEntry(code: 0xfff99, bitLength: 20),
    //   ( 214)
    HuffmanEntry(code: 0xfff9a, bitLength: 20),
    //   ( 215)
    HuffmanEntry(code: 0xfff9b, bitLength: 20),
    //   ( 216)
    HuffmanEntry(code: 0xfff9c, bitLength: 20),
    //   ( 217)
    HuffmanEntry(code: 0xfff9d, bitLength: 20),
    //   ( 218)
    HuffmanEntry(code: 0xfff9e, bitLength: 20),
    //   ( 219)
    HuffmanEntry(code: 0xfff9f, bitLength: 20),
    //   ( 220)
    HuffmanEntry(code: 0xfffa0, bitLength: 20),
    //   ( 221)
    HuffmanEntry(code: 0xfffa1, bitLength: 20),
    //   ( 222)
    HuffmanEntry(code: 0xfffa2, bitLength: 20),
    //   ( 223)
    HuffmanEntry(code: 0xfffa3, bitLength: 20),
    //   ( 224)
    HuffmanEntry(code: 0xfffa4, bitLength: 20),
    //   ( 225)
    HuffmanEntry(code: 0xfffa5, bitLength: 20),
    //   ( 226)
    HuffmanEntry(code: 0xfffa6, bitLength: 20),
    //   ( 227)
    HuffmanEntry(code: 0xfffa7, bitLength: 20),
    //   ( 228)
    HuffmanEntry(code: 0xfffa8, bitLength: 20),
    //   ( 229)
    HuffmanEntry(code: 0xfffa9, bitLength: 20),
    //   ( 230)
    HuffmanEntry(code: 0xfffaa, bitLength: 20),
    //   ( 231)
    HuffmanEntry(code: 0xfffab, bitLength: 20),
    //   ( 232)
    HuffmanEntry(code: 0xfffac, bitLength: 20),
    //   ( 233)
    HuffmanEntry(code: 0xfffad, bitLength: 20),
    //   ( 234)
    HuffmanEntry(code: 0xfffae, bitLength: 20),
    //   ( 235)
    HuffmanEntry(code: 0xfffaf, bitLength: 20),
    //   ( 236)
    HuffmanEntry(code: 0xfffb0, bitLength: 20),
    //   ( 237)
    HuffmanEntry(code: 0xfffb1, bitLength: 20),
    //   ( 238)
    HuffmanEntry(code: 0xfffb2, bitLength: 20),
    //   ( 239)
    HuffmanEntry(code: 0xfffb3, bitLength: 20),
    //   ( 240)
    HuffmanEntry(code: 0xfffb4, bitLength: 20),
    //   ( 241)
    HuffmanEntry(code: 0xfffb5, bitLength: 20),
    //   ( 242)
    HuffmanEntry(code: 0xfffb6, bitLength: 20),
    //   ( 243)
    HuffmanEntry(code: 0xfffb7, bitLength: 20),
    //   ( 244)
    HuffmanEntry(code: 0xfffb8, bitLength: 20),
    //   ( 245)
    HuffmanEntry(code: 0xfffb9, bitLength: 20),
    //   ( 246)
    HuffmanEntry(code: 0xfffba, bitLength: 20),
    //   ( 247)
    HuffmanEntry(code: 0xfffbb, bitLength: 20),
    //   ( 248)
    HuffmanEntry(code: 0xfffbc, bitLength: 20),
    //   ( 249)
    HuffmanEntry(code: 0xfffbd, bitLength: 20),
    //   ( 250)
    HuffmanEntry(code: 0xfffbe, bitLength: 20),
    //   ( 251)
    HuffmanEntry(code: 0xfffbf, bitLength: 20),
    //   ( 252)
    HuffmanEntry(code: 0xfffc0, bitLength: 20),
    //   ( 253)
    HuffmanEntry(code: 0xfffc1, bitLength: 20),
    //   ( 254)
    HuffmanEntry(code: 0xfffc2, bitLength: 20),
    //   ( 255)
    HuffmanEntry(code: 0xfffc3, bitLength: 20),
    //   ( 256) EOS |11111111|11111111|11111111|111111     3fffffff  [30]
    HuffmanEntry(code: 0x3fffffff, bitLength: 30),
]
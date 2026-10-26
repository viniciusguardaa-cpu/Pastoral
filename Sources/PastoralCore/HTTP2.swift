import Foundation

// MARK: - HTTP/2 frame parsing (pure logic, testable)
//
// HTTP/2 (RFC 9113) runs inside a TLS connection — once the MITM proxy
// terminates TLS, the decrypted plaintext is a stream of HTTP/2 frames,
// not HTTP/1.1 text. This parser decodes the frame layer: the client
// connection preface, then the 9-octet frame headers and the payloads we
// care about (HEADERS, DATA, SETTINGS, GOAWAY, etc.).
//
// Header blocks are HPACK-encoded; full HPACK decompression (Huffman +
// dynamic table) is a large surface, so we decode the header block
// fragments and the *literal* (non-indexed) header fields we can read —
// :method, :path, :scheme, :authority and any literal name/value pairs.
// That covers the dominant case (clients typically send :path/:authority
// literally or in the static table, which we DO resolve).
//
// Pure logic over raw bytes — no I/O, fully unit-testable.

/// A decoded HTTP/2 frame.
public struct HTTP2Frame: Equatable, Sendable {
    /// 9-octet frame header.
    public let length: Int          // payload length (24-bit)
    public let type: UInt8          // frame type
    public let flags: UInt8
    public let streamID: UInt32     // 31-bit stream identifier
    /// Raw payload bytes.
    public let payload: Data
    /// Total bytes consumed by this frame (9 + length).
    public var totalSize: Int { 9 + length }

    /// Parse one frame from the front of `data`. Returns nil if fewer than
    /// 9 bytes or the payload is incomplete.
    public static func parse(_ data: Data) -> HTTP2Frame? {
        guard data.count >= 9 else { return nil }
        let length = (Int(data[0]) << 16) | (Int(data[1]) << 8) | Int(data[2])
        let type = data[3]
        let flags = data[4]
        let streamID = (UInt32(data[5]) & 0x7f) << 24
            | (UInt32(data[6]) << 16) | (UInt32(data[7]) << 8) | UInt32(data[8])
        guard data.count >= 9 + length else { return nil }
        let payload = data.subdata(in: 9..<(9 + length))
        return HTTP2Frame(length: length, type: type, flags: flags,
                          streamID: streamID, payload: payload)
    }

    /// Parse all complete frames at the front of `data`, returning the
    /// frames plus any trailing incomplete bytes.
    public static func parseAll(_ data: Data) -> (frames: [HTTP2Frame], remainder: Data) {
        var frames: [HTTP2Frame] = []
        var pos = 0
        while pos + 9 <= data.count {
            guard let f = parse(data.subdata(in: pos..<data.count)) else { break }
            frames.append(f)
            pos += f.totalSize
        }
        let remainder = pos < data.count ? data.subdata(in: pos..<data.count) : Data()
        return (frames, remainder)
    }
}

/// HTTP/2 frame types (RFC 9113 §6).
public enum HTTP2FrameType: UInt8, Sendable {
    case data = 0x0
    case headers = 0x1
    case priority = 0x2
    case rstStream = 0x3
    case settings = 0x4
    case pushPromise = 0x5
    case ping = 0x6
    case goaway = 0x7
    case windowUpdate = 0x8
    case continuation = 0x9
}

/// The 24-octet client connection preface that precedes the first frame.
public enum HTTP2Preface {
    /// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    public static let clientMagic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    /// Returns true if `data` starts with the client connection preface.
    public static func matches(_ data: Data) -> Bool {
        data.count >= 24 && data.prefix(24) == Data(clientMagic.utf8)
    }
    /// Strip the preface if present, returning the frame-stream remainder.
    public static func strip(_ data: Data) -> Data {
        matches(data) ? data.subdata(in: 24..<data.count) : data
    }
}

// MARK: - HPACK-lite: literal header fields

/// A decoded HPACK header field (name + value). `indexed` is true when the
/// field was resolved from the HPACK static table (no literal bytes).
public struct HTTP2HeaderField: Equatable, Sendable {
    public let name: String
    public let value: String
    /// True when decoded from the static table (index only).
    public let indexed: Bool
}

/// Minimal HPACK decoder. Handles:
///   - Indexed Header Field (0x80 prefix) → static table lookup
///   - Literal Header Field with Incremental Indexing, indexed name (0x40)
///   - Literal Header Field with Incremental Indexing, literal name
///   - Literal Header Field without Indexing (0x00) / Never Indexed (0x10)
///   - Dynamic Table Size Update (0x20) — consumed, not applied
/// Huffman-encoded strings are returned as nil name/value (we don't decode
/// Huffman); the field is skipped rather than crashing the stream.
public enum HPACKLite {
    /// HPACK static table (RFC 7541 Appendix A), indices 1..61.
    static let staticTable: [(String, String)] = [
        (":authority", ""), (":method", "GET"), (":method", "POST"),
        (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
        (":scheme", "https"), (":status", "200"), (":status", "204"),
        (":status", "206"), (":status", "304"), (":status", "400"),
        (":status", "404"), (":status", "500"), ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
        ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
        ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
        ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""),
        ("content-length", ""), ("content-location", ""), ("content-range", ""),
        ("content-type", ""), ("cookie", ""), ("date", ""), ("etag", ""),
        ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
        ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
        ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
        ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
        ("proxy-authorization", ""), ("range", ""), ("referer", ""),
        ("refresh", ""), ("retry-after", ""), ("server", ""), ("set-cookie", ""),
        ("strict-transport-security", ""), ("transfer-encoding", ""), ("user-agent", ""),
        ("vary", ""), ("via", ""), ("www-authenticate", "")
    ]

    /// Decode a header block fragment into header fields. Fields whose
    /// name or value is Huffman-encoded are skipped (we can't decode
    /// Huffman without the full table). Returns the fields we could decode.
    public static func decode(_ block: Data) -> [HTTP2HeaderField] {
        var fields: [HTTP2HeaderField] = []
        var pos = 0
        let bytes = [UInt8](block)
        while pos < bytes.count {
            let b = bytes[pos]
            if (b & 0x80) != 0 {
                // Indexed Header Field.
                let (idx, consumed) = readInteger(bytes, offset: pos, prefixBits: 7)
                pos += consumed
                if let f = staticEntry(Int(idx)) { fields.append(f) }
            } else if (b & 0xc0) == 0x40 {
                // Literal with Incremental Indexing.
                let (idx, consumed) = readInteger(bytes, offset: pos, prefixBits: 6)
                pos += consumed
                var name: String? = nil
                if idx > 0 {
                    name = staticName(Int(idx))
                } else {
                    let (n, c) = readString(bytes, offset: pos)
                    pos += c
                    name = n
                }
                let (value, vc) = readString(bytes, offset: pos)
                pos += vc
                if let n = name, let v = value {
                    fields.append(HTTP2HeaderField(name: n, value: v, indexed: false))
                }
            } else if (b & 0xe0) == 0x20 {
                // Dynamic Table Size Update — consume and ignore.
                let (_, consumed) = readInteger(bytes, offset: pos, prefixBits: 5)
                pos += consumed
            } else {
                // Literal without indexing (0x00) or never indexed (0x10).
                let prefix = (b & 0x10) != 0 ? 4 : 4  // both use 4-bit index prefix
                let (idx, consumed) = readInteger(bytes, offset: pos, prefixBits: prefix)
                pos += consumed
                var name: String? = nil
                if idx > 0 {
                    name = staticName(Int(idx))
                } else {
                    let (n, c) = readString(bytes, offset: pos)
                    pos += c
                    name = n
                }
                let (value, vc) = readString(bytes, offset: pos)
                pos += vc
                if let n = name, let v = value {
                    fields.append(HTTP2HeaderField(name: n, value: v, indexed: false))
                }
            }
        }
        return fields
    }

    /// HPACK integer decode (N-bit prefix, continuation bytes).
    static func readInteger(_ bytes: [UInt8], offset: Int, prefixBits: Int) -> (UInt32, Int) {
        let prefixMax = UInt32((1 << prefixBits) - 1)
        var pos = offset
        guard pos < bytes.count else { return (0, 0) }
        var value = UInt32(bytes[pos] & UInt8(prefixMax))
        pos += 1
        if value < prefixMax { return (value, 1) }
        var m: UInt32 = 0
        while pos < bytes.count {
            let b = bytes[pos]
            pos += 1
            value += UInt32(b & 0x7f) << m
            m += 7
            if (b & 0x80) == 0 { break }
        }
        return (value, pos - offset)
    }

    /// Read an HPACK string: huffman flag + length prefix + bytes.
    /// Returns (string, bytes consumed); string is nil if Huffman-encoded.
    static func readString(_ bytes: [UInt8], offset: Int) -> (String?, Int) {
        guard offset < bytes.count else { return (nil, 0) }
        let huffman = (bytes[offset] & 0x80) != 0
        let (len, consumed) = readInteger(bytes, offset: offset, prefixBits: 7)
        var pos = offset + consumed
        guard pos + Int(len) <= bytes.count else { return (nil, consumed) }
        let strBytes = Array(bytes[pos..<(pos + Int(len))])
        pos += Int(len)
        if huffman { return (nil, pos - offset) }
        return (String(bytes: strBytes, encoding: .utf8), pos - offset)
    }

    static func staticEntry(_ index: Int) -> HTTP2HeaderField? {
        guard index >= 1 && index <= staticTable.count else { return nil }
        let (n, v) = staticTable[index - 1]
        return HTTP2HeaderField(name: n, value: v, indexed: true)
    }

    static func staticName(_ index: Int) -> String? {
        guard index >= 1 && index <= staticTable.count else { return nil }
        return staticTable[index - 1].0
    }
}

// MARK: - HEADERS frame payload decode

/// Decoded request metadata from a HEADERS frame.
public struct HTTP2Headers: Equatable, Sendable {
    public let streamID: UInt32
    /// Decoded header fields (HPACK-lite; Huffman-encoded fields skipped).
    public let fields: [HTTP2HeaderField]
    /// Pseudo-headers, for convenience.
    public var method: String? { fields.first { $0.name == ":method" }?.value }
    public var path: String? { fields.first { $0.name == ":path" }?.value }
    public var scheme: String? { fields.first { $0.name == ":scheme" }?.value }
    public var authority: String? { fields.first { $0.name == ":authority" }?.value }

    /// Decode a HEADERS frame payload (skipping padding + priority fields
    /// per flags) into header fields.
    public static func decode(_ frame: HTTP2Frame) -> HTTP2Headers? {
        guard frame.type == HTTP2FrameType.headers.rawValue else { return nil }
        var bytes = [UInt8](frame.payload)
        var pos = 0
        // PADDED flag (0x8): pad length byte first.
        var padLen = 0
        if (frame.flags & 0x8) != 0 {
            guard bytes.count > 0 else { return nil }
            padLen = Int(bytes[0]); pos += 1
        }
        // PRIORITY flag (0x20): 5 bytes (E + stream dep + weight).
        if (frame.flags & 0x20) != 0 {
            pos += 5
        }
        guard pos <= bytes.count else { return nil }
        let blockLen = bytes.count - pos - padLen
        guard blockLen >= 0 else { return nil }
        let block = Data(bytes[pos..<(pos + blockLen)])
        let fields = HPACKLite.decode(block)
        return HTTP2Headers(streamID: frame.streamID, fields: fields)
    }
}

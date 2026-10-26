import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for HTTP/2 frame parsing + HPACK-lite header decoding.
@Suite("HTTP/2 frame parser")
struct HTTP2Tests {

    /// Build a frame: length(3) type(1) flags(1) streamID(4) payload.
    private func makeFrame(type: UInt8, flags: UInt8, streamID: UInt32,
                           payload: [UInt8]) -> Data {
        var d = Data()
        let len = payload.count
        d.append(UInt8((len >> 16) & 0xff))
        d.append(UInt8((len >> 8) & 0xff))
        d.append(UInt8(len & 0xff))
        d.append(type)
        d.append(flags)
        d.append(UInt8((streamID >> 24) & 0x7f))
        d.append(UInt8((streamID >> 16) & 0xff))
        d.append(UInt8((streamID >> 8) & 0xff))
        d.append(UInt8(streamID & 0xff))
        d.append(contentsOf: payload)
        return d
    }

    @Test("Parse a SETTINGS frame")
    func parseSettings() {
        // SETTINGS frame: stream 0, empty payload, no flags.
        let frame = makeFrame(type: 0x4, flags: 0, streamID: 0, payload: [])
        let parsed = HTTP2Frame.parse(frame)
        #expect(parsed != nil)
        #expect(parsed?.type == 0x4)
        #expect(parsed?.streamID == 0)
        #expect(parsed?.length == 0)
        #expect(parsed?.totalSize == 9)
    }

    @Test("Parse a frame with payload")
    func parseWithPayload() {
        let payload: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        let frame = makeFrame(type: 0x0, flags: 0x1, streamID: 1, payload: payload)
        let parsed = HTTP2Frame.parse(frame)
        #expect(parsed != nil)
        #expect(parsed?.type == 0x0)
        #expect(parsed?.streamID == 1)
        #expect(parsed?.length == 4)
        #expect([UInt8](parsed!.payload) == payload)
    }

    @Test("Parse returns nil on incomplete frame")
    func parseIncomplete() {
        let frame = makeFrame(type: 0x0, flags: 0, streamID: 1, payload: [1, 2, 3, 4])
        let truncated = frame.prefix(10)  // header + 1 byte of 4-byte payload
        #expect(HTTP2Frame.parse(truncated) == nil)
        #expect(HTTP2Frame.parse(Data([1, 2, 3])) == nil)  // < 9 bytes
    }

    @Test("Parse multiple frames with remainder")
    func parseAll() {
        let f1 = makeFrame(type: 0x4, flags: 0, streamID: 0, payload: [0, 6, 0, 0, 0, 0, 0, 0])
        let f2 = makeFrame(type: 0x1, flags: 0x4, streamID: 1, payload: [0x88])
        var data = Data()
        data.append(f1)
        data.append(f2)
        data.append(contentsOf: [0xaa, 0xbb])  // trailing incomplete
        let (frames, remainder) = HTTP2Frame.parseAll(data)
        #expect(frames.count == 2)
        #expect(frames[0].type == 0x4)
        #expect(frames[1].type == 0x1)
        #expect([UInt8](remainder) == [0xaa, 0xbb])
    }

    @Test("Client preface detection and stripping")
    func preface() {
        var data = Data(HTTP2Preface.clientMagic.utf8)
        data.append(makeFrame(type: 0x4, flags: 0, streamID: 0, payload: []))
        #expect(HTTP2Preface.matches(data))
        let stripped = HTTP2Preface.strip(data)
        #expect([UInt8](stripped).first == 0x00)  // first frame length byte
        #expect(stripped.count == 9)  // just the SETTINGS frame
        #expect(!HTTP2Preface.matches(Data("GET / HTTP/1.1".utf8)))
    }

    @Test("Stream ID is 31-bit (reserved bit masked)")
    func streamIDMask() {
        let frame = makeFrame(type: 0x0, flags: 0, streamID: 0x80000001, payload: [])
        let parsed = HTTP2Frame.parse(frame)
        #expect(parsed?.streamID == 1)  // reserved bit masked out
    }
}

/// Tests for the HPACK-lite decoder (static table + literal fields).
@Suite("HPACK-lite decoder")
struct HPACKLiteTests {

    @Test("Indexed header field from static table")
    func indexedField() {
        // 0x82 = indexed, index 2 = ":method: GET"
        let fields = HPACKLite.decode(Data([0x82]))
        #expect(fields.count == 1)
        #expect(fields[0].name == ":method")
        #expect(fields[0].value == "GET")
        #expect(fields[0].indexed)
    }

    @Test("Multiple indexed fields")
    func multipleIndexed() {
        // 0x82=:method GET, 0x84=:path /, 0x87=:scheme https
        let fields = HPACKLite.decode(Data([0x82, 0x84, 0x87]))
        #expect(fields.count == 3)
        #expect(fields[0].name == ":method" && fields[0].value == "GET")
        #expect(fields[1].name == ":path" && fields[1].value == "/")
        #expect(fields[2].name == ":scheme" && fields[2].value == "https")
    }

    @Test("Literal field without indexing, indexed name")
    func literalIndexedName() {
        // 0x0f + 0x00 → literal without indexing, index... use 0x04 (:path)
        // 0x04 = 0b00000100: without indexing, name index 4 = :path
        // then length-prefixed value "/api/v1"
        let value = Array("/api/v1".utf8)
        var block: [UInt8] = [0x04]  // literal w/o indexing, name idx 4
        block.append(UInt8(value.count))
        block.append(contentsOf: value)
        let fields = HPACKLite.decode(Data(block))
        #expect(fields.count == 1)
        #expect(fields[0].name == ":path")
        #expect(fields[0].value == "/api/v1")
        #expect(!fields[0].indexed)
    }

    @Test("Literal field with new name")
    func literalNewName() {
        // 0x00 → literal without indexing, new name
        // name "x-custom", value "yes"
        let name = Array("x-custom".utf8)
        let value = Array("yes".utf8)
        var block: [UInt8] = [0x00]
        block.append(UInt8(name.count))
        block.append(contentsOf: name)
        block.append(UInt8(value.count))
        block.append(contentsOf: value)
        let fields = HPACKLite.decode(Data(block))
        #expect(fields.count == 1)
        #expect(fields[0].name == "x-custom")
        #expect(fields[0].value == "yes")
    }

    @Test("Literal field with incremental indexing")
    func literalIncremental() {
        // 0x40 → literal w/ incremental indexing, new name
        let name = Array("x-tok".utf8)
        let value = Array("abc".utf8)
        var block: [UInt8] = [0x40]
        block.append(UInt8(name.count))
        block.append(contentsOf: name)
        block.append(UInt8(value.count))
        block.append(contentsOf: value)
        let fields = HPACKLite.decode(Data(block))
        #expect(fields.count == 1)
        #expect(fields[0].name == "x-tok")
        #expect(fields[0].value == "abc")
    }

    @Test("Huffman-encoded value is skipped, not fatal")
    func huffmanSkipped() {
        // 0x00 → literal w/o indexing, new name
        // name literal "x-a", value Huffman (0x80 | len)
        let name = Array("x-a".utf8)
        var block: [UInt8] = [0x00]
        block.append(UInt8(name.count))
        block.append(contentsOf: name)
        block.append(0x82)  // huffman + len 2
        block.append(contentsOf: [0xff, 0xff])
        // Followed by a decodable indexed field to prove parsing continues.
        block.append(0x82)
        let fields = HPACKLite.decode(Data(block))
        // The huffman field is skipped (name decoded but value nil → field
        // dropped), then :method GET still decodes.
        #expect(fields.contains { $0.name == ":method" && $0.value == "GET" })
    }

    @Test("Decode a realistic request header block")
    func realisticBlock() {
        // :method GET (0x82), :path / (0x84), :scheme https (0x87),
        // :authority via literal (0x01 = index 1 :authority), value "x.com"
        let auth = Array("x.com".utf8)
        var block: [UInt8] = [0x82, 0x84, 0x87]
        block.append(0x01)  // literal w/o indexing, name idx 1 = :authority
        block.append(UInt8(auth.count))
        block.append(contentsOf: auth)
        let headers = HPACKLite.decode(Data(block))
        let pseudo = HTTP2Headers(streamID: 1, fields: headers)
        #expect(pseudo.method == "GET")
        #expect(pseudo.path == "/")
        #expect(pseudo.scheme == "https")
        #expect(pseudo.authority == "x.com")
    }
}

/// Tests for HEADERS frame payload decoding (padding + priority).
@Suite("HTTP/2 HEADERS decode")
struct HTTP2HeadersDecodeTests {

    private func makeHeadersFrame(flags: UInt8, streamID: UInt32, payload: [UInt8]) -> HTTP2Frame {
        HTTP2Frame(length: payload.count, type: 0x1, flags: flags,
                   streamID: streamID, payload: Data(payload))
    }

    @Test("Decode HEADERS frame with simple block")
    func simpleHeaders() {
        // :method GET + :path / (indexed)
        let payload: [UInt8] = [0x82, 0x84]
        let frame = makeHeadersFrame(flags: 0x4, streamID: 3, payload: payload)
        let h = HTTP2Headers.decode(frame)
        #expect(h != nil)
        #expect(h?.streamID == 3)
        #expect(h?.method == "GET")
        #expect(h?.path == "/")
    }

    @Test("Decode HEADERS frame with padding")
    func paddedHeaders() {
        // PADDED flag (0x8): first byte = pad length, then block, then pad.
        let payload: [UInt8] = [0x02, 0x82, 0x84, 0x00, 0x00]  // pad=2
        let frame = makeHeadersFrame(flags: 0x4 | 0x8, streamID: 1, payload: payload)
        let h = HTTP2Headers.decode(frame)
        #expect(h != nil)
        #expect(h?.method == "GET")
        #expect(h?.path == "/")
    }

    @Test("Decode HEADERS frame with priority")
    func priorityHeaders() {
        // PRIORITY flag (0x20): 5 bytes priority, then block.
        let payload: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x10, 0x82, 0x84]
        let frame = makeHeadersFrame(flags: 0x4 | 0x20, streamID: 1, payload: payload)
        let h = HTTP2Headers.decode(frame)
        #expect(h != nil)
        #expect(h?.method == "GET")
    }

    @Test("Returns nil for non-HEADERS frame")
    func nonHeaders() {
        let frame = HTTP2Frame(length: 0, type: 0x4, flags: 0, streamID: 0, payload: Data())
        #expect(HTTP2Headers.decode(frame) == nil)
    }
}

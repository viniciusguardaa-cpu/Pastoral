import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the content-injection engine (pure logic).
@Suite("Content rewriter")
struct ContentRewriterTests {

    private func pngImage() -> PreparedImage {
        PreparedImage(data: Data([0x89, 0x50, 0x4E, 0x47]), contentType: "image/png")
    }

    // MARK: - Decision

    @Test("Rewrites image/* content type")
    func imageContentType() {
        let rule = InjectionRule(scope: .allImages)
        let headers = ["Content-Type": "image/jpeg"]
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: "10.0.0.5", host: "x.com",
            path: "/a", responseHeaders: headers))
    }

    @Test("Rewrites on image extension even without image Content-Type")
    func imageExtension() {
        let rule = InjectionRule(scope: .allImages)
        let headers = ["Content-Type": "application/octet-stream"]
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/photos/cat.PNG?dl=1", responseHeaders: headers))
    }

    @Test("Does not rewrite non-image content")
    func notImage() {
        let rule = InjectionRule(scope: .allImages)
        let headers = ["Content-Type": "text/html"]
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/index.html", responseHeaders: headers))
    }

    @Test("Disabled rule never rewrites")
    func disabled() {
        let rule = InjectionRule(enabled: false, scope: .allImages)
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/a.png", responseHeaders: [:]))
    }

    @Test("Domain scope matches suffix")
    func domainScope() {
        let rule = InjectionRule(scope: .domains(["instagram.com", "cdn.example.org"]))
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "scontent.instagram.com",
            path: "/x.jpg", responseHeaders: [:]))
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "instagram.com",
            path: "/x.jpg", responseHeaders: [:]))
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "notinstagram.com",
            path: "/x.jpg", responseHeaders: [:]))
    }

    @Test("Path pattern scope matches regex")
    func pathPattern() {
        let rule = InjectionRule(scope: .pathPattern(#"/media/.*\.jpg"#))
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/media/a/b.jpg", responseHeaders: [:]))
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/static/logo.png", responseHeaders: [:]))
    }

    @Test("Target IP restriction limits to listed victims")
    func targetIPs() {
        let rule = InjectionRule(scope: .allImages, targetIPs: ["10.0.0.9"])
        #expect(ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: "10.0.0.9", host: "x.com",
            path: "/a.png", responseHeaders: [:]))
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: "10.0.0.5", host: "x.com",
            path: "/a.png", responseHeaders: [:]))
        #expect(!ResponseRewriter.shouldRewrite(
            rule: rule, clientIP: nil, host: "x.com",
            path: "/a.png", responseHeaders: [:]))
    }

    @Test("Media scope covers video only when imagesAndMedia")
    func mediaScope() {
        let headers = ["Content-Type": "video/mp4"]
        let images = InjectionRule(scope: .allImages, mediaScope: .imagesOnly)
        let media = InjectionRule(scope: .allImages, mediaScope: .imagesAndMedia)
        #expect(!ResponseRewriter.shouldRewrite(
            rule: images, clientIP: nil, host: "x.com",
            path: "/v.mp4", responseHeaders: headers))
        #expect(ResponseRewriter.shouldRewrite(
            rule: media, clientIP: nil, host: "x.com",
            path: "/v.mp4", responseHeaders: headers))
    }

    // MARK: - Response rebuild

    @Test("Rewritten response has correct Content-Length and no stale cache headers")
    func rebuild() {
        let statusLine = "HTTP/1.1 200 OK"
        let headers = [
            "Content-Type": "image/jpeg",
            "Content-Length": "9999",
            "ETag": "\"abc\"",
            "Cache-Control": "max-age=3600",
            "Transfer-Encoding": "chunked",
            "Server": "nginx",
            "Date": "Tue, 15 Sep 2026 00:00:00 GMT"
        ]
        let out = ResponseRewriter.rewriteResponse(
            statusLine: statusLine, headers: headers, body: pngImage())
        let str = String(decoding: out.prefix(512), as: UTF8.self)
        #expect(str.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(str.contains("Content-Type: image/png\r\n"))
        #expect(str.contains("Content-Length: 4\r\n"))
        #expect(str.contains("Cache-Control: no-store"))
        #expect(str.contains("Server: nginx"))
        #expect(!str.contains("ETag"))
        #expect(!str.contains("max-age"))
        #expect(!str.contains("chunked"))
        #expect(out.suffix(4) == Data([0x89, 0x50, 0x4E, 0x47]))
    }

    @Test("Status line extracted from raw head")
    func statusLine() {
        let raw = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://x/\r\n\r\n".data(using: .utf8)!
        #expect(ResponseRewriter.statusLine(of: raw) == "HTTP/1.1 301 Moved Permanently")
    }

    // MARK: - Chunked decoding

    @Test("Dechunk a simple chunked body")
    func dechunk() {
        let raw = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n".data(using: .utf8)!
        let out = ChunkedDecoder.decode(raw)
        #expect(out != nil)
        #expect(String(data: out!, encoding: .utf8) == "Wikipedia")
    }

    @Test("Dechunk with chunk extensions and trailers")
    func dechunkExtensions() {
        let raw = "4;foo=bar\r\nWiki\r\n0\r\nX-Trailer: x\r\n\r\n".data(using: .utf8)!
        let out = ChunkedDecoder.decode(raw)
        #expect(String(data: out ?? Data(), encoding: .utf8) == "Wiki")
    }

    @Test("Incomplete chunked body returns nil")
    func dechunkIncomplete() {
        let raw = "4\r\nWiki\r\n5\r\npe".data(using: .utf8)!
        #expect(ChunkedDecoder.decode(raw) == nil)
        #expect(!ChunkedDecoder.isComplete(raw))
    }

    // MARK: - ResponseBuffer

    @Test("Buffer detects Content-Length completion")
    func bufferLength() {
        let buf = ResponseBuffer()
        buf.append("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe".data(using: .utf8)!)
        #expect(buf.headComplete)
        #expect(buf.framing == .length(5))
        #expect(!buf.isComplete(eof: false))
        buf.append("llo".data(using: .utf8)!)
        #expect(buf.isComplete(eof: false))
        #expect(String(data: buf.decodedBody ?? Data(), encoding: .utf8) == "hello")
    }

    @Test("Buffer handles chunked framing")
    func bufferChunked() {
        let buf = ResponseBuffer()
        buf.append("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n".data(using: .utf8)!)
        #expect(buf.framing == .chunked)
        #expect(!buf.isComplete(eof: false))
        buf.append("0\r\n\r\n".data(using: .utf8)!)
        #expect(buf.isComplete(eof: false))
        #expect(String(data: buf.decodedBody ?? Data(), encoding: .utf8) == "abc")
    }

    @Test("Buffer untilClose needs EOF")
    func bufferUntilClose() {
        let buf = ResponseBuffer()
        buf.append("HTTP/1.0 200 OK\r\n\r\nbody".data(using: .utf8)!)
        #expect(buf.framing == .untilClose)
        #expect(!buf.isComplete(eof: false))
        #expect(buf.isComplete(eof: true))
    }

    @Test("204 response has no body")
    func bufferNoBody() {
        let buf = ResponseBuffer()
        buf.append("HTTP/1.1 204 No Content\r\n\r\n".data(using: .utf8)!)
        #expect(buf.framing == .some(ResponseFraming.none))
        #expect(buf.isComplete(eof: false))
    }

    // MARK: - ImagePool rotation

    @Test("Pool rotates round-robin when enabled")
    func rotation() {
        let pool = ImagePool(images: [
            PreparedImage(data: Data([1]), contentType: "image/png"),
            PreparedImage(data: Data([2]), contentType: "image/png"),
            PreparedImage(data: Data([3]), contentType: "image/png")
        ])
        #expect(pool.next(rotate: true)?.data == Data([1]))
        #expect(pool.next(rotate: true)?.data == Data([2]))
        #expect(pool.next(rotate: true)?.data == Data([3]))
        #expect(pool.next(rotate: true)?.data == Data([1]))
        // No rotation → always first.
        #expect(pool.next(rotate: false)?.data == Data([1]))
        #expect(pool.next(rotate: false)?.data == Data([1]))
    }

    @Test("Empty pool returns nil")
    func emptyPool() {
        let pool = ImagePool()
        #expect(pool.isEmpty)
        #expect(pool.next(rotate: true) == nil)
    }

    // MARK: - Expected dimensions

    @Test("Parses w/h query params")
    func dimsQuery() {
        #expect(ResponseRewriter.expectedDimensions(from: "/img.jpg?w=300&h=200")?.width == 300)
        #expect(ResponseRewriter.expectedDimensions(from: "/img.jpg?w=300&h=200")?.height == 200)
        #expect(ResponseRewriter.expectedDimensions(from: "/img.jpg?width=640&height=480")?.width == 640)
        #expect(ResponseRewriter.expectedDimensions(from: "/img.jpg?width=640&height=480")?.height == 480)
    }

    @Test("Parses WxH path pattern")
    func dimsPath() {
        #expect(ResponseRewriter.expectedDimensions(from: "/media/300x200/cat.jpg")?.width == 300)
        #expect(ResponseRewriter.expectedDimensions(from: "/media/300x200/cat.jpg")?.height == 200)
        #expect(ResponseRewriter.expectedDimensions(from: "/img.jpg") == nil)
    }
}
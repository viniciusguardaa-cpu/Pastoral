import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the replay request builder (phase 5).
@Suite("Replay builder")
struct ReplayBuilderTests {

    private func sampleExchange(method: String = "GET", path: String = "/api/users",
                                host: String = "example.com",
                                headers: [String: String] = [:],
                                body: Data? = nil) -> CapturedExchange {
        var h = headers
        if host != "" { h["Host"] = host }
        return CapturedExchange(
            host: host, method: method, path: path,
            requestHeaders: h, requestBody: body,
            isTLS: true, sni: host
        )
    }

    @Test("Replays a simple GET unchanged")
    func replayUnchanged() throws {
        let ex = sampleExchange(headers: ["User-Agent": "Test/1.0", "Accept": "*/*"])
        let data = try #require(ReplayBuilder.buildRequest(from: ex))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.hasPrefix("GET /api/users HTTP/1.1\r\n"))
        #expect(str.contains("Host: example.com\r\n"))
        #expect(str.contains("User-Agent: Test/1.0\r\n"))
        #expect(str.contains("Accept: */*\r\n"))
        #expect(str.hasSuffix("\r\n\r\n"))
    }

    @Test("Changes the method to POST")
    func changeMethod() throws {
        let ex = sampleExchange(method: "GET")
        let mods = ReplayBuilder.Modifications(method: "POST", body: "name=alice".data(using: .utf8))
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.hasPrefix("POST /api/users HTTP/1.1\r\n"))
        #expect(str.contains("Content-Length: 10\r\n"))
        #expect(str.hasSuffix("name=alice"))
    }

    @Test("Changes the path")
    func changePath() throws {
        let ex = sampleExchange(path: "/api/users")
        let mods = ReplayBuilder.Modifications(path: "/api/admin/users")
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.hasPrefix("GET /api/admin/users HTTP/1.1\r\n"))
    }

    @Test("Injects a cookie header")
    func injectHeader() throws {
        let ex = sampleExchange()
        let mods = ReplayBuilder.Modifications(setHeaders: ["Cookie": "session=abc123"])
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.contains("Cookie: session=abc123\r\n"))
    }

    @Test("Replaces an existing header (case-insensitive)")
    func replaceHeader() throws {
        let ex = sampleExchange(headers: ["User-Agent": "Old/1.0"])
        let mods = ReplayBuilder.Modifications(setHeaders: ["user-agent": "New/2.0"])
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.contains("user-agent: New/2.0\r\n"))
        #expect(!str.contains("Old/1.0"))
    }

    @Test("Removes a header")
    func removeHeader() throws {
        let ex = sampleExchange(headers: ["If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT"])
        let mods = ReplayBuilder.Modifications(removeHeaders: ["if-modified-since"])
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(!str.contains("If-Modified-Since"))
        #expect(!str.contains("if-modified-since"))
    }

    @Test("Overrides the Host header")
    func overrideHost() throws {
        let ex = sampleExchange(host: "example.com")
        let mods = ReplayBuilder.Modifications(host: "staging.example.com")
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.contains("Host: staging.example.com\r\n"))
        #expect(!str.contains("Host: example.com\r\n"))
    }

    @Test("Recomputes Content-Length for new body")
    func recomputeContentLength() throws {
        let ex = sampleExchange(method: "POST",
                                  headers: ["Content-Length": "5"],
                                  body: "hello".data(using: .utf8))
        let mods = ReplayBuilder.Modifications(body: "hello world".data(using: .utf8))
        let data = try #require(ReplayBuilder.buildRequest(from: ex, modifications: mods))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.contains("Content-Length: 11\r\n"))
        #expect(str.hasSuffix("hello world"))
    }

    @Test("Returns nil for empty method")
    func emptyMethod() {
        let ex = sampleExchange(method: "")
        #expect(ReplayBuilder.buildRequest(from: ex) == nil)
    }

    @Test("Returns nil for empty path")
    func emptyPath() {
        let ex = sampleExchange(path: "")
        #expect(ReplayBuilder.buildRequest(from: ex) == nil)
    }

    @Test("Replays a POST with original body when no body override")
    func keepOriginalBody() throws {
        let ex = sampleExchange(method: "POST",
                                  headers: ["Content-Length": "10"],
                                  body: "user=alice".data(using: .utf8))
        let data = try #require(ReplayBuilder.buildRequest(from: ex))
        let str = String(decoding: data, as: UTF8.self)
        #expect(str.contains("Content-Length: 10\r\n"))
        #expect(str.hasSuffix("user=alice"))
    }
}

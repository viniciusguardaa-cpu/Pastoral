import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for HTTP request/response parsing.
@Suite("HTTP parsing")
struct HTTPParsingTests {

    @Test("Parse a simple GET request")
    func parseGet() {
        let raw = "GET /path/to/page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n".data(using: .utf8)!
        let parsed = HTTPRequestParser.parse(raw)!
        #expect(parsed.method == "GET")
        #expect(parsed.path == "/path/to/page")
        #expect(parsed.host == "example.com")
        #expect(parsed.headers["User-Agent"] == "test")
        #expect(parsed.body == nil)
    }

    @Test("Parse a POST request with body")
    func parsePost() {
        let raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nhello=world\r\n".data(using: .utf8)!
        let parsed = HTTPRequestParser.parse(raw)!
        #expect(parsed.method == "POST")
        #expect(parsed.path == "/submit")
        #expect(parsed.host == "example.com")
        #expect(parsed.headers["Content-Length"] == "13")
        #expect(parsed.body != nil)
        #expect(String(data: parsed.body!, encoding: .utf8) == "hello=world\r\n")
    }

    @Test("Parse request with host:port")
    func parseHostPort() {
        let raw = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".data(using: .utf8)!
        let parsed = HTTPRequestParser.parse(raw)!
        #expect(parsed.host == "example.com")
    }

    @Test("Find header end index")
    func findHeaderEnd() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody".data(using: .utf8)!
        let idx = HTTPRequestParser.findHeaderEnd(in: raw)!
        // "GET / HTTP/1.1\r\nHost: x\r\n" = 23 bytes, \r\n\r\n starts at 23
        #expect(idx == 23)
    }

    @Test("Return nil for incomplete headers")
    func incompleteHeaders() {
        let raw = "GET / HTTP/1.1\r\nHost: x".data(using: .utf8)!
        #expect(HTTPRequestParser.parse(raw) == nil)
    }

    @Test("Parse HTTP response")
    func parseResponse() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello".data(using: .utf8)!
        let parsed = HTTPResponseParser.parse(raw)!
        #expect(parsed.status == 200)
        #expect(parsed.reason == "OK")
        #expect(parsed.headers["Content-Type"] == "text/html")
        #expect(String(data: parsed.body!, encoding: .utf8) == "hello")
    }

    @Test("Parse response with no body")
    func parseResponseNoBody() {
        let raw = "HTTP/1.1 204 No Content\r\n\r\n".data(using: .utf8)!
        let parsed = HTTPResponseParser.parse(raw)!
        #expect(parsed.status == 204)
        #expect(parsed.body == nil)
    }
}

/// Unit tests for CapturedExchange credential detection.
@Suite("Credential detection")
struct CredentialTests {

    @Test("Cookie header marks credential")
    func cookieHeader() {
        let ex = CapturedExchange(host: "x.com", method: "GET", path: "/",
                                  requestHeaders: ["Cookie": "session=abc"])
        #expect(ex.hasCredential == true)
    }

    @Test("Set-Cookie response marks credential")
    func setCookieResponse() {
        let ex = CapturedExchange(host: "x.com", method: "GET", path: "/",
                                  responseHeaders: ["Set-Cookie": "token=xyz"])
        #expect(ex.hasCredential == true)
    }

    @Test("POST with password field marks credential")
    func postPassword() {
        let body = "password=secret123".data(using: .utf8)!
        let ex = CapturedExchange(host: "x.com", method: "POST", path: "/login",
                                  requestBody: body)
        #expect(ex.hasCredential == true)
    }

    @Test("POST with token field marks credential")
    func postToken() {
        let body = "token=abc&name=john".data(using: .utf8)!
        let ex = CapturedExchange(host: "x.com", method: "POST", path: "/api",
                                  requestBody: body)
        #expect(ex.hasCredential == true)
    }

    @Test("Authorization header marks credential")
    func authHeader() {
        let ex = CapturedExchange(host: "x.com", method: "GET", path: "/",
                                  requestHeaders: ["Authorization": "Bearer xyz"])
        #expect(ex.hasCredential == true)
    }

    @Test("Plain GET without credentials")
    func noCredential() {
        let ex = CapturedExchange(host: "x.com", method: "GET", path: "/page")
        #expect(ex.hasCredential == false)
    }
}

/// Unit tests for HAR/CSV export.
@Suite("Export")
struct ExportTests {

    @Test("CSV export has header row")
    func csvHeader() {
        let csv = String(data: ExchangeExporter.exportCSV([]), encoding: .utf8)!
        #expect(csv.hasPrefix("timestamp,host,method,path,status,size,credential,isTLS,sni"))
    }

    @Test("CSV export includes exchanges")
    func csvRows() {
        let exchanges = [
            CapturedExchange(host: "a.com", method: "GET", path: "/p", status: 200),
            CapturedExchange(host: "b.com", method: "POST", path: "/q", status: 404)
        ]
        let csv = String(data: ExchangeExporter.exportCSV(exchanges), encoding: .utf8)!
        let lines = csv.split(separator: "\n")
        #expect(lines.count == 3)  // header + 2 rows
        #expect(csv.contains("a.com"))
        #expect(csv.contains("b.com"))
        #expect(csv.contains("200"))
        #expect(csv.contains("404"))
    }

    @Test("HAR export is valid JSON")
    func harValid() throws {
        let exchanges = [
            CapturedExchange(host: "a.com", method: "GET", path: "/p", status: 200)
        ]
        let data = try ExchangeExporter.exportHAR(exchanges)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(json != nil)
        let log = json?["log"] as? [String: Any]
        #expect(log?["version"] as? String == "1.2")
        let entries = log?["entries"] as? [[String: Any]]
        #expect(entries?.count == 1)
    }

    @Test("CSV escapes commas")
    func csvEscape() {
        let ex = CapturedExchange(host: "a,b.com", method: "GET", path: "/p")
        let csv = String(data: ExchangeExporter.exportCSV([ex]), encoding: .utf8)!
        #expect(csv.contains("\"a,b.com\""))
    }
}

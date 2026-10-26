import Foundation

// MARK: - HTTP request/response capture models
//
// Pure data models for captured HTTP traffic. Used by the proxy to report
// what it saw, by the app to display in the Sheep tab, and by the export
// logic (HAR/CSV). All testable without a running proxy.

/// A captured HTTP exchange (request + response summary). This is what
/// populates the live requests table in the Sheep tab.
public struct CapturedExchange: Identifiable, Equatable, Sendable {
    public let id: UUID
    public var timestamp: Date
    public var host: String
    public var method: String
    public var path: String
    public var requestHeaders: [String: String]
    public var requestBody: Data?
    public var status: Int?
    public var responseHeaders: [String: String]
    public var responseBody: Data?
    public var isTLS: Bool          // true if CONNECT/TLS, false if plain HTTP
    public var sni: String?         // SNI for TLS connections
    /// True when the proxy replaced the response body (content injection).
    public var wasRewritten: Bool

    public init(id: UUID = UUID(), timestamp: Date = .now, host: String,
                method: String, path: String,
                requestHeaders: [String: String] = [:], requestBody: Data? = nil,
                status: Int? = nil, responseHeaders: [String: String] = [:],
                responseBody: Data? = nil, isTLS: Bool = false, sni: String? = nil,
                wasRewritten: Bool = false) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.method = method
        self.path = path
        self.requestHeaders = requestHeaders
        self.requestBody = requestBody
        self.status = status
        self.responseHeaders = responseHeaders
        self.responseBody = responseBody
        self.isTLS = isTLS
        self.sni = sni
        self.wasRewritten = wasRewritten
    }

    /// Total response size in bytes (body + estimated headers).
    public var sizeBytes: Int {
        let bodyLen = responseBody?.count ?? 0
        let headerLen = responseHeaders.reduce(0) { $0 + $1.key.count + $1.value.count + 4 }
        return bodyLen + headerLen
    }

    /// True if the request carries credentials: POST with password/token
    /// fields, or Cookie/Set-Cookie headers.
    public var hasCredential: Bool {
        // Check for Cookie/Set-Cookie headers.
        if requestHeaders.keys.contains(where: { $0.lowercased() == "cookie" }) { return true }
        if responseHeaders.keys.contains(where: { $0.lowercased() == "set-cookie" }) { return true }
        // Check POST body for password/token fields.
        if method.uppercased() == "POST", let body = requestBody {
            let bodyStr = String(data: body, encoding: .utf8) ?? ""
            let lower = bodyStr.lowercased()
            let credFields = ["password", "passwd", "token", "secret",
                              "api_key", "apikey", "access_token",
                              "refresh_token", "authorization"]
            for field in credFields {
                if lower.contains(field) { return true }
            }
        }
        // Check Authorization header.
        if requestHeaders.keys.contains(where: { $0.lowercased() == "authorization" }) {
            return true
        }
        return false
    }
}

// MARK: - HTTP parsing (pure logic, testable)

/// Parse an HTTP request from raw bytes. Returns the method, path, host,
/// headers, and body. Pure function — no I/O.
public struct HTTPRequestParser {
    public struct ParsedRequest: Equatable {
        public let method: String
        public let path: String
        public let headers: [String: String]
        public let body: Data?
        public let host: String?
        public let rawHead: Data   // the request line + headers (up to \r\n\r\n)
    }

    public static func parse(_ data: Data) -> ParsedRequest? {
        // Find the end of headers (\r\n\r\n).
        guard let headerEnd = findHeaderEnd(in: data) else { return nil }
        let headerData = data.prefix(headerEnd + 4)
        guard let headerStr = String(data: headerData, encoding: .utf8) else { return nil }

        let lines = headerStr.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else { return nil }
        let parts = firstLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0])
        let path = String(parts[1])

        // Parse headers.
        var headers: [String: String] = [:]
        var host: String? = nil
        for line in lines.dropFirst() {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIdx)...])
                .trimmingCharacters(in: .whitespaces)
            headers[key] = value
            if key.lowercased() == "host" {
                // Strip port if present.
                host = value.split(separator: ":").first.map(String.init) ?? value
            }
        }

        // Body is everything after \r\n\r\n.
        let bodyStart = headerEnd + 4
        let body = bodyStart < data.count ? data.suffix(from: bodyStart) : nil
        let bodyData = body?.isEmpty == false ? Data(body!) : nil

        return ParsedRequest(method: method, path: path, headers: headers,
                             body: bodyData, host: host, rawHead: Data(headerData))
    }

    /// Find the index of the \r\n\r\n that terminates HTTP headers.
    public static func findHeaderEnd(in data: Data) -> Int? {
        let pattern: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]  // \r\n\r\n
        guard data.count >= 4 else { return nil }
        for i in 0...(data.count - 4) {
            if data[i] == pattern[0] && data[i+1] == pattern[1]
               && data[i+2] == pattern[2] && data[i+3] == pattern[3] {
                return i
            }
        }
        return nil
    }
}

/// Parse an HTTP response from raw bytes. Returns status, headers, body.
public struct HTTPResponseParser {
    public struct ParsedResponse: Equatable {
        public let status: Int
        public let reason: String
        public let headers: [String: String]
        public let body: Data?
        public let rawHead: Data
    }

    public static func parse(_ data: Data) -> ParsedResponse? {
        guard let headerEnd = HTTPRequestParser.findHeaderEnd(in: data) else { return nil }
        let headerData = data.prefix(headerEnd + 4)
        guard let headerStr = String(data: headerData, encoding: .utf8) else { return nil }

        let lines = headerStr.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else { return nil }
        let parts = firstLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, let status = Int(parts[1]) else { return nil }
        let reason = parts.count >= 3 ? String(parts[2]) : ""

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIdx)...])
                .trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }

        let bodyStart = headerEnd + 4
        let body = bodyStart < data.count ? data.suffix(from: bodyStart) : nil
        let bodyData = body?.isEmpty == false ? Data(body!) : nil

        return ParsedResponse(status: status, reason: reason, headers: headers,
                              body: bodyData, rawHead: Data(headerData))
    }
}

// MARK: - Export (HAR + CSV)

/// Export captured exchanges to HAR (HTTP Archive) format. Pure logic —
/// produces a Data blob, no file I/O.
public enum ExchangeExporter {
    /// Export to HAR 1.2 format.
    public static func exportHAR(_ exchanges: [CapturedExchange]) throws -> Data {
        let harEntries = exchanges.map { exchange -> [String: Any] in
            var request: [String: Any] = [
                "method": exchange.method,
                "url": "http\(exchange.isTLS ? "s" : "")://\(exchange.host)\(exchange.path)",
                "httpVersion": exchange.isTLS ? "HTTP/1.1" : "HTTP/1.1",
                "headers": exchange.requestHeaders.map { ["name": $0.key, "value": $0.value] },
                "queryString": [],
                "headersSize": -1,
                "cookiesSize": -1
            ]
            if let body = exchange.requestBody {
                request["postData"] = [
                    "mimeType": exchange.requestHeaders["Content-Type"] ?? "application/octet-stream",
                    "text": String(data: body, encoding: .utf8) ?? ""
                ] as [String: Any]
            }

            var response: [String: Any] = [
                "status": exchange.status ?? 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": exchange.responseHeaders.map { ["name": $0.key, "value": $0.value] },
                "cookies": [],
                "headersSize": -1,
                "bodySize": exchange.responseBody?.count ?? 0
            ]
            if let body = exchange.responseBody {
                response["content"] = [
                    "size": body.count,
                    "mimeType": exchange.responseHeaders["Content-Type"] ?? "application/octet-stream",
                    "text": String(data: body.prefix(65536), encoding: .utf8) ?? ""
                ] as [String: Any]
            }

            return [
                "startedDateTime": ISO8601DateFormatter().string(from: exchange.timestamp),
                "time": 0,
                "request": request,
                "response": response,
                "cache": [:],
                "timings": ["send": 0, "wait": 0, "receive": 0]
            ] as [String: Any]
        }

        let har: [String: Any] = [
            "log": [
                "version": "1.2",
                "creator": ["name": "Pastoral", "version": "1.0"],
                "entries": harEntries
            ] as [String: Any]
        ]

        return try JSONSerialization.data(withJSONObject: har, options: .prettyPrinted)
    }

    /// Export to CSV. Columns: timestamp, host, method, path, status,
    /// size, credential, isTLS, sni.
    public static func exportCSV(_ exchanges: [CapturedExchange]) -> Data {
        var rows: [String] = []
        rows.append("timestamp,host,method,path,status,size,credential,isTLS,sni")
        let fmt = ISO8601DateFormatter()
        for ex in exchanges {
            let ts = fmt.string(from: ex.timestamp)
            let cred = ex.hasCredential ? "yes" : "no"
            let tls = ex.isTLS ? "yes" : "no"
            let sni = ex.sni ?? ""
            let status = ex.status.map(String.init) ?? ""
            let row = "\(csvEscape(ts)),\(csvEscape(ex.host)),\(csvEscape(ex.method)),\(csvEscape(ex.path)),\(csvEscape(status)),\(ex.sizeBytes),\(cred),\(tls),\(csvEscape(sni))"
            rows.append(row)
        }
        return (rows.joined(separator: "\n") + "\n").data(using: .utf8) ?? Data()
    }

    /// Escape a field for CSV (wrap in quotes if it contains commas/quotes).
    private static func csvEscape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return s
    }
}

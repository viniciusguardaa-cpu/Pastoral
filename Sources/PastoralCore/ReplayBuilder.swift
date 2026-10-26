import Foundation

/// Pure logic for replaying a captured HTTP request with optional
/// modifications (phase 5). The builder takes a `CapturedExchange` and a
/// set of overrides, and produces raw HTTP/1.1 request bytes ready to
/// send to the origin. No I/O — fully testable.
///
/// Modifications supported:
/// - Change the method (e.g. GET → POST).
/// - Change the path.
/// - Add/replace/remove headers (e.g. inject a cookie, drop
///   `If-Modified-Since` to force a 200).
/// - Replace the body.
/// - Override the Host header (for replay against a different host).
///
/// `Content-Length` and `Host` are recomputed automatically so the
/// replayed request is always well-formed.
public enum ReplayBuilder {

    /// A set of modifications to apply to a captured request on replay.
    public struct Modifications: Equatable, Sendable {
        public var method: String?            // nil = keep original
        public var path: String?              // nil = keep original
        public var host: String?              // nil = keep original Host header
        public var body: Data?                // nil = keep original body
        /// Headers to add or replace (key → value). Case-insensitive keys.
        public var setHeaders: [String: String] = [:]
        /// Header names to remove (case-insensitive).
        public var removeHeaders: Set<String> = []

        public init(method: String? = nil, path: String? = nil, host: String? = nil,
                    body: Data? = nil, setHeaders: [String: String] = [:],
                    removeHeaders: Set<String> = []) {
            self.method = method
            self.path = path
            self.host = host
            self.body = body
            self.setHeaders = setHeaders
            self.removeHeaders = removeHeaders
        }
    }

    /// Build raw HTTP/1.1 request bytes from a captured exchange with
    /// modifications applied. Returns nil if the original request is
    /// malformed (no method/path).
    public static func buildRequest(from exchange: CapturedExchange,
                                    modifications: Modifications = Modifications()) -> Data? {
        let method = (modifications.method ?? exchange.method).uppercased()
        let path = modifications.path ?? exchange.path
        guard !method.isEmpty, !path.isEmpty else { return nil }

        // Start from the original headers, then apply modifications.
        var headers = exchange.requestHeaders

        // Remove headers (case-insensitive).
        if !modifications.removeHeaders.isEmpty {
            let toRemove = Set(modifications.removeHeaders.map { $0.lowercased() })
            headers = headers.filter { !toRemove.contains($0.key.lowercased()) }
        }
        // Add/replace headers (case-insensitive: remove existing matching
        // keys first to avoid duplicates).
        for (key, value) in modifications.setHeaders {
            let lower = key.lowercased()
            headers = headers.filter { $0.key.lowercased() != lower }
            headers[key] = value
        }
        // Override Host header.
        if let host = modifications.host {
            let lower = "host"
            headers = headers.filter { $0.key.lowercased() != lower }
            headers["Host"] = host
        }

        // Body: use the override or the original.
        let body: Data? = modifications.body ?? exchange.requestBody

        // Recompute Content-Length to match the (possibly new) body.
        let lowerCL = "content-length"
        headers = headers.filter { $0.key.lowercased() != lowerCL }
        if let body, !body.isEmpty {
            headers["Content-Length"] = String(body.count)
        }

        // Build the request line + headers.
        var lines: [String] = ["\(method) \(path) HTTP/1.1"]
        // Stable header order: sort by key for deterministic output.
        for key in headers.keys.sorted() {
            lines.append("\(key): \(headers[key] ?? "")")
        }
        var raw = Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
        if let body, !body.isEmpty {
            raw.append(body)
        }
        return raw
    }
}

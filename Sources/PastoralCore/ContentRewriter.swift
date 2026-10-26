import Foundation

// MARK: - Content rewriting (pure logic, testable)
//
// The injection engine: given an HTTP response, decide whether to swap its
// body for one of our images, and produce the rewritten wire bytes. Shared
// between the app (GUI state) and the proxy (which applies it). No I/O —
// image bytes arrive already prepared (transcoded/resized) by the app.

/// Which requests a rule applies to.
public enum InjectionScope: Codable, Equatable, Sendable {
    /// Every image (and optionally media) response.
    case allImages
    /// Only responses from these domains (suffix match, case-insensitive).
    case domains([String])
    /// Only paths matching this regex.
    case pathPattern(String)
}

/// Which content classes a rule rewrites.
public enum MediaScope: String, Codable, Equatable, Sendable {
    /// `image/*` Content-Types and image file extensions only.
    case imagesOnly
    /// Images plus `video/*`/`audio/*` and media file extensions
    /// (.mp4/.webm/.ts/…) — the "fullscreen" mode for TVs.
    case imagesAndMedia
}

/// A complete injection rule. `Codable` so the app can persist/share it.
public struct InjectionRule: Codable, Equatable, Sendable {
    /// Master switch — when false nothing is rewritten.
    public var enabled: Bool
    /// Which requests this rule applies to.
    public var scope: InjectionScope
    /// Restrict to these victim (source) IPs. Empty = all intercepted hosts.
    public var targetIPs: Set<String>
    /// Images only, or images + media streams.
    public var mediaScope: MediaScope
    /// Try to match the dimensions the page expected (from the request URL).
    public var preserveDimensions: Bool
    /// Cycle through the image pool instead of always serving the first.
    public var rotate: Bool

    public init(enabled: Bool = true,
                scope: InjectionScope = .allImages,
                targetIPs: Set<String> = [],
                mediaScope: MediaScope = .imagesOnly,
                preserveDimensions: Bool = false,
                rotate: Bool = false) {
        self.enabled = enabled
        self.scope = scope
        self.targetIPs = targetIPs
        self.mediaScope = mediaScope
        self.preserveDimensions = preserveDimensions
        self.rotate = rotate
    }
}

/// An image variant ready to serve: encoded bytes + its MIME type.
/// Produced by the app's ImageProvider (ImageIO transcode); the core only
/// sees the final bytes.
public struct PreparedImage: Equatable, Sendable {
    public let data: Data
    public let contentType: String      // e.g. "image/png"
    public let pixelWidth: Int?
    public let pixelHeight: Int?

    public init(data: Data, contentType: String,
                pixelWidth: Int? = nil, pixelHeight: Int? = nil) {
        self.data = data
        self.contentType = contentType
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
    }
}

/// A thread-safe rotation over prepared images. `next()` round-robins so
/// responses don't all carry the same picture when rotation is enabled.
public final class ImagePool: @unchecked Sendable {
    private let lock = NSLock()
    private var images: [PreparedImage]
    private var index = 0

    public init(images: [PreparedImage] = []) {
        self.images = images
    }

    public var isEmpty: Bool {
        lock.lock(); defer { lock.unlock() }
        return images.isEmpty
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return images.count
    }

    /// Replace the whole pool (user picked a new file/folder).
    public func update(_ newImages: [PreparedImage]) {
        lock.lock()
        images = newImages
        index = 0
        lock.unlock()
    }

    /// Next image to serve. `rotate == false` always returns the first.
    public func next(rotate: Bool) -> PreparedImage? {
        lock.lock()
        defer { lock.unlock() }
        guard !images.isEmpty else { return nil }
        if !rotate || images.count == 1 { return images[0] }
        defer { index = (index + 1) % images.count }
        return images[index]
    }
}

// MARK: - Decision + header rewriting

/// Pure functions deciding whether a response is rewritten, and producing
/// the rewritten wire bytes (status line + headers + new body).
public enum ResponseRewriter {
    /// File extensions treated as images when Content-Type is missing.
    public static let imageExtensions: Set<String> = [
        "jpg", "jpeg", "png", "webp", "gif", "svg", "ico", "avif", "bmp", "tiff"
    ]
    /// Extensions treated as media for the "fullscreen" mode.
    public static let mediaExtensions: Set<String> = [
        "mp4", "m4v", "webm", "ts", "m2ts", "mp3", "aac", "m4a", "ogg", "mov"
    ]

    /// Case-insensitive header lookup (parsed headers keep original case).
    public static func headerValue(_ headers: [String: String], _ name: String) -> String? {
        headers.first { $0.key.lowercased() == name.lowercased() }?.value
    }

    /// Path extension (query stripped), lowercased. Nil if none.
    public static func pathExtension(_ path: String) -> String? {
        let p = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
        // Take the last path segment so "/a.b/c" doesn't count ".b".
        let last = p.split(separator: "/").last.map(String.init) ?? p
        guard let dot = last.lastIndex(of: "."), dot != last.startIndex else { return nil }
        return String(last[last.index(after: dot)...]).lowercased()
    }

    /// True when the response carries an image (Content-Type image/* or an
    /// image extension in the path).
    public static func isImageResponse(headers: [String: String], path: String) -> Bool {
        if let ct = headerValue(headers, "Content-Type")?.lowercased(),
           ct.hasPrefix("image/") { return true }
        if let ext = pathExtension(path) { return imageExtensions.contains(ext) }
        return false
    }

    /// True when the response carries media (video/audio Content-Type or a
    /// media extension in the path).
    public static func isMediaResponse(headers: [String: String], path: String) -> Bool {
        if let ct = headerValue(headers, "Content-Type")?.lowercased(),
           ct.hasPrefix("video/") || ct.hasPrefix("audio/") { return true }
        if let ext = pathExtension(path) { return mediaExtensions.contains(ext) }
        return false
    }

    /// Decide whether this response should have its body swapped.
    /// - Parameters:
    ///   - rule: the active injection rule
    ///   - clientIP: source IP of the victim connection (nil if unknown)
    ///   - host/path: from the request
    ///   - responseHeaders: from the origin response
    public static func shouldRewrite(rule: InjectionRule,
                                     clientIP: String?,
                                     host: String,
                                     path: String,
                                     responseHeaders: [String: String]) -> Bool {
        guard rule.enabled else { return false }

        // Target restriction: only listed victim IPs.
        if !rule.targetIPs.isEmpty {
            guard let clientIP, rule.targetIPs.contains(clientIP) else { return false }
        }

        // Content class gate.
        let image = isImageResponse(headers: responseHeaders, path: path)
        let media = rule.mediaScope == .imagesAndMedia
            && isMediaResponse(headers: responseHeaders, path: path)
        guard image || media else { return false }

        // Scope gate.
        switch rule.scope {
        case .allImages:
            return true
        case .domains(let domains):
            let h = host.lowercased()
            return domains.contains { d in
                let dd = d.lowercased()
                return h == dd || h.hasSuffix("." + dd)
            }
        case .pathPattern(let pattern):
            return path.range(of: pattern, options: .regularExpression) != nil
        }
    }

    /// Headers we drop from the origin response when rewriting — anything
    /// that would let the client reuse a stale copy or mis-frame the body.
    static let strippedHeaders: Set<String> = [
        "etag", "last-modified", "cache-control", "pragma", "expires", "age",
        "content-length", "content-type", "content-encoding",
        "transfer-encoding", "content-range", "accept-ranges",
        "digest", "content-md5", "if-none-match", "if-modified-since",
        "keep-alive"
    ]

    /// Extract the status line (first line) from a raw response head.
    public static func statusLine(of rawHead: Data) -> String {
        guard let s = String(data: rawHead, encoding: .utf8),
              let first = s.components(separatedBy: "\r\n").first, !first.isEmpty else {
            return "HTTP/1.1 200 OK"
        }
        return first
    }

    /// Build the rewritten response: original status line, surviving
    /// headers, then our Content-Type/Length and no-store directives.
    /// `Connection: close` so the client never pipelines past our body.
    public static func rewriteResponse(statusLine: String,
                                       headers: [String: String],
                                       body: PreparedImage) -> Data {
        var head = statusLine + "\r\n"
        for (key, value) in headers where !strippedHeaders.contains(key.lowercased()) {
            head += "\(key): \(value)\r\n"
        }
        head += "Content-Type: \(body.contentType)\r\n"
        head += "Content-Length: \(body.data.count)\r\n"
        head += "Cache-Control: no-store, no-cache, must-revalidate\r\n"
        head += "Connection: close\r\n"
        head += "\r\n"
        var out = Data(head.utf8)
        out.append(body.data)
        return out
    }

    /// Guess the dimensions the page expects for this resource, from the
    /// request path/query (w=/h=, width=/height=, or a `WxH` pattern like
    /// /300x200/ used by many CDNs). Nil when no reliable hint.
    public static func expectedDimensions(from path: String) -> (width: Int, height: Int)? {
        if let qIdx = path.firstIndex(of: "?") {
            let query = String(path[path.index(after: qIdx)...])
            var w: Int? = nil, h: Int? = nil
            for pair in query.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                guard kv.count == 2 else { continue }
                let key = kv[0].lowercased()
                let val = Int(kv[1].split(separator: ",").first ?? "")
                guard let val else { continue }
                if key == "w" || key == "width" { w = val }
                if key == "h" || key == "height" { h = val }
            }
            if let w, let h, w > 0, h > 0 { return (w, h) }
        }
        // WxH embedded in the path: /images/300x200/cat.jpg or _300x200.
        if let match = path.range(of: #"(\d{1,5})x(\d{1,5})"#, options: .regularExpression),
           match.upperBound < path.endIndex || match.upperBound == path.endIndex {
            let parts = path[match].split(separator: "x")
            if parts.count == 2, let w = Int(parts[0]), let h = Int(parts[1]),
               w > 0, h > 0, w <= 10000, h <= 10000 {
                return (w, h)
            }
        }
        return nil
    }
}

// MARK: - Chunked transfer decoding

/// One-shot decoder for `Transfer-Encoding: chunked` bodies. Returns nil
/// when the stream is incomplete or malformed — callers use it both to
/// dechunk and to test completeness.
public enum ChunkedDecoder {
    /// Decode a complete chunked body. Returns nil if incomplete/invalid.
    public static func decode(_ data: Data) -> Data? {
        var pos = 0
        var out = Data()
        let bytes = [UInt8](data)
        while true {
            // Read the chunk-size line up to CRLF.
            guard let lineEnd = findCRLF(bytes, from: pos) else { return nil }
            guard let line = String(bytes: bytes[pos..<lineEnd], encoding: .utf8) else { return nil }
            let sizePart = line.split(separator: ";").first.map(String.init) ?? line
            guard let size = Int(sizePart.trimmingCharacters(in: .whitespaces), radix: 16) else {
                return nil
            }
            pos = lineEnd + 2

            if size == 0 {
                // Terminal chunk: consume optional trailer headers until an
                // empty line. "0\r\n\r\n" is the common shape.
                while true {
                    guard let tEnd = findCRLF(bytes, from: pos) else { return nil }
                    if tEnd == pos { return out }        // empty line — done
                    pos = tEnd + 2                        // skip trailer line
                }
            }

            guard pos + size + 2 <= bytes.count else { return nil }
            out.append(contentsOf: bytes[pos..<(pos + size)])
            guard bytes[pos + size] == 0x0D, bytes[pos + size + 1] == 0x0A else { return nil }
            pos += size + 2
        }
    }

    /// True when `data` contains a complete chunked stream.
    public static func isComplete(_ data: Data) -> Bool {
        decode(data) != nil
    }

    private static func findCRLF(_ bytes: [UInt8], from pos: Int) -> Int? {
        var i = pos
        while i + 1 < bytes.count {
            if bytes[i] == 0x0D && bytes[i + 1] == 0x0A { return i }
            i += 1
        }
        return nil
    }
}

// MARK: - Incremental response buffering

/// How a response body is framed on the wire.
public enum ResponseFraming: Equatable, Sendable {
    /// No body (HEAD, 204, 304, 1xx).
    case none
    /// Content-Length bounded.
    case length(Int)
    /// Transfer-Encoding: chunked.
    case chunked
    /// Body runs until the connection closes.
    case untilClose
}

/// Accumulates raw response bytes, parses the head as soon as it arrives
/// (so the proxy can decide rewrite-vs-stream early), and reports when the
/// full body has been received per the framing. Used by TransparentProxy.
public final class ResponseBuffer {
    /// All bytes received so far (head + body together).
    public private(set) var raw = Data()
    /// Parsed response head, once complete.
    public private(set) var head: HTTPResponseParser.ParsedResponse?
    /// Offset in `raw` where the body begins.
    public private(set) var bodyStart = 0
    /// Body framing derived from the head.
    public private(set) var framing: ResponseFraming?

    public init() {}

    public var headComplete: Bool { head != nil }

    /// The raw status line, for rebuilding a rewritten response.
    public var statusLine: String {
        guard let head else { return "HTTP/1.1 200 OK" }
        return ResponseRewriter.statusLine(of: head.rawHead)
    }

    /// Append bytes; parses the head when possible.
    public func append(_ chunk: Data) {
        raw.append(chunk)
        if head == nil { tryParseHead() }
    }

    private func tryParseHead() {
        guard let end = HTTPRequestParser.findHeaderEnd(in: raw),
              let parsed = HTTPResponseParser.parse(raw) else { return }
        head = parsed
        bodyStart = end + 4
        framing = Self.framing(for: parsed, method: nil)
    }

    /// Recompute framing knowing the request method (HEAD → no body).
    public func noteRequestMethod(_ method: String) {
        guard let head else { return }
        framing = Self.framing(for: head, method: method)
    }

    static func framing(for resp: HTTPResponseParser.ParsedResponse,
                        method: String?) -> ResponseFraming {
        if method?.uppercased() == "HEAD" { return .none }
        if resp.status == 204 || resp.status == 304
            || (100..<200).contains(resp.status) { return .none }
        if let te = ResponseRewriter.headerValue(resp.headers, "Transfer-Encoding"),
           te.lowercased().contains("chunked") { return .chunked }
        if let cl = ResponseRewriter.headerValue(resp.headers, "Content-Length"),
           let n = Int(cl.trimmingCharacters(in: .whitespaces)) { return .length(n) }
        return .untilClose
    }

    /// Body bytes received so far (still chunked-encoded when applicable).
    public var bodyBytes: Data {
        guard bodyStart > 0, raw.count > bodyStart else { return Data() }
        return raw.subdata(in: bodyStart..<raw.count)
    }

    /// True when the full body is in `raw`. `eof` = origin closed the
    /// connection (needed for `.untilClose` framing).
    public func isComplete(eof: Bool) -> Bool {
        guard let framing else { return false }
        switch framing {
        case .none: return true
        case .length(let n): return bodyBytes.count >= n
        case .chunked: return ChunkedDecoder.isComplete(bodyBytes)
        case .untilClose: return eof
        }
    }

    /// The decoded body (dechunked / length-sliced), or nil if incomplete.
    public var decodedBody: Data? {
        guard let framing, let head else { return nil }
        let b = bodyBytes
        switch framing {
        case .none: return Data()
        case .length(let n):
            guard b.count >= n else { return nil }
            return Data(b.prefix(n))
        case .chunked:
            return ChunkedDecoder.decode(b)
        case .untilClose:
            return b
        }
    }
}

import Foundation
import PastoralCore

// MARK: - Injection engine (proxy-side, hot-swappable)
//
// Holds the active InjectionRule and the pool of prepared images. All
// connections share one engine; the app reconfigures it live (button on/
// off, new image picked) without restarting the proxy. Thread-safe.

/// Optional hook so the app can resize the injected image to the
/// dimensions the page expects. Kept as a closure so PastoralProxy stays
/// free of ImageIO/CoreGraphics dependencies.
public typealias ImageResizer = @Sendable (PreparedImage, _ width: Int, _ height: Int) -> PreparedImage?

public final class InjectionEngine: @unchecked Sendable {
    private let lock = NSLock()
    private var rule: InjectionRule
    private let pool = ImagePool()

    /// Called to resize the injected image to the expected dimensions when
    /// `rule.preserveDimensions` is set and the request URL carries a hint.
    public var resizer: ImageResizer?

    public init(rule: InjectionRule = InjectionRule(enabled: false),
                images: [PreparedImage] = []) {
        self.rule = rule
        self.pool.update(images)
    }

    /// Replace rule and image pool atomically.
    public func configure(rule: InjectionRule, images: [PreparedImage]) {
        lock.lock()
        self.rule = rule
        lock.unlock()
        pool.update(images)
    }

    /// Turn rewriting off (keeps the pool so re-enabling is instant).
    public func disable() {
        lock.lock()
        rule.enabled = false
        lock.unlock()
    }

    public var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return rule.enabled && !pool.isEmpty
    }

    /// Early decision, made as soon as the response head is parsed —
    /// before the body is buffered. Cheaper than building the rewrite.
    public func shouldRewrite(clientIP: String?, host: String, path: String,
                              responseHeaders: [String: String]) -> Bool {
        lock.lock()
        let r = rule
        lock.unlock()
        guard r.enabled, !pool.isEmpty else { return false }
        return ResponseRewriter.shouldRewrite(rule: r, clientIP: clientIP,
                                              host: host, path: path,
                                              responseHeaders: responseHeaders)
    }

    /// Produce the rewritten wire bytes for a fully-buffered response.
    /// Returns nil if the rule doesn't match or the pool is empty.
    public func rewrite(clientIP: String?, host: String, path: String,
                        buffer: ResponseBuffer) -> Data? {
        lock.lock()
        let r = rule
        lock.unlock()
        guard let head = buffer.head else { return nil }
        guard ResponseRewriter.shouldRewrite(rule: r, clientIP: clientIP,
                                             host: host, path: path,
                                             responseHeaders: head.headers) else { return nil }

        var image = pool.next(rotate: r.rotate)
        // Optional dimension matching: resize the injected image to the
        // width/height the page expected (parsed from the request URL).
        if r.preserveDimensions,
           let dims = ResponseRewriter.expectedDimensions(from: path),
           let img = image,
           let resizer,
           let resized = resizer(img, dims.width, dims.height) {
            image = resized
        }
        guard let body = image else { return nil }

        return ResponseRewriter.rewriteResponse(statusLine: buffer.statusLine,
                                                headers: head.headers,
                                                body: body)
    }
}

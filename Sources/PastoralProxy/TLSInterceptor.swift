import Foundation
import Network
import Security
import PastoralCore

// MARK: - TLS termination (MITM)
//
// Transparently-redirected HTTPS arrives as a raw TLS ClientHello (no
// CONNECT — the client thinks it reached the origin). We peek the SNI,
// build a SecIdentity from the CA's leaf cert, and terminate TLS on a
// throwaway NWListener bound to 127.0.0.1. The client connection is then
// pumped byte-for-byte through a second NWConnection into that listener,
// which performs the handshake and hands us decrypted HTTP/1.1 (ALPN is
// pinned to http/1.1 so no HTTP/2 reaches the parser). The decrypted
// request follows the same forward/capture/rewrite path as plain HTTP;
// the origin side is a normal verified TLS connection.
//
// If identity creation or the listener fails we fall back to tunneling
// (CONNECT-mode only, where the origin is known) or drop.
//
// Diagnostics: each interception carries a TLSHandshakeProbe that watches
// the bytes flowing back toward the victim for TLS alert records and
// tracks whether the listener ever accepted a connection (= handshake
// succeeded). The probe emits the DiagEvent when the outcome is known.

/// Per-interception handshake tracker. Thread-safe via its own lock.
final class TLSHandshakeProbe: @unchecked Sendable {
    let clientIP: String?
    let sni: String?
    let hello: ClientHelloInfo?
    private let emit: (DiagEvent) -> Void
    private let lock = NSLock()
    private var succeeded = false
    private var alert: TLSAlert?
    private var done = false

    init(clientIP: String?, sni: String?, hello: ClientHelloInfo?,
         emit: @escaping (DiagEvent) -> Void) {
        self.clientIP = clientIP; self.sni = sni; self.hello = hello
        self.emit = emit
    }

    /// The TLS listener accepted a connection — handshake completed.
    func handshakeSucceeded(negotiated: String? = nil) {
        lock.lock()
        guard !done else { lock.unlock(); return }
        succeeded = true; done = true
        lock.unlock()
        emit(DiagEvent(
            clientIP: clientIP, sni: sni,
            negotiated: negotiated ?? "TLS",
            fingerprint: hello?.summary, ja3: hello?.ja3, alpn: hello?.alpn,
            outcome: "handshake_ok", category: .ok))
    }

    /// Bytes flowing back toward the victim — look for TLS alert records.
    func observeServerRecord(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !succeeded else { return }
        if let a = TLSAlert.parse(data) { alert = a }
    }

    /// The client connection ended. If the handshake never completed,
    /// classify why.
    func clientClosed() {
        lock.lock()
        guard !done else { lock.unlock(); return }
        done = true
        let seenAlert = alert
        lock.unlock()

        if let a = seenAlert {
            emit(DiagEvent(
                clientIP: clientIP, sni: sni,
                fingerprint: hello?.summary, ja3: hello?.ja3, alpn: hello?.alpn,
                outcome: "alert:\(a.descriptionName)",
                detail: "TLS alert \(a.descriptionName) (level \(a.level.rawValue))",
                category: DiagClassifier.classify(alert: a)))
        } else if !succeeded {
            // Client dropped TCP right after seeing our certificate —
            // no alert. Classic app-level pinning behavior.
            emit(DiagEvent(
                clientIP: clientIP, sni: sni,
                fingerprint: hello?.summary, ja3: hello?.ja3, alpn: hello?.alpn,
                outcome: "closed_after_hello",
                detail: "conexão caiu após o ServerHello sem alerta TLS",
                category: .pinning))
        }
    }
}

extension TransparentProxy {

    /// True when the first bytes look like a TLS handshake record.
    func looksLikeTLS(_ data: Data) -> Bool {
        data.count >= 5 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04
    }

    /// Intercept a TLS connection whose first bytes are `initialData` (a
    /// ClientHello). `originHint` carries the CONNECT target when the
    /// client spoke to us as an explicit proxy; nil for rdr'd traffic,
    /// where the SNI is the only routing information.
    ///
    /// In CONNECT mode the "200 Connection Established" (or a 502 when the
    /// flow can't go through) is sent only once we know the outcome —
    /// never before the ClientHello was read and the termination path is
    /// set up, so a dead origin yields a clean 502 instead of a
    /// half-open tunnel.
    func interceptTLS(clientConn: NWConnection, initialData: Data,
                      originHint: (host: String, port: UInt16)?,
                      requestHeaders: [String: String] = [:]) {
        let connectMode = originHint != nil
        @Sendable func announceConnect(status: Int = 200) {
            guard connectMode else { return }
            let line = status == 200
                ? "HTTP/1.1 200 Connection Established\r\n\r\n"
                : "HTTP/1.1 502 Bad Gateway\r\n\r\n"
            clientConn.send(content: Data(line.utf8),
                            completion: .contentProcessed { _ in })
        }
        let hello = ClientHelloInfo.parse(initialData)
        let sni = hello?.sni ?? extractSNI(from: initialData) ?? originHint?.host
        guard let sni, !sni.isEmpty else {
            // No SNI and no CONNECT hint — we don't know the origin.
            onCapture(CapturedExchange(
                host: originHint?.host ?? "unknown", method: "CONNECT",
                path: "/", requestHeaders: requestHeaders,
                isTLS: true, sni: nil))
            emitDiag(DiagEvent(
                clientIP: clientIP(of: clientConn),
                fingerprint: hello?.summary, ja3: hello?.ja3, alpn: hello?.alpn,
                outcome: "no_sni", detail: "ClientHello sem SNI",
                category: .other))
            if let hint = originHint {
                // Explicit proxy with a target despite the missing SNI —
                // tunnel blindly so the session at least gets through.
                announceConnect()
                tunnelToOrigin(clientConn: clientConn, initialData: initialData,
                               target: hint)
            } else {
                announceConnect(status: 502)   // no-op fora do CONNECT
                clientConn.cancel()
            }
            return
        }

        onCapture(CapturedExchange(
            host: sni, method: "CONNECT", path: "/",
            requestHeaders: requestHeaders,
            isTLS: true, sni: sni))

        // Transparent mode (no CA): tunnel the flow to the real origin —
        // the ClientHello we already consumed is replayed upstream and
        // bytes pump both ways. The victim's HTTPS keeps working; only
        // the SNI is observable.
        guard caManager != nil else {
            announceConnect()
            tunnelToOrigin(clientConn: clientConn, initialData: initialData,
                           target: originHint ?? (host: sni, port: 443))
            return
        }

        let victimIP = clientIP(of: clientConn)
        let probe = TLSHandshakeProbe(
            clientIP: victimIP, sni: sni, hello: hello) { [weak self] e in
            self?.emitDiag(e)
        }

        guard let listener = makeTLSListener(
                sni: sni, victimIP: victimIP, hello: hello, probe: probe)
        else {
            // Termination failed even with a CA — anomaly worth logging;
            // still tunnel so the victim's connection isn't dropped.
            emitDiag(DiagEvent(
                clientIP: victimIP, sni: sni,
                fingerprint: hello?.summary, ja3: hello?.ja3, alpn: hello?.alpn,
                outcome: "no_identity",
                detail: "falha ao criar identidade/listener TLS",
                category: .other))
            announceConnect()
            tunnelToOrigin(clientConn: clientConn, initialData: initialData,
                           target: originHint ?? (host: sni, port: 443))
            return
        }

        // Track the listener so stop() cancels it and it outlives this
        // function's scope.
        tlsListenerLock.lock()
        tlsListeners.append(listener)
        tlsListenerLock.unlock()

        // When the listener is ready, open a plain-TCP connection into it
        // and pump: client bytes (starting with the ClientHello) flow into
        // the TLS listener; decrypted HTTP comes back out. The probe
        // inspects what flows back for TLS alerts; when the client goes
        // away it classifies the outcome.
        listener.stateUpdateHandler = { [weak self, weak clientConn] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard let port = listener.port, let clientConn else { return }
                // Infrastructure ready — only now tell the client the
                // tunnel is established, so this is a real 200: the leaf
                // identity exists and the terminating listener is up.
                announceConnect()
                let inner = NWConnection(host: "127.0.0.1", port: port,
                                         using: .tcp)
                inner.start(queue: self.queue)
                inner.send(content: initialData,
                           completion: .contentProcessed { _ in })
                // inner → client: carries TLS records back (alerts too).
                self.forwardData(from: inner, to: clientConn) { data in
                    probe.observeServerRecord(data)
                }
                // client → inner: isComplete/error here means the victim
                // went away — decide the diagnosis.
                clientConn.receive(minimumIncompleteLength: 1,
                                   maximumLength: 65536) {
                    [weak self] data, _, isComplete, error in
                    guard let self else { return }
                    if let data, !data.isEmpty {
                        inner.send(content: data,
                                   completion: .contentProcessed { _ in })
                    }
                    if isComplete || error != nil {
                        probe.clientClosed()
                        clientConn.cancel()
                        inner.cancel()
                    } else {
                        self.pumpClientToInner(clientConn, inner, probe)
                    }
                }
            case .failed:
                probe.clientClosed()
                announceConnect(status: 502)   // no-op fora do CONNECT
                clientConn?.cancel()
                fallthrough
            case .cancelled:
                self.tlsListenerLock.lock()
                self.tlsListeners.removeAll { $0 === listener }
                self.tlsListenerLock.unlock()
            default:
                break
            }
        }
        listener.start(queue: queue)
    }

    /// Continuation of the client→inner pump (kept separate so the probe
    /// can be captured without re-stating the receive callback).
    private func pumpClientToInner(_ clientConn: NWConnection,
                                   _ inner: NWConnection,
                                   _ probe: TLSHandshakeProbe) {
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                inner.send(content: data,
                           completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                probe.clientClosed()
                clientConn.cancel()
                inner.cancel()
            } else {
                self.pumpClientToInner(clientConn, inner, probe)
            }
        }
    }

    /// Tunnel a TLS flow to the real origin without terminating it.
    /// Replays `initialData` (the ClientHello already read from the
    /// client) upstream, then pumps bytes in both directions. Used in
    /// transparent mode (no CA) and as a fallback when termination fails.
    private func tunnelToOrigin(clientConn: NWConnection, initialData: Data,
                                target: (host: String, port: UInt16)) {
        let originConn = NWConnection(
            host: NWEndpoint.Host(target.host),
            port: NWEndpoint.Port(integerLiteral: target.port),
            using: .tcp)
        originConn.start(queue: queue)
        originConn.send(content: initialData,
                        completion: .contentProcessed { _ in })
        tunnel(clientConn: clientConn, originConn: originConn)
    }

    /// A one-shot TLS listener for a single intercepted connection.
    /// Terminates TLS with the leaf identity for `sni`; the single accepted
    /// connection carries decrypted HTTP/1.1 which is parsed and forwarded
    /// to the real origin over TLS.
    private func makeTLSListener(sni: String, victimIP: String?,
                                 hello: ClientHelloInfo?,
                                 probe: TLSHandshakeProbe) -> NWListener? {
        guard let caManager else { return nil }
        do {
            let identity = try caManager.secIdentity(for: sni)
            let tlsOpts = NWProtocolTLS.Options()
            guard let secID = sec_identity_create(identity) else { return nil }
            sec_protocol_options_set_local_identity(
                tlsOpts.securityProtocolOptions, secID)
            // Only offer http/1.1 — the decrypted stream must stay h1.
            // (Clients offering h2 negotiate down to h1; an h2-obsessed
            // client that refuses will fail the handshake and be logged.)
            sec_protocol_options_add_tls_application_protocol(
                tlsOpts.securityProtocolOptions, "http/1.1")

            let params = NWParameters(tls: tlsOpts)
            params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            let listener = try NWListener(using: params)
            listener.newConnectionLimit = 1
            listener.newConnectionHandler = { [weak self, weak listener] innerConn in
                guard let self else { innerConn.cancel(); return }
                // One-shot listener: its only job was this connection.
                // Cancelling stops listening but keeps the accepted conn.
                listener?.cancel()
                innerConn.start(queue: self.queue)

                // Handshake succeeded — read the negotiated protocol for
                // the diagnostic event (best-effort; may be nil).
                var negotiated = "TLS"
                if let meta = innerConn.metadata(definition: NWProtocolTLS.definition)
                        as? NWProtocolTLS.Metadata {
                    let v = sec_protocol_metadata_get_negotiated_tls_protocol_version(
                        meta.securityProtocolMetadata)
                    negotiated = String(describing: v)
                }
                probe.handshakeSucceeded(negotiated: negotiated)

                innerConn.receive(minimumIncompleteLength: 1,
                                  maximumLength: 65536) { data, _, _, error in
                    guard let data, error == nil else {
                        innerConn.cancel()
                        return
                    }
                    // Decrypted HTTP/1.1 — parse and forward to the real
                    // origin over TLS (SNI:443).
                    self.handlePlainHTTP(
                        clientConn: innerConn, initialData: data,
                        tlsOrigin: (sni: sni, clientIP: victimIP,
                                    hello: hello, probe: probe))
                }
            }
            return listener
        } catch {
            return nil
        }
    }
}

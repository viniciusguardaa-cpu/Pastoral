import Foundation

// MARK: - TLS handshake probe
//
// Lightweight hook the proxy uses to record when a TLS handshake
// succeeds. The concrete implementation lives in the proxy layer;
// this protocol keeps PastoralCore free of Network.framework deps.

/// A probe that records TLS handshake outcomes for diagnostics.
public protocol TLSHandshakeProbe: Sendable {
    /// Called by the proxy when the TLS handshake with the origin
    /// completes successfully.
    func handshakeSucceeded()
}

// MARK: - Interception diagnosis
//
// Structured per-connection events emitted by the proxy in diagnostic
// mode, written as JSONL so `Scripts/diagnose.sh` can classify failures
// per target domain. The categories answer "why is HTTPS interception
// broken for this host" — the single most useful debugging output for
// a MITM tool.

/// Why an intercepted connection failed (or succeeded).
public enum DiagCategory: String, Codable, Sendable, CaseIterable {
    case ok = "OK"
    /// Client saw our cert, sent unknown_ca/bad_certificate alert.
    case caNotTrusted = "CA_NAO_CONFIA"
    /// Client killed the connection after the cert without a TLS alert —
    /// it validated and rejected silently (app-level pinning).
    case pinning = "PINNING"
    /// Handshake OK but origin refused/dropped early — origin likely
    /// detected our TLS fingerprint.
    case fingerprint = "FINGERPRINT"
    /// QUIC/UDP-443 traffic seen but no TCP/443 connection ever arrived.
    case quicInvisible = "QUIC_INVISIVEL"
    /// HTTP/2 frames or h2 preface on a path we terminate as h1.
    case http2Reset = "HTTP2_RESET"
    case other = "OUTRO"
}

/// What the user should do about a classified failure.
public func diagSuggestion(_ cat: DiagCategory) -> String {
    switch cat {
    case .ok: return "—"
    case .caNotTrusted:
        return "Instale a CA Pastoral na trust store do alvo (system store em Android/iOS para apps nativos)."
    case .pinning:
        return "O app fixa o certificado — aplique bypass de pinning (Frida unpin.js / LSPosed) ou aceite que esse domínio não é interceptável."
    case .fingerprint:
        return "Ative o espelhamento de fingerprint TLS (mirror) ou verifique se o servidor exige h2/h3."
    case .quicInvisible:
        return "Ative force_tcp_fallback (bloqueio UDP/443 no anchor sheep) para forçar o cliente a TLS/TCP."
    case .http2Reset:
        return "O cliente insiste em h2 — verifique ALPN no listener e se o cliente aceita downgrade para http/1.1."
    case .other:
        return "Inspecione o log verboso da conexão para detalhes."
    }
}

/// One diagnostic event: a TLS/HTTP connection attempt through the proxy.
public struct DiagEvent: Codable, Sendable {
    public var ts: TimeInterval = Date().timeIntervalSince1970
    public var clientIP: String?
    public var sni: String?
    /// Negotiated protocol, e.g. "TLS1.3/http/1.1".
    public var negotiated: String?
    /// Client fingerprint summary (JA3 + counts).
    public var fingerprint: String?
    /// ja3 hash alone, for grouping.
    public var ja3: String?
    /// ALPN protocols the client offered — browsers always list h2;
    /// native apps often don't (used by the user-store heuristic).
    public var alpn: [String]?
    /// Raw outcome: "handshake_ok", "alert:unknown_ca", "closed_after_hello",
    /// "quic_seen", "h2_preface", "origin_reset"…
    public var outcome: String
    public var detail: String?
    public var category: DiagCategory

    public init(clientIP: String? = nil, sni: String? = nil,
                negotiated: String? = nil, fingerprint: String? = nil,
                ja3: String? = nil, alpn: [String]? = nil,
                outcome: String,
                detail: String? = nil, category: DiagCategory) {
        self.clientIP = clientIP; self.sni = sni
        self.negotiated = negotiated; self.fingerprint = fingerprint
        self.ja3 = ja3; self.alpn = alpn; self.outcome = outcome
        self.detail = detail; self.category = category
    }
}

/// Maps a raw outcome to a category. Pure logic — unit-tested.
public enum DiagClassifier {
    public static func classify(outcome: String, alert: TLSAlert? = nil) -> DiagCategory {
        switch outcome {
        case "handshake_ok": return .ok
        case "quic_seen": return .quicInvisible
        case "h2_preface", "h2_reset": return .http2Reset
        case "origin_reset", "origin_4xx": return .fingerprint
        case "closed_after_hello": return .pinning
        case let s where s.hasPrefix("alert:"):
            // Explicit TLS alert back to our forged cert → distrust.
            // (A pinning app usually just drops the TCP without alerting.)
            return .caNotTrusted
        default: return .other
        }
    }

    /// Classify an alert we saw flowing back to the client side.
    public static func classify(alert: TLSAlert) -> DiagCategory {
        switch alert.code {
        case 42, 46, 48, 49, 116: // cert-related rejections
            return .caNotTrusted
        case 0, 90:               // close_notify / user_canceled
            return .pinning
        case 70, 109:             // protocol_version / missing_extension
            return .fingerprint
        default:
            return .other
        }
    }
}

/// Appends DiagEvents as JSONL. One line per event — diagnose.sh reads
/// this file and aggregates per domain. Thread-safe, buffered-free.
public final class DiagLog: @unchecked Sendable {
    public let path: String
    private let lock = NSLock()
    private let encoder = JSONEncoder()

    public static var defaultPath: String {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/Pastoral")
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("diagnose.jsonl").path
    }

    public init(path: String = DiagLog.defaultPath) {
        self.path = path
    }

    public func record(_ event: DiagEvent) {
        guard let line = try? encoder.encode(event) else { return }
        lock.lock(); defer { lock.unlock() }
        if let h = FileHandle(forWritingAtPath: path) {
            h.seekToEndOfFile(); h.write(line); h.write("\n".data(using: .utf8)!)
            try? h.close()
        } else {
            try? (line + "\n".data(using: .utf8)!).write(
                to: URL(fileURLWithPath: path))
        }
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(atPath: path)
    }
}

import Foundation
import Darwin
import PastoralCore

/// Client for the privileged helper over the Unix socket at
/// /var/run/pastoral.sock. Speaks line-delimited JSON (one request per
/// line, one response per line). Uses POSIX sockets on a background queue
/// so the UI never blocks. The proxy (step 5) uses Network.framework; the
/// helper control channel is intentionally simpler.
actor HelperClient {
    // Default socket lives in /var/run (needs root). For local testing
    // without the helper installed, override with PASTORAL_SOCKET.
    static let socketPath =
        ProcessInfo.processInfo.environment["PASTORAL_SOCKET"] ?? "/var/run/pastoral.sock"

    private var fd: Int32 = -1
    /// Dedicated connection for QUIC observation streaming. Separate from
    /// `fd` so the regular request/response channel is not blocked while
    /// observations arrive.
    private var quicFd: Int32 = -1
    private var quicThread: Thread?
    /// Dedicated connection for mDNS/LLMNR observation streaming.
    private var mdnsFd: Int32 = -1
    private var mdnsThread: Thread?
    /// Dedicated connection for Wi-Fi key (hcx) observation streaming.
    private var hcxFd: Int32 = -1
    private var hcxThread: Thread?

    /// Open a connection to the helper. Throws if the socket is absent or
    /// the connection is refused (helper not installed / not running).
    func connect() throws {
        if fd >= 0 { return }
        // The launchd-owned socket can be briefly unwritable right after
        // the daemon (re)starts while our ownership refresh runs; retry a
        // few times before giving up.
        var lastErr: Int32 = 0
        for attempt in 0..<3 {
            let s = socket(AF_UNIX, SOCK_STREAM, 0)
            guard s >= 0 else { throw HelperClientError.socketFailed(errno) }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var noSignal: Int32 = 1
            setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            Self.socketPath.withCString { path in
                withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                    let count = min(strlen(path), buf.count - 1)
                    buf.copyBytes(from: UnsafeRawBufferPointer(start: path, count: count))
                }
            }
            let r = withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(s, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if r == 0 {
                fd = s
                return
            }
            lastErr = errno
            Darwin.close(s)
            if attempt < 2 { Thread.sleep(forTimeInterval: 0.4) }
        }
        throw HelperClientError.connectFailed(lastErr)
    }

    /// Send a request and await the single-line response.
    func send(_ request: HelperRequest) async throws -> HelperResponse {
        try connect()
        defer { Darwin.close(fd); fd = -1 }
        let data = try LineCodec.encode(request)
        writeAll(data)
        guard let line = readLine() else {
            throw HelperClientError.noResponse
        }
        return try LineCodec.decode(line, as: HelperResponse.self)
    }

    /// Convenience: probe liveness + status. Returns nil if the helper is
    /// unreachable (so callers can mark it offline without try/catch noise).
    func status() async -> HelperStatus? {
        do {
            let res = try await send(.status)
            switch res {
            case .statusReport(let forwarding, let interface, let bpf):
                return HelperStatus(responding: true, forwarding: forwarding,
                                     bpfAccessible: bpf, interface: interface)
            default:
                return nil
            }
        } catch {
            return nil
        }
    }

    func close() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
        stopQUICCapture()
        stopMDNSCapture()
        stopHCXCapture()
    }

    // MARK: - QUIC observation streaming

    /// Start passive QUIC/HTTP3 sniffing on `interface`. The first line
    /// back from the helper is the `ok`/`error` acknowledgement; subsequent
    /// lines are `quicObservation` events, delivered to `handler` on a
    /// background thread. Returns the acknowledgement (or throws).
    func startQUICCapture(interface: String,
                          handler: @escaping @Sendable (QUICObservation) -> Void) async throws -> HelperResponse {
        // Open a dedicated connection for the stream.
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw HelperClientError.socketFailed(errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        Self.socketPath.withCString { path in
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                let count = min(strlen(path), buf.count - 1)
                buf.copyBytes(from: UnsafeRawBufferPointer(start: path, count: count))
            }
        }
        let r = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(s, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if r != 0 { let err = errno; Darwin.close(s); throw HelperClientError.connectFailed(err) }
        quicFd = s

        // Send quicStart on this connection.
        let data = try LineCodec.encode(HelperRequest.quicStart(interface: interface))
        Self.writeAllTo(fd: s, data)
        guard let line = Self.readLineFrom(fd: s) else {
            throw HelperClientError.noResponse
        }
        let ack = try LineCodec.decode(line, as: HelperResponse.self)
        guard case .ok = ack else { return ack }

        // Spawn a reader thread for the observation stream.
        let t = Thread {
            while true {
                guard let obsLine = Self.readLineFrom(fd: s) else { break }
                guard let resp = try? LineCodec.decode(obsLine, as: HelperResponse.self) else { continue }
                if case .quicObservation(let src, let dst, let sni, let alpn, let ver) = resp {
                    handler(QUICObservation(sourceIP: src, destIP: dst, sni: sni, alpn: alpn, version: ver))
                }
            }
        }
        t.name = "pastoral.quic.client"
        t.start()
        quicThread = t
        return ack
    }

    /// Stop QUIC sniffing: send `quicStop` on the main control channel and
    /// close the streaming connection (which ends the reader thread).
    func stopQUICCapture() {
        if quicFd >= 0 {
            // Send quicStop on the streaming connection itself so the helper
            // stops writing to it before we close it.
            if let data = try? LineCodec.encode(HelperRequest.quicStop) {
                Self.writeAllTo(fd: quicFd, data)
            }
            shutdown(quicFd, SHUT_RDWR)
            Darwin.close(quicFd)
            quicFd = -1
        }
        quicThread = nil
    }

    // MARK: - mDNS/LLMNR observation streaming

    /// Start passive mDNS/LLMNR sniffing on `interface`. Observations are
    /// delivered to `handler` on a background thread.
    func startMDNSCapture(interface: String,
                          handler: @escaping @Sendable (MDNSObservation) -> Void) async throws -> HelperResponse {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw HelperClientError.socketFailed(errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        Self.socketPath.withCString { path in
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                let count = min(strlen(path), buf.count - 1)
                buf.copyBytes(from: UnsafeRawBufferPointer(start: path, count: count))
            }
        }
        let r = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(s, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if r != 0 { let err = errno; Darwin.close(s); throw HelperClientError.connectFailed(err) }
        mdnsFd = s

        let data = try LineCodec.encode(HelperRequest.mdnsStart(interface: interface))
        Self.writeAllTo(fd: s, data)
        guard let line = Self.readLineFrom(fd: s) else {
            throw HelperClientError.noResponse
        }
        let ack = try LineCodec.decode(line, as: HelperResponse.self)
        guard case .ok = ack else { return ack }

        let t = Thread {
            while true {
                guard let obsLine = Self.readLineFrom(fd: s) else { break }
                guard let resp = try? LineCodec.decode(obsLine, as: HelperResponse.self) else { continue }
                if case .mdnsObservation(let src, let stype, let inst, let host, let port, let addrs) = resp {
                    handler(MDNSObservation(sourceIP: src, serviceType: stype, instance: inst,
                                            hostname: host, port: port, addresses: addrs))
                }
            }
        }
        t.name = "pastoral.mdns.client"
        t.start()
        mdnsThread = t
        return ack
    }

    /// Stop mDNS/LLMNR sniffing and close the streaming connection.
    func stopMDNSCapture() {
        if mdnsFd >= 0 {
            if let data = try? LineCodec.encode(HelperRequest.mdnsStop) {
                Self.writeAllTo(fd: mdnsFd, data)
            }
            shutdown(mdnsFd, SHUT_RDWR)
            Darwin.close(mdnsFd)
            mdnsFd = -1
        }
        mdnsThread = nil
    }

    // MARK: - Wi-Fi key (hcx) observation streaming

    /// Start Wi-Fi key capture ("caça-senha") on the helper. The first
    /// line back is the ok/error acknowledgement; subsequent lines are
    /// `hcxCapture` observations delivered to `handler` on a background
    /// thread. `seconds == 0` captures until `stopHCXCapture()`.
    func startHCXCapture(interface: String, essid: String, bssid: String,
                         seconds: Int,
                         handler: @escaping @Sendable (WpaCapture) -> Void) async throws -> HelperResponse {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw HelperClientError.socketFailed(errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        Self.socketPath.withCString { path in
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                let count = min(strlen(path), buf.count - 1)
                buf.copyBytes(from: UnsafeRawBufferPointer(start: path, count: count))
            }
        }
        let r = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(s, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if r != 0 { let err = errno; Darwin.close(s); throw HelperClientError.connectFailed(err) }
        hcxFd = s

        let data = try LineCodec.encode(HelperRequest.hcxStart(
            interface: interface, essid: essid, bssid: bssid, seconds: seconds))
        Self.writeAllTo(fd: s, data)
        guard let line = Self.readLineFrom(fd: s) else {
            throw HelperClientError.noResponse
        }
        let ack = try LineCodec.decode(line, as: HelperResponse.self)
        guard case .ok = ack else { return ack }

        let t = Thread {
            while true {
                guard let obsLine = Self.readLineFrom(fd: s) else { break }
                guard let resp = try? LineCodec.decode(obsLine, as: HelperResponse.self) else { continue }
                if case .hcxCapture(let cap) = resp { handler(cap) }
            }
        }
        t.name = "pastoral.hcx.client"
        t.start()
        hcxThread = t
        return ack
    }

    /// Stop the key hound and close the streaming connection.
    func stopHCXCapture() {
        if hcxFd >= 0 {
            if let data = try? LineCodec.encode(HelperRequest.hcxStop) {
                Self.writeAllTo(fd: hcxFd, data)
            }
            shutdown(hcxFd, SHUT_RDWR)
            Darwin.close(hcxFd)
            hcxFd = -1
        }
        hcxThread = nil
    }

    deinit { if fd >= 0 { Darwin.close(fd) } }

    // MARK: - I/O

    private func writeAll(_ data: Data) { Self.writeAllTo(fd: fd, data) }

    private func readLine() -> String? { Self.readLineFrom(fd: fd) }

    nonisolated private static func writeAllTo(fd: Int32, _ data: Data) {
        data.withUnsafeBytes { raw in
            var remaining = raw.count
            var ptr = raw.baseAddress!
            while remaining > 0 {
                let written = Darwin.write(fd, ptr, remaining)
                if written <= 0 {
                    if errno == EINTR { continue }
                    return
                }
                ptr = ptr.advanced(by: written)
                remaining -= written
            }
        }
    }

    nonisolated private static func readLineFrom(fd: Int32) -> String? {
        var buffer = Data()
        var byte: UInt8 = 0
        while true {
            let n = Darwin.read(fd, &byte, 1)
            if n == 0 { return buffer.isEmpty ? nil : String(data: buffer, encoding: .utf8) }
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if byte == 0x0A { break }
            buffer.append(byte)
        }
        return String(data: buffer, encoding: .utf8)
    }
}

/// A decoded QUIC observation delivered to the app.
struct QUICObservation: Sendable, Identifiable {
    let sourceIP: String
    let destIP: String
    let sni: String?
    let alpn: [String]
    let version: UInt32
    let id = UUID()
}

/// A decoded mDNS/LLMNR observation delivered to the app.
struct MDNSObservation: Sendable, Identifiable {
    let sourceIP: String
    let serviceType: String
    let instance: String
    let hostname: String?
    let port: UInt16?
    let addresses: [String]
    let id = UUID()
}

enum HelperClientError: Error, LocalizedError {
    case socketFailed(Int32)
    case connectFailed(Int32)
    case noResponse

    var errorDescription: String? {
        switch self {
        case .socketFailed(let e): return "não consegui criar o socket (errno \(e))"
        case .connectFailed(let e):
            let msg = e == 61 ? "conexão recusada" : (e == 13 ? "permissão negada" : (e == 2 ? "arquivo ausente" : ""))
            return "não consegui conectar ao helper (errno \(e)\(msg.isEmpty ? "" : ": " + msg))"
        case .noResponse: return "helper não respondeu"
        }
    }
}

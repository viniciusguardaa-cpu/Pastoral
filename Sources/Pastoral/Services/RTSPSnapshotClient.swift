import Foundation
import Darwin
import PastoralCore

// MARK: - RTSP snapshot client (I/O layer)
//
// Connects to a camera over TCP, runs the RTSP DESCRIBE/SETUP/PLAY
// handshake, reads interleaved RTP packets, and returns a single JPEG
// frame. Uses the pure parsers in RTSPSnapshot (PastoralCore) so the
// framing logic stays testable.
//
// Runs unprivileged (outbound TCP to the camera). No helper needed.

/// Result of a snapshot attempt.
enum SnapshotResult {
    case success(CameraSnapshot)
    case noJPEGStream(codec: String)   // camera is H.264/H.265 — detected but not snapshotted
    case failed(String)
}

final class RTSPSnapshotClient: @unchecked Sendable {
    private let host: String
    private let port: Int
    private var path: String
    private let paths: [String]
    private let credentials: [(user: String, pass: String, isDefault: Bool)]
    private var fd: Int32 = -1
    private var cseq = 0
    private var sessionID: String?

    // Auth state (see RTSPStreamClient): challenge + working credential.
    private var authChallenge: RTSPAuthChallenge?
    private var activeCredential: (user: String, pass: String)?
    private var nonceCount = 0
    private let cnonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()

    /// Called once when a credential successfully authenticates.
    var onAuthenticated: ((user: String, pass: String, isDefault: Bool)) -> Void = { _ in }

    init(host: String, port: Int = 554, path: String = "/",
         fallbackPaths: [String] = [],
         credentials: [(user: String, pass: String, isDefault: Bool)] = []) {
        self.host = host
        self.port = port
        self.path = path
        self.paths = [path] + fallbackPaths
        self.credentials = credentials
    }

    /// Full RTSP URL for this camera.
    var url: String { "rtsp://\(host):\(port)\(path)" }

    /// Grab a single JPEG frame. Falls back to a JPEG snapshot URL when
    /// the RTSP track isn't JPEG (H.264/H.265 cameras).
    func snapshot(timeoutSeconds: Double = 4.0) async -> SnapshotResult {
        do {
            try await connect(timeoutSeconds: timeoutSeconds)
            defer { disconnect() }

            var lastFailure = "nenhum path RTSP respondeu"
            for candidatePath in paths {
                path = candidatePath

                // 1. DESCRIBE (with 401 → credential retry)
                let track: RTSPTrack
                switch try await describeWithAuth() {
                case .success(let t): track = t
                case .failure(let msg): lastFailure = msg; continue
                }

                // Only JPEG-over-RTP is snapshotted. H.264/H.265 would need
                // a real codec; we report the codec so the UI can show
                // "detected".
                guard track.codec.uppercased().contains("JPEG") else {
                    return await tryHTTPSnapshot() ?? .noJPEGStream(codec: track.codec)
                }

                // 2. SETUP (TCP interleaved)
                let trackURL = absoluteTrackURL(track.trackID)
                let (s2, h2, _) = try await sendRequest(
                    method: "SETUP", url: trackURL,
                    extraHeaders: ["Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"])
                guard s2 == 200 else { lastFailure = "SETUP returned \(s2)"; continue }
                sessionID = h2["session"]?.split(separator: ";").first.map(String.init)

                // 3. PLAY
                let (s3, _, _) = try await sendRequest(
                    method: "PLAY", url: url, session: sessionID,
                    extraHeaders: ["Range": "npt=0.000-"])
                guard s3 == 200 else { lastFailure = "PLAY returned \(s3)"; continue }

                // 4. Read interleaved RTP packets until a JPEG frame completes.
                let packets = try await readRTPPackets(maxPackets: 256, timeoutSeconds: timeoutSeconds)
                guard let jpeg = RTSPSnapshot.reassembleJPEG(packets) else {
                    lastFailure = "no complete JPEG frame in stream"
                    continue
                }

                // 5. TEARDOWN (best effort).
                _ = try? await sendRequest(method: "TEARDOWN", url: url, session: sessionID)

                return .success(CameraSnapshot(data: jpeg, contentType: "image/jpeg", sourceURL: url))
            }
            return await tryHTTPSnapshot() ?? .failed(lastFailure)
        } catch {
            // RTSP failed entirely — try the HTTP snapshot fallback.
            return await tryHTTPSnapshot() ?? .failed(error.localizedDescription)
        }
    }

    /// Result of a DESCRIBE attempt on the current path.
    private enum DescribeResult {
        case success(RTSPTrack)
        case failure(String)
    }

    /// DESCRIBE the current `url` and return the first video track.
    /// On 401, retries with each candidate credential (see
    /// RTSPStreamClient.describeWithAuth).
    private func describeWithAuth() async throws -> DescribeResult {
        let accept = ["Accept": "application/sdp"]
        let (status, headers, body) = try await sendRequest(
            method: "DESCRIBE", url: url, extraHeaders: accept)
        if status == 200 {
            let sdp = String(data: body, encoding: .utf8) ?? ""
            guard let track = RTSPSnapshot.parseSDP(sdp).first else {
                return .failure("no video track in SDP")
            }
            return .success(track)
        }
        guard status == 401 else {
            return .failure("DESCRIBE returned \(status)")
        }
        guard let challengeHeader = headers["www-authenticate"],
              let challenge = RTSPAuth.parseChallenge(challengeHeader) else {
            return .failure("401 sem WWW-Authenticate reconhecido")
        }
        authChallenge = challenge
        for cred in credentials {
            activeCredential = (cred.user, cred.pass)
            let (s, _, b) = try await sendRequest(
                method: "DESCRIBE", url: url, extraHeaders: accept)
            if s == 200 {
                onAuthenticated(cred)
                let sdp = String(data: b, encoding: .utf8) ?? ""
                guard let track = RTSPSnapshot.parseSDP(sdp).first else {
                    return .failure("no video track in SDP")
                }
                return .success(track)
            }
            if s != 401 {
                return .failure("DESCRIBE returned \(s)")
            }
        }
        activeCredential = nil
        return .failure("autenticação falhou (401) — nenhuma credencial aceita")
    }

    // MARK: - HTTP snapshot fallback
    //
    // Many cameras expose a JPEG snapshot over HTTP even when the RTSP
    // track is H.264. Common paths:
    //   /cgi-bin/viewer/video.jpg?camera=1   (Axis)
    //   /cgi-bin/snapshot.cgi?               (generic)
    //   /ISAPI/Streaming/channels/101/picture (Hikvision)
    //   /snap/                               (Dahua)
    //   /image/jpeg.cgi                      (Foscam)
    // We try a few and return the first 200 image/jpeg.

    private static let snapshotPaths = [
        "/cgi-bin/viewer/video.jpg?camera=1&resolution=640x480",
        "/cgi-bin/snapshot.cgi?resolution=640x480",
        "/ISAPI/Streaming/channels/101/picture",
        "/snap.jpg",
        "/image/jpeg.cgi",
        "/snapshot.jpg"
    ]

    private func tryHTTPSnapshot() async -> SnapshotResult? {
        for path in Self.snapshotPaths {
            let url = "http://\(host)\(path)"
            if let snap = await fetchHTTPImage(url: url, port: 80) {
                return .success(snap)
            }
        }
        return nil
    }

    private func fetchHTTPImage(url: String, port: Int) async -> CameraSnapshot? {
        guard let parsed = URL(string: url),
              let host = parsed.host else { return nil }
        var req = "GET \(parsed.path)\(parsed.query.map { "?\($0)" } ?? "") HTTP/1.0\r\nHost: \(host)\r\nConnection: close\r\n"
        // HTTP snapshot endpoints usually take Basic auth — reuse the
        // credential that authenticated the RTSP session, if any.
        if let cred = activeCredential {
            let token = Data("\(cred.user):\(cred.pass)".utf8).base64EncodedString()
            req += "Authorization: Basic \(token)\r\n"
        }
        req += "\r\n"
        guard let fd = try? await connectTCP(host: host, port: port, timeout: 3.0) else { return nil }
        defer { close(fd) }
        _ = req.data(using: .utf8)?.withUnsafeBytes { buf in
            _ = Darwin.write(fd, buf.baseAddress, buf.count)
        }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(4.0)
        while Date() < deadline {
            let n = buf.withUnsafeMutableBufferPointer { ptr in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n <= 0 { break }
            data.append(contentsOf: buf.prefix(n))
            if data.count > 4_000_000 { break }   // 4 MB cap
        }
        // Find the body start (after \r\n\r\n).
        guard let sep = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let body = data.subdata(in: sep.upperBound..<data.count)
        // Heuristic: JPEG starts with FFD8.
        guard body.count > 2, body[0] == 0xFF, body[1] == 0xD8 else { return nil }
        return CameraSnapshot(data: body, contentType: "image/jpeg", sourceURL: url)
    }

    // MARK: - RTSP socket I/O

    private func connect(timeoutSeconds: Double) async throws {
        fd = try await connectTCP(host: host, port: port, timeout: timeoutSeconds)
    }

    private func disconnect() {
        if fd >= 0 { close(fd); fd = -1 }
    }

    private func sendRequest(method: String, url: String,
                             session: String? = nil,
                             extraHeaders: [String: String] = [:]) async throws -> (Int, [String: String], Data) {
        cseq += 1
        var headers = extraHeaders
        if let cred = activeCredential, let challenge = authChallenge {
            nonceCount += 1
            headers["Authorization"] = RTSPAuth.authorizationHeader(
                method: method, uri: url, challenge: challenge,
                username: cred.user, password: cred.pass,
                nonceCount: nonceCount, cnonce: cnonce)
        }
        let req = RTSPSnapshot.buildRequest(method: method, url: url, cseq: cseq,
                                            session: session, extraHeaders: headers)
        _ = req.withUnsafeBytes { buf in
            write(fd, buf.baseAddress, buf.count)
        }
        // Read until we have a full response head.
        var buffer = Data()
        var tmp = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(4.0)
        while Date() < deadline {
            let n = tmp.withUnsafeMutableBufferPointer { ptr in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n <= 0 { break }
            buffer.append(contentsOf: tmp.prefix(n))
            if let parsed = RTSPSnapshot.parseResponse(buffer) {
                let bodyStart = parsed.bodyStart
                let contentLength = RTSPSnapshot.contentLength(in: parsed.headers) ?? 0
                let have = buffer.count - bodyStart
                if have >= contentLength {
                    let body = buffer.subdata(in: bodyStart..<(bodyStart + contentLength))
                    return (parsed.status, parsed.headers, body)
                }
            }
        }
        throw NSError(domain: "RTSP", code: -1, userInfo: [NSLocalizedDescriptionKey: "response timeout"])
    }

    /// Read interleaved RTP packets from the RTSP TCP stream. RTSP
    /// interleaving frames: '$' (0x24), channel (1 byte), length (2 BE),
    /// then `length` bytes of RTP packet.
    private func readRTPPackets(maxPackets: Int, timeoutSeconds: Double) async throws -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var stream = Data()
        var tmp = [UInt8](repeating: 0, count: 8192)
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline && packets.count < maxPackets {
            let n = tmp.withUnsafeMutableBufferPointer { ptr in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n <= 0 { break }
            stream.append(contentsOf: tmp.prefix(n))
            // Parse as many interleaved frames as are available.
            var pos = 0
            while pos + 4 <= stream.count {
                guard stream[pos] == 0x24 else { pos += 1; continue }   // '$'
                let channel = stream[pos + 1]
                let length = Int(stream[pos + 2]) << 8 | Int(stream[pos + 3])
                let frameStart = pos + 4
                if frameStart + length > stream.count { break }   // need more bytes
                let pkt = Array(stream[frameStart..<(frameStart + length)])
                packets.append(pkt)
                _ = channel
                pos = frameStart + length
            }
            if pos > 0 { stream.removeFirst(pos) }
        }
        return packets
    }

    // MARK: - TCP connect

    private func connectTCP(host: String, port: Int, timeout: Double) async throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &result)
        guard rc == 0, let info = result else {
            throw NSError(domain: "RTSP", code: -2, userInfo: [NSLocalizedDescriptionKey: "getaddrinfo failed"])
        }
        defer { freeaddrinfo(info) }
        let s = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard s >= 0 else {
            throw NSError(domain: "RTSP", code: -3, userInfo: [NSLocalizedDescriptionKey: "socket failed"])
        }
        // Non-blocking connect with timeout.
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        let connectRC = Darwin.connect(s, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if connectRC != 0 && errno != EINPROGRESS {
            close(s)
            throw NSError(domain: "RTSP", code: -4, userInfo: [NSLocalizedDescriptionKey: "connect failed"])
        }
        var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
        let pollRC = poll(&pfd, 1, Int32(timeout * 1000))
        if pollRC <= 0 || (pfd.revents & Int16(POLLOUT)) == 0 {
            close(s)
            throw NSError(domain: "RTSP", code: -5, userInfo: [NSLocalizedDescriptionKey: "connect timeout"])
        }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0 {
            close(s)
            throw NSError(domain: "RTSP", code: -6, userInfo: [NSLocalizedDescriptionKey: "connect refused"])
        }
        _ = fcntl(s, F_SETFL, flags)   // restore blocking
        return s
    }

    // MARK: - URL helpers

    /// Resolve a track control path (which may be relative or absolute)
    /// against the RTSP base URL.
    private func absoluteTrackURL(_ control: String) -> String {
        if control.hasPrefix("rtsp://") { return control }
        if control.hasPrefix("/") { return "rtsp://\(host):\(port)\(control)" }
        // Relative path like "trackID=0" — append to the base URL.
        let base = url.hasSuffix("/") ? String(url.dropLast()) : url
        return "\(base)/\(control)"
    }
}

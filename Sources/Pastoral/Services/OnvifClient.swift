import Foundation
import Darwin
import PastoralCore

// MARK: - ONVIF media client
//
// Asks a camera for its real RTSP stream URIs — the same queries ONVIF
// Device Manager runs: GetCapabilities → Media XAddr → GetProfiles →
// GetStreamUri. ONVIF HTTP auth is standard HTTP Digest (RFC 2617),
// identical math to RTSP Digest, so we reuse RTSPAuth.
//
// All socket I/O is blocking — call streamURIs from a detached task.

enum OnvifClient {
    struct Result {
        /// rtsp://… URIs for the camera's profiles (main stream first).
        var uris: [String]
        /// Credential ONVIF accepted, if auth was required — the same
        /// account usually works on RTSP too.
        var credential: (user: String, pass: String)?
    }

    /// Resolve stream URIs for the camera at `xaddr` (the device service
    /// URL from WS-Discovery). Tries unauthenticated first, then each
    /// credential. Returns nil if the camera won't talk ONVIF to us.
    static func streamURIs(xaddr: String,
                           credentials: [(user: String, pass: String)],
                           timeout: Double = 3.0) -> Result? {
        guard let url = URL(string: xaddr), url.scheme == "http",
              url.host != nil else { return nil }
        let cnonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()

        // 1. Find a credential the ONVIF service accepts.
        var authed: (user: String, pass: String)?
        var capsBody: String?
        for cred in [("", "")] + credentials {
            guard let r = soapPost(url: url, body: Onvif.getCapabilitiesXML,
                                   user: cred.user, pass: cred.pass,
                                   cnonce: cnonce, timeout: timeout) else {
                return nil   // transport dead — retrying won't help
            }
            if r.status == 200 {
                capsBody = r.body
                authed = cred.user.isEmpty ? nil : cred
                break
            }
            if r.status != 401 { return nil }   // 404/500/fault — bail
        }
        guard let capsBody else { return nil }

        // 2. Media service XAddr — may be a different port/path than the
        //    device service. Fall back to the device xaddr.
        let mediaURL = Onvif.mediaXAddr(from: capsBody)
            .flatMap { URL(string: $0) } ?? url

        // 3. GetProfiles → profile tokens (main + sub streams)
        guard let profiles = soapPost(url: mediaURL, body: Onvif.getProfilesXML,
                                      user: authed?.user ?? "", pass: authed?.pass ?? "",
                                      cnonce: cnonce, timeout: timeout),
              profiles.status == 200 else { return nil }
        let tokens = Array(Onvif.profileTokens(from: profiles.body).prefix(2))
        guard !tokens.isEmpty else { return nil }

        // 4. GetStreamUri per profile
        var uris: [String] = []
        for token in tokens {
            guard let r = soapPost(url: mediaURL,
                                   body: Onvif.getStreamUriXML(profileToken: token),
                                   user: authed?.user ?? "", pass: authed?.pass ?? "",
                                   cnonce: cnonce, timeout: timeout),
                  r.status == 200,
                  let uri = Onvif.streamURI(from: r.body) else { continue }
            uris.append(uri)
        }
        guard !uris.isEmpty else { return nil }
        return Result(uris: uris, credential: authed)
    }

    // MARK: - HTTP + Digest

    /// POST a SOAP envelope. On 401, retries once with HTTP Digest
    /// (or Basic) auth built from the WWW-Authenticate challenge.
    /// Returns nil only on transport failure.
    private static func soapPost(url: URL, body: String,
                                 user: String, pass: String, cnonce: String,
                                 timeout: Double)
        -> (status: Int, headers: [String: String], body: String)? {
        guard let host = url.host else { return nil }
        let port = url.port ?? 80
        var path = url.path.isEmpty ? "/" : url.path
        if let q = url.query { path += "?\(q)" }

        var challenge: RTSPAuthChallenge?
        for attempt in 1...2 {
            var req = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\n"
                + "Content-Type: application/soap+xml; charset=utf-8\r\n"
                + "Content-Length: \(body.utf8.count)\r\n"
                + "Connection: close\r\n"
            if let challenge, !user.isEmpty {
                let auth = RTSPAuth.authorizationHeader(
                    method: "POST", uri: path, challenge: challenge,
                    username: user, password: pass,
                    nonceCount: attempt, cnonce: cnonce)
                req += "Authorization: \(auth)\r\n"
            }
            req += "\r\n\(body)"

            guard let fd = try? connectTCP(host: host, port: port, timeout: timeout)
            else { return nil }
            defer { close(fd) }
            _ = req.data(using: .utf8)?.withUnsafeBytes { buf in
                _ = Darwin.write(fd, buf.baseAddress, buf.count)
            }
            var data = Data()
            var tmp = [UInt8](repeating: 0, count: 8192)
            let deadline = Date().addingTimeInterval(timeout)
            while Date() < deadline {
                let n = tmp.withUnsafeMutableBufferPointer { ptr in
                    Darwin.read(fd, ptr.baseAddress, ptr.count)
                }
                if n <= 0 { break }
                data.append(contentsOf: tmp.prefix(n))
                if data.count > 512_000 { break }
            }
            guard let parsed = RTSPSnapshot.parseResponse(data) else { return nil }
            let bodyStr = String(
                data: data.subdata(in: parsed.bodyStart..<data.count),
                encoding: .utf8) ?? ""

            if parsed.status == 401, challenge == nil, !user.isEmpty,
               let wwwAuth = parsed.headers["www-authenticate"],
               let ch = RTSPAuth.parseChallenge(wwwAuth) {
                challenge = ch
                continue   // retry with Authorization
            }
            return (parsed.status, parsed.headers, bodyStr)
        }
        return nil
    }

    // MARK: - TCP connect (same nonblocking pattern as RTSPSnapshotClient)

    private static func connectTCP(host: String, port: Int, timeout: Double) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0,
              let info = result else {
            throw NSError(domain: "ONVIF", code: -1)
        }
        defer { freeaddrinfo(info) }
        let s = socket(info.pointee.ai_family, info.pointee.ai_socktype,
                       info.pointee.ai_protocol)
        guard s >= 0 else { throw NSError(domain: "ONVIF", code: -2) }
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        let connectRC = Darwin.connect(s, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if connectRC != 0 && errno != EINPROGRESS {
            close(s)
            throw NSError(domain: "ONVIF", code: -3)
        }
        var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(timeout * 1000)) > 0,
              (pfd.revents & Int16(POLLOUT)) != 0 else {
            close(s)
            throw NSError(domain: "ONVIF", code: -4)
        }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0, err == 0 else {
            close(s)
            throw NSError(domain: "ONVIF", code: -5)
        }
        _ = fcntl(s, F_SETFL, flags)
        return s
    }
}

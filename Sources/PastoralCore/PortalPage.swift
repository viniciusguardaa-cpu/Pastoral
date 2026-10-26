import Foundation

/// Captive-portal machinery for Lobo mode. When a target's plain HTTP
/// flows through the transparent proxy, these helpers decide what the
/// phone sees: the OS connectivity probes get an "offline" answer (which
/// forces iOS/Android to open their browser), and every other GET is
/// redirected to our full-screen page.
///
/// Pure and side-effect free — unit tested in isolation. The proxy is
/// the only caller that turns these into actual bytes on the wire.
public enum PortalPage {

    /// OS connectivity probe endpoints, by normalized host + exact path.
    /// Each expects a magic response ("success", 204, …); we answer with
    /// `offlineBody` so the device concludes "no internet" — which is
    /// exactly what triggers the captive-portal UI on us.
    /// (`www.apple.com`'s check is HTTPS on recent iOS; kept here for
    /// devices/firmwares that still probe it over plain HTTP.)
    public static let captiveChecks: [(host: String, path: String)] = [
        ("captive.apple.com", "/hotspot-detect.html"),
        ("www.apple.com", "/library/test/success.html"),
        ("connectivitycheck.google.com", "/generate_204"),
        ("connect.google.com", "/generate_204"),
        ("connectivitycheck.gstatic.com", "/generate_204"),
        ("clients3.google.com", "/generate_204"),
        ("connectivity-check.ubuntu.com", "/"),
        ("neverssl.com", "/"),
    ]

    private static let captiveKeys: Set<String> =
        Set(captiveChecks.map { "\($0.0)|\($0.1)" })

    /// Lowercased host without the `:port` suffix.
    public static func normalizedHost(_ host: String) -> String {
        var h = host.lowercased()
        if let i = h.firstIndex(of: ":") { h.removeSubrange(i...) }
        return h
    }

    private static func normalizedPath(_ path: String) -> String {
        guard let q = path.firstIndex(of: "?") else { return path }
        return String(path[..<q])
    }

    /// True when this request is an OS connectivity probe we should
    /// answer with "offline".
    public static func isCaptiveCheck(host: String, path: String) -> Bool {
        captiveKeys.contains("\(normalizedHost(host))|\(normalizedPath(path))")
    }

    /// The path our page is served at. We redirect with this relative
    /// location so the follow-up request keeps hitting the same origin —
    /// which still flows through us (the traffic was diverted to begin
    /// with).
    public static let pagePath = "/__pastoral__/portal.html"

    /// Deliberately different from every magic string an OS looks for.
    public static let offlineBody = "pastoral-offline"

    /// Full-screen dark page: optional background image plus message.
    /// Kept tiny (a few KB) — it is served to a phone we are also
    /// trying to starve.
    public static func pageHTML(message: String, imageBase64: String? = nil) -> String {
        let safeMessage = escape(message)
        let imgTag: String
        if let imageBase64, !imageBase64.isEmpty {
            // Data URI keeps the page self-contained (one request).
            imgTag = """
                <img src="data:image/jpeg;base64,\(imageBase64)" \
                    alt="" draggable="false">

            """
        } else {
            imgTag = ""
        }
        return """
        <!doctype html>
        <html lang="pt-BR">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
        <title>Rede</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          html, body { height: 100%; }
          body {
            background: #0b0b0f; color: #f5f5f7;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex; align-items: center; justify-content: center;
            overflow: hidden; touch-action: manipulation;
          }
          img {
            position: fixed; inset: 0; width: 100%; height: 100%;
            object-fit: cover; opacity: 0.82; z-index: -1;
          }
          .card { text-align: center; padding: 40px 24px; max-width: 90vw; }
          h1 { font-size: 30px; font-weight: 700; letter-spacing: -0.02em; }
          p { margin-top: 14px; font-size: 15px; color: #a1a1a6; line-height: 1.5; }
        </style>
        </head>
        <body>
          \(imgTag)<div class="card">
            <h1>\(safeMessage)</h1>
            <p>Toque fora da mensagem ou tente novamente em instantes.</p>
          </div>
        </body>
        </html>
        """
    }

    /// Escape the five HTML metacharacters — the message comes from our
    /// own app, but a portal page is rendered in the victim's browser.
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

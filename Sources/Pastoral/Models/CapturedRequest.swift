import Foundation
import PastoralCore

/// A captured HTTP(S) request row in the Sheep tab. Populated by the
/// transparent proxy in step 5+. The `credential` flag is set when the
/// request carries password/token fields or Cookie/Set-Cookie headers.
struct CapturedRequest: Identifiable, Hashable {
    let id: UUID
    var timestamp: Date
    var host: String
    var method: String
    var path: String
    var status: Int?
    var sizeBytes: Int
    var hasCredential: Bool
    var isTLS: Bool
    var sni: String?

    init(id: UUID = UUID(), timestamp: Date = .now, host: String, method: String,
         path: String, status: Int? = nil, sizeBytes: Int = 0,
         hasCredential: Bool = false, isTLS: Bool = false, sni: String? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.method = method
        self.path = path
        self.status = status
        self.sizeBytes = sizeBytes
        self.hasCredential = hasCredential
        self.isTLS = isTLS
        self.sni = sni
    }

    /// Convert from the proxy's CapturedExchange to the UI model.
    init(from ex: CapturedExchange) {
        self.id = ex.id
        self.timestamp = ex.timestamp
        self.host = ex.host
        self.method = ex.method
        self.path = ex.path
        self.status = ex.status
        self.sizeBytes = ex.sizeBytes
        self.hasCredential = ex.hasCredential
        self.isTLS = ex.isTLS
        self.sni = ex.sni
    }

    /// The full URL of the request — used to open the page in the default
    /// browser. TLS rows captured as CONNECT carry only the SNI, so they
    /// open the origin's root. Nil when there's nothing navigable.
    var fullURL: URL? {
        if path.hasPrefix("http://") || path.hasPrefix("https://") {
            return URL(string: path)
        }
        guard host != "unknown", !host.isEmpty else { return nil }
        return URL(string: "\(isTLS ? "https" : "http")://\(host)\(path)")
    }
}

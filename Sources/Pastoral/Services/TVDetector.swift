import Foundation
import Darwin

// MARK: - Smart-TV / streaming-box discovery via Bonjour
//
// Browses mDNS/DNS-SD service types that TVs, streaming boxes and speakers
// advertise (_airplay, _googlecast, _raop, …), resolves each instance to
// IPv4 addresses, and reports them so the app can mark LAN hosts as TVs.
// Runs unprivileged — NetService needs no root and no helper round-trip.
//
// OUI matching (in AppState) covers TVs that don't advertise Bonjour.

final class TVDetector: NSObject {
    /// Bonjour service types that indicate a TV / streamer / set-top box.
    static let serviceTypes: [String] = [
        "_airplay._tcp.",        // Apple TV, AirPlay TVs
        "_raop._tcp.",           // AirPlay audio (Apple TV, HomePod)
        "_mediaremotetv._tcp.",  // Apple TV Remote
        "_companion-link._tcp.", // Apple TV / iOS companion
        "_googlecast._tcp.",     // Chromecast / Android TV / Google TV
        "_androidtvremote2._tcp.",
        "_spotify-connect._tcp.",// TVs/consoles running Spotify Connect
        "_hap._tcp.",            // HomeKit accessories (some TVs)
        "_roku._tcp.",           // Roku ECP
        "_dial._tcp.",           // DIAL (Netflix/YouTube cast, TVs)
        "_xbmc-jsonrpc._tcp.",   // Kodi
        "_plexmediasvr._tcp."    // Plex server (NAS — weak signal, kept last)
    ]

    /// OUI vendor keywords that strongly suggest a TV or streaming box.
    /// Apple is deliberately absent — its OUI pool is shared with Macs;
    /// Apple TV is detected via Bonjour instead.
    static let vendorKeywords: [String] = [
        "samsung", "lg electronics", "sony", "vizio", "tcl", "hisense",
        "roku", "philips", "panasonic", "sharp", "toshiba", "skyworth",
        "vestel", "loewe", "bang & olufsen", "amazon technologies",
        "amazon.com", "google, inc", "googl", "xfinity", "arris",
        "technicolor", "sagemcom", "humax", "tivo"
    ]

    /// Called on the main thread when the set of detected IPs changes.
    var onChange: ((Set<String>) -> Void)?

    private(set) var detectedIPs: Set<String> = []
    private var browsers: [NetServiceBrowser] = []
    private var resolving: [ObjectIdentifier: NetService] = [:]
    private var running = false

    func start() {
        guard !running else { return }
        running = true
        for type in Self.serviceTypes {
            let b = NetServiceBrowser()
            b.delegate = self
            b.searchForServices(ofType: type, inDomain: "local.")
            browsers.append(b)
        }
    }

    func stop() {
        running = false
        browsers.forEach { $0.stop() }
        browsers.removeAll()
        resolving.values.forEach { $0.stop() }
        resolving.removeAll()
    }

    private func addIPs(_ ips: [String]) {
        let changed = detectedIPs.union(ips) != detectedIPs
        detectedIPs.formUnion(ips)
        if changed { onChange?(detectedIPs) }
    }

    /// Extract IPv4 strings from NetService.addresses (sockaddr blobs).
    static func ipv4Addresses(of service: NetService) -> [String] {
        (service.addresses ?? []).compactMap { data -> String? in
            data.withUnsafeBytes { raw -> String? in
                guard let sa = raw.baseAddress?.assumingMemoryBound(to: sockaddr.self),
                      sa.pointee.sa_family == AF_INET else { return nil }
                let sin = raw.baseAddress!.assumingMemoryBound(to: sockaddr_in.self)
                var addr = sin.pointee.sin_addr
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &addr, &buf,
                                socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
                return String(cString: buf)
            }
        }
    }
}

extension TVDetector: NetServiceBrowserDelegate {
    func netServiceBrowser(_ browser: NetServiceBrowser,
                           didFind service: NetService,
                           moreComing: Bool) {
        resolving[ObjectIdentifier(service)] = service
        service.delegate = self
        service.resolve(withTimeout: 5)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser,
                           didRemove service: NetService,
                           moreComing: Bool) {
        resolving[ObjectIdentifier(service)]?.stop()
        resolving.removeValue(forKey: ObjectIdentifier(service))
    }
}

extension TVDetector: NetServiceDelegate {
    func netServiceDidResolveAddress(_ sender: NetService) {
        defer {
            resolving.removeValue(forKey: ObjectIdentifier(sender))
            sender.stop()
        }
        let ips = Self.ipv4Addresses(of: sender)
        if !ips.isEmpty { addIPs(ips) }
    }

    func netService(_ sender: NetService,
                    didNotResolve errorDict: [String: NSNumber]) {
        resolving.removeValue(forKey: ObjectIdentifier(sender))
    }
}

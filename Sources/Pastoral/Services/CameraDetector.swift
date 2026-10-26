import Foundation
import Darwin

// MARK: - IP camera discovery via Bonjour + OUI
//
// Browses mDNS/DNS-SD service types that IP cameras advertise
// (_rtsp._tcp, _onvif._tcp, _camera._tcp, _h264/_h265 over RTSP, …),
// resolves each instance to IPv4 addresses, and reports them so the
// app can mark LAN hosts as cameras. Runs unprivileged — NetService
// needs no root and no helper round-trip.
//
// OUI matching (in AppState) covers cameras that don't advertise Bonjour
// (many Hikvision/Dahua/Axis cameras ship with mDNS off by default).

final class CameraDetector: NSObject {
    /// Bonjour service types that indicate an IP camera or NVR.
    static let serviceTypes: [String] = [
        "_rtsp._tcp.",          // generic RTSP server (most IP cameras)
        "_onvif._tcp.",         // ONVIF Profile S (device discovery)
        "_camera._tcp.",        // generic camera
        "_h264._tcp.",          // H.264 RTSP stream
        "_h265._tcp.",          // H.265/HEVC RTSP stream
        "_video._tcp.",         // generic video source
        "_uvonvif._tcp.",       // Ubiquiti ONVIF bridge
        "_nvr._tcp."            // NVR / DVR
    ]

    /// OUI vendor keywords that strongly suggest an IP camera, NVR, or
    /// video encoder. These are the major surveillance manufacturers;
    /// consumer webcam vendors (Logitech, etc.) are excluded to avoid
    /// false positives on laptops/peripherals.
    static let vendorKeywords: [String] = [
        "hikvision", "dahua", "axis communications", "axis ab",
        "bosch security", "bosch", "vivotek", "avtronics",
        "foscam", "amcrest", "reolink", "ubiquiti", "ubnt",
        "hanwha", "wisenet", "pelco", "flir systems", "flir",
        "d-link", "dlink", "trendnet", "lorex", "swann",
        "zmodo", "annke", "sannce", "gw security", "laview",
        "speco", "geovision", "acti", "vicon", "panasonic",
        "sony", "canon", "nikon", "ricoh",
        "wyze", "xiaomi", "tuya", "ezviz"
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

extension CameraDetector: NetServiceBrowserDelegate {
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

extension CameraDetector: NetServiceDelegate {
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

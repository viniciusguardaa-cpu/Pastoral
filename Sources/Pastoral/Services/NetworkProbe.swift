import Foundation
import Darwin
import CoreWLAN

/// Reads local network context for the status bar (no root needed):
/// interface, local IP (getifaddrs), MAC + SSID (CoreWLAN), gateway
/// (default route). The `route` tool is a thin wrapper over AF_ROUTE; a
/// future refinement can use a routing socket directly.
enum NetworkProbe {
    static func read() -> NetworkInfo {
        var info = NetworkInfo()
        let route = defaultRoute()

        // CoreWLAN client (modern API: CWWiFiClient, not the deprecated
        // CWInterface.interface() class method).
        let cw = CWWiFiClient.shared().interface()

        // Interface: prefer the default-route interface, fall back to the
        // active CoreWLAN interface.
        if let iface = route.interface {
            info.interfaceName = iface
        } else {
            info.interfaceName = cw?.interfaceName
        }

        info.gatewayIP = route.gateway
        info.localIP = ipv4(of: info.interfaceName)

        // CoreWLAN gives MAC + SSID for the Wi-Fi interface.
        if let cw {
            info.localMAC = cw.hardwareAddress()
            info.ssid = cw.ssid()
            if info.interfaceName == nil {
                info.interfaceName = cw.interfaceName
            }
        }
        return info
    }

    private struct RouteInfo {
        var interface: String?
        var gateway: String?
    }

    private static func defaultRoute() -> RouteInfo {
        var info = RouteInfo()
        guard let output = runCapture("/sbin/route", ["-n", "get", "default"]) else { return info }
        for line in output.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("interface:") {
                info.interface = String(t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces))
            } else if t.hasPrefix("gateway:") {
                let g = String(t.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces))
                if !g.isEmpty, g != "0.0.0.0" { info.gateway = g }
            }
        }
        return info
    }

    private static func ipv4(of interface: String?) -> String? {
        guard let interface else { return nil }
        var addrs: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&addrs) == 0, let first = addrs else { return nil }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ptr = cursor {
            let name = String(cString: ptr.pointee.ifa_name)
            if name == interface, let sa = ptr.pointee.ifa_addr {
                if Int32(sa.pointee.sa_family) == AF_INET {
                    let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                        sin.pointee.sin_addr
                    }
                    if let s = inet_ntoa(addr) {
                        return String(cString: s)
                    }
                }
            }
            cursor = ptr.pointee.ifa_next
        }
        return nil
    }

    private static func runCapture(_ path: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run(); p.waitUntilExit() } catch { return nil }
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}

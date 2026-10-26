import Foundation
import Darwin
import PastoralCore

// MARK: - ONVIF WS-Discovery probe
//
// Sends a WS-Discovery Probe to the multicast group 239.255.255.250:3702
// (plus subnet broadcast — some cameras only answer broadcast) and
// collects ProbeMatch responses for a short window. Cameras reply
// unicast to our ephemeral source port.
//
// This is the same discovery ONVIF Device Manager performs on open —
// unprivileged, no helper needed.

enum OnvifProbe {

    /// Discover ONVIF devices on the LAN. Blocking — call from a
    /// detached task. Returns one OnvifDevice per responding device.
    static func discover(window: TimeInterval = 2.5) -> [OnvifDevice] {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [] }
        defer { close(fd) }

        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: 0, tv_usec: 150_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Bind ephemeral so replies have somewhere to land.
        var bindAddr = sockaddr_in()
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_port = 0
        bindAddr.sin_addr = in_addr(s_addr: INADDR_ANY)
        _ = withUnsafePointer(to: &bindAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        func sendProbe(to ip: String, types: String) {
            var dest = sockaddr_in()
            dest.sin_family = sa_family_t(AF_INET)
            dest.sin_port = UInt16(3702).bigEndian
            dest.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            inet_pton(AF_INET, ip, &dest.sin_addr)
            let xml = Onvif.probeXML(types: types)
            xml.withCString { cstr in
                _ = withUnsafePointer(to: &dest) { d in
                    d.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, cstr, strlen(cstr), 0, sa,
                               socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }

        sendProbe(to: "239.255.255.250", types: "dn:NetworkVideoTransmitter")
        sendProbe(to: "255.255.255.255", types: "dn:NetworkVideoTransmitter")

        var devices: [String: OnvifDevice] = [:]   // keyed by endpoint/xaddr
        var buf = [UInt8](repeating: 0, count: 65535)
        var from = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let deadline = Date().addingTimeInterval(window)
        let resendAt = Date().addingTimeInterval(window * 0.4)
        var resent = false

        while Date() < deadline {
            if !resent && Date() >= resendAt {
                // Second round: multicast again + a generic probe catches
                // cameras that don't match the NVT type filter.
                sendProbe(to: "239.255.255.250", types: "")
                sendProbe(to: "255.255.255.255", types: "")
                resent = true
            }
            let n = withUnsafeMutablePointer(to: &from) { f in
                f.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &fromLen)
                }
            }
            guard n > 0 else { continue }
            let xml = String(decoding: buf.prefix(n), as: UTF8.self)
            var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sinAddr = from.sin_addr
            inet_ntop(AF_INET, &sinAddr, &ipBuf, socklen_t(INET_ADDRSTRLEN))
            let senderIP = String(cString: ipBuf)
            for var dev in Onvif.parseProbeMatches(xml) {
                if dev.ip.isEmpty { dev.ip = senderIP }
                devices[dev.endpoint ?? dev.xaddr] = dev
            }
        }
        return Array(devices.values)
    }
}

import Foundation
import Darwin
import PastoralCore
import libpcap
import PastoralBPFShim

/// Active ARP scan: broadcasts ARP requests for a /24 subnet via a raw
/// BPF socket, sniffs replies with pcap, and merges with the kernel ARP
/// table (sysctl net.link.generic.system.arptable). Runs in the helper
/// (root) so it can open BPF and send raw frames.
struct ARPScanner {
    let interface: String
    let localIP: [UInt8]
    let localMAC: MAC

    /// Scan the /24 of `localIP` and return discovered hosts.
    func scan(timeoutSeconds: Int = 2) -> [ARPEntry] {
        // 1) Read the kernel ARP table as a baseline.
        let hosts = readKernelARPTable().filter { !isMulticastOrBroadcast($0.ip) }

        // 2) Broadcast ARP requests for the entire /24.
        let subnet = localIP
        guard subnet.count == 4 else { return hosts }

        // Open a BPF device for sending + receiving.
        guard let bpf = openBPF() else {
            // Fallback: just return the kernel table.
            return hosts
        }
        defer { close(bpf.fd) }

        // Send ARP requests for each IP in the /24 (skip .0 and .255).
        let networkBase = (UInt32(subnet[0]) << 24) | (UInt32(subnet[1]) << 16)
                        | (UInt32(subnet[2]) << 8) | 0
        for i in 1..<255 {
            let targetIP = [
                UInt8((networkBase >> 24) & 0xFF),
                UInt8((networkBase >> 16) & 0xFF),
                UInt8((networkBase >> 8) & 0xFF),
                UInt8(i)
            ]
            // Skip our own IP.
            if targetIP == subnet { continue }
            let frame = ARPFrame.request(senderMAC: localMAC, senderIP: subnet, targetIP: targetIP)
            _ = write(bpf.fd, frame, frame.count)
        }

        // 3) Sniff replies for `timeoutSeconds`.
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        var discovered: [String: ARPEntry] = [:]
        for h in hosts { discovered[h.ip] = h }

        // Set a read timeout on the BPF fd.
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        _ = setsockopt(bpf.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        while Date() < deadline {
            let buffer = readBPF(fd: bpf.fd, bpfBufLen: bpf.bufLen)
            guard let packet = buffer else { continue }
            // BPF returns packets with a bpf_hdr prefix per packet.
            for pkt in iterateBPF(buffer: packet, bufLen: bpf.bufLen) {
                guard let eth = EthernetFrame.decode(pkt),
                      eth.etherType == EtherType.arp.rawValue else { continue }
                guard let arp = ARPPacket.decode(eth.payload),
                      arp.operation == .reply else { continue }
                let ip = arp.senderIPString
                let mac = arp.senderMAC.string
                if !ip.isEmpty && mac != "00:00:00:00:00:00" && !isMulticastOrBroadcast(ip) {
                    discovered[ip] = ARPEntry(ip: ip, mac: mac, interface: interface, expires: nil)
                }
            }
        }

        return Array(discovered.values).sorted { $0.ip < $1.ip }
    }

    // MARK: - Kernel ARP table

    /// Check if an IP is multicast (224.0.0.0/4) or broadcast (x.x.x.255/0).
    private func isMulticastOrBroadcast(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4 else { return true }
        let first = parts[0]
        // Multicast: 224.0.0.0 - 239.255.255.255
        if first >= 224 && first <= 239 { return true }
        // Broadcast: x.x.x.0 or x.x.x.255
        if parts[3] == 0 || parts[3] == 255 { return true }
        return false
    }

    /// Read the kernel ARP table via sysctl (net.link.generic.system.arptable).
    /// Falls back to parsing `arp -a` if the sysctl fails.
    private func readKernelARPTable() -> [ARPEntry] {
        // Try `arp -a` — it's a reliable, if inelegant, way to get the table.
        guard let output = runCapture("/usr/sbin/arp", ["-a"]) else { return [] }
        var entries: [ARPEntry] = []
        // Format: "hostname (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        let pattern = #"\(([\d.]+)\) at ([0-9a-fA-F:]+) on (\w+)"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        for line in output.split(separator: "\n") {
            let nsLine = String(line) as NSString
            let range = NSRange(location: 0, length: nsLine.length)
            if let match = regex.firstMatch(in: nsLine as String, range: range) {
                let ip = nsLine.substring(with: match.range(at: 1))
                let mac = nsLine.substring(with: match.range(at: 2))
                let iface = nsLine.substring(with: match.range(at: 3))
                entries.append(ARPEntry(ip: ip, mac: mac, interface: iface, expires: nil))
            }
        }
        return entries
    }

    // MARK: - BPF

    struct BPFHandle {
        let fd: Int32
        let bufLen: UInt32
    }

    /// Open a BPF device, configure it, and bind to the interface.
    private func openBPF() -> BPFHandle? {
        for i in 0..<16 {
            let path = "/dev/bpf\(i)"
            let fd = open(path, O_RDWR)
            if fd >= 0 {
                // Bind to interface.
                let r = pastoral_ioctl_ifname(fd, pastoral_BIOCSETIF, interface)
                if r != 0 {
                    close(fd)
                    continue
                }
                // Get buffer length.
                var bufLen: UInt = 0
                _ = pastoral_ioctl_ulong(fd, pastoral_BIOCGBLEN, &bufLen)
                // Enable immediate mode (return on packet arrival).
                var immediate: UInt = 1
                _ = pastoral_ioctl_ulong(fd, pastoral_BIOCIMMEDIATE, &immediate)
                // Set header complete = 1 so our source MAC is preserved.
                var hdrcmplt: UInt = 1
                _ = pastoral_ioctl_ulong(fd, pastoral_BIOCSHDRCMPLT, &hdrcmplt)
                return BPFHandle(fd: fd, bufLen: bufLen > 0 ? UInt32(bufLen) : 32768)
            }
        }
        return nil
    }

    /// Read a chunk from the BPF device.
    private func readBPF(fd: Int32, bpfBufLen: UInt32) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: Int(bpfBufLen))
        let n = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
            read(fd, ptr.baseAddress, Int(bpfBufLen))
        }
        if n <= 0 { return nil }
        return Array(buffer.prefix(n))
    }

    /// Iterate BPF packets in a buffer (each preceded by a bpf_hdr).
    private func iterateBPF(buffer: [UInt8], bufLen: UInt32) -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var offset = 0
        let bpfHdrSize = Int(pastoral_bpf_hdr_size)
        while offset + bpfHdrSize <= buffer.count {
            // Read bpf_hdr: bh_caplen, bh_datalen, bh_hdrlen
            let capLen = Int(buffer[offset]) | (Int(buffer[offset + 1]) << 8)
                       | (Int(buffer[offset + 2]) << 16) | (Int(buffer[offset + 3]) << 24)
            let hdrLen = Int(buffer[offset + 8]) | (Int(buffer[offset + 9]) << 8)
                       | (Int(buffer[offset + 10]) << 16) | (Int(buffer[offset + 11]) << 24)
            let pktStart = offset + hdrLen
            let pktEnd = pktStart + capLen
            if pktEnd <= buffer.count {
                packets.append(Array(buffer[pktStart..<pktEnd]))
            }
            // BPF headers are word-aligned.
            let aligned = (pktEnd + 3) & ~3
            offset = aligned
            if offset <= 0 { break }
        }
        return packets
    }

    // MARK: - Shell

    private func runCapture(_ path: String, _ args: [String]) -> String? {
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

import Foundation
import Darwin
import PastoralCore
import PastoralBPFShim

/// Passive mDNS/LLMNR sniffer: opens a BPF device on the given interface,
/// filters IPv4 UDP packets on port 5353 (mDNS) or 5355 (LLMNR), parses
/// the DNS messages, and emits discovered services/queries via a callback.
///
/// Runs in the privileged helper. Stop via `stop()`.
final class MDNSSniffer {
    /// A discovery observation emitted by the sniffer.
    struct Observation: Sendable {
        let sourceIP: String
        let destIP: String
        let sourcePort: UInt16
        let destPort: UInt16
        /// Parsed DNS message (may be nil if parsing fails).
        let message: MDNSMessage?
        /// Services extracted from the message (empty for queries).
        let services: [MDNSService]
        let timestamp: Date
    }

    private let interface: String
    private let handler: @Sendable (Observation) -> Void
    private var thread: Thread?
    private var fd: Int32 = -1
    private var stopped = false
    private let lock = NSLock()
    /// Dedup by (sourceIP, serviceType, instance) to avoid spamming.
    private var seen: Set<String> = []

    init(interface: String, handler: @escaping @Sendable (Observation) -> Void) {
        self.interface = interface
        self.handler = handler
    }

    @discardableResult
    func start() -> Bool {
        guard let bpf = openBPF() else { return false }
        fd = bpf.fd
        let bufLen = bpf.bufLen
        let t = Thread { [weak self] in self?.captureLoop(bufLen: bufLen) }
        t.name = "pastoral.mdns.sniffer"
        t.start()
        thread = t
        return true
    }

    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        let localFd = fd
        fd = -1
        lock.unlock()
        if localFd >= 0 { close(localFd) }
    }

    // MARK: - Capture loop

    private func captureLoop(bufLen: UInt32) {
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        while !shouldStop() {
            guard let buffer = readBPF(fd: fd, bpfBufLen: bufLen) else { continue }
            for pkt in iterateBPF(buffer: buffer, bufLen: bufLen) {
                processPacket(pkt)
            }
        }
    }

    private func shouldStop() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return stopped || fd < 0
    }

    private func processPacket(_ bytes: [UInt8]) {
        guard let eth = EthernetFrame.decode(bytes),
              eth.etherType == EtherType.ipv4.rawValue else { return }
        guard let ip = IPv4Header.decode(eth.payload),
              ip.protocolNumber == IPProtocol.udp.rawValue else { return }
        guard let udp = decodeUDP(ip.payload) else { return }
        // mDNS: 5353. LLMNR: 5355.
        guard udp.sourcePort == 5353 || udp.destPort == 5353
                || udp.sourcePort == 5355 || udp.destPort == 5355 else { return }
        guard let msg = MDNSParser.parse(udp.payload) else { return }
        let services = MDNSService.extract(from: msg)

        // Dedup service observations.
        var emitted = false
        for svc in services {
            let key = "\(ip.sourceIPString)|\(svc.serviceType)|\(svc.instance)"
            lock.lock()
            let isNew = seen.insert(key).inserted
            if seen.count > 4096 { seen.removeAll(keepingCapacity: true) }
            lock.unlock()
            if isNew { emitted = true }
        }
        // Always emit queries (questions) and non-deduped service announcements.
        if emitted || !msg.questions.isEmpty {
            let obs = Observation(
                sourceIP: ip.sourceIPString,
                destIP: ip.destIPString,
                sourcePort: udp.sourcePort,
                destPort: udp.destPort,
                message: msg,
                services: services,
                timestamp: Date()
            )
            handler(obs)
        }
    }

    // MARK: - UDP decode

    private struct UDPHeader {
        let sourcePort: UInt16
        let destPort: UInt16
        let length: UInt16
        let payload: [UInt8]
    }

    private func decodeUDP(_ bytes: [UInt8]) -> UDPHeader? {
        guard bytes.count >= 8 else { return nil }
        let src = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let dst = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        let len = (UInt16(bytes[4]) << 8) | UInt16(bytes[5])
        let payload = Array(bytes[8...])
        return UDPHeader(sourcePort: src, destPort: dst, length: len, payload: payload)
    }

    // MARK: - BPF (mirrors QUICSniffer/ARPScanner)

    private struct BPFHandle { let fd: Int32; let bufLen: UInt32 }

    private func openBPF() -> BPFHandle? {
        for i in 0..<16 {
            let path = "/dev/bpf\(i)"
            let f = open(path, O_RDWR)
            if f >= 0 {
                let r = pastoral_ioctl_ifname(f, pastoral_BIOCSETIF, interface)
                if r != 0 { close(f); continue }
                var bufLen: UInt = 0
                _ = pastoral_ioctl_ulong(f, pastoral_BIOCGBLEN, &bufLen)
                var immediate: UInt = 1
                _ = pastoral_ioctl_ulong(f, pastoral_BIOCIMMEDIATE, &immediate)
                var hdrcmplt: UInt = 1
                _ = pastoral_ioctl_ulong(f, pastoral_BIOCSHDRCMPLT, &hdrcmplt)
                return BPFHandle(fd: f, bufLen: bufLen > 0 ? UInt32(bufLen) : 32768)
            }
        }
        return nil
    }

    private func readBPF(fd: Int32, bpfBufLen: UInt32) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: Int(bpfBufLen))
        let n = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
            read(fd, ptr.baseAddress, Int(bpfBufLen))
        }
        if n <= 0 { return nil }
        return Array(buffer.prefix(n))
    }

    private func iterateBPF(buffer: [UInt8], bufLen: UInt32) -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var offset = 0
        let bpfHdrSize = Int(pastoral_bpf_hdr_size)
        while offset + bpfHdrSize <= buffer.count {
            let capLen = Int(buffer[offset]) | (Int(buffer[offset + 1]) << 8)
                       | (Int(buffer[offset + 2]) << 16) | (Int(buffer[offset + 3]) << 24)
            let hdrLen = Int(buffer[offset + 8]) | (Int(buffer[offset + 9]) << 8)
                       | (Int(buffer[offset + 10]) << 16) | (Int(buffer[offset + 11]) << 24)
            let pktStart = offset + hdrLen
            let pktEnd = pktStart + capLen
            if pktEnd <= buffer.count {
                packets.append(Array(buffer[pktStart..<pktEnd]))
            }
            let aligned = (pktEnd + 3) & ~3
            offset = aligned
            if offset <= 0 { break }
        }
        return packets
    }
}

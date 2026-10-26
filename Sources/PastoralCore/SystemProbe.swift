import Foundation

/// Abstraction over the privileged system queries the helper needs. Kept
/// as a protocol so the command-dispatch logic is unit-testable with a
/// mock, and the real helper injects a `LiveSystemProbe` that calls
/// sysctl / route / stat.
public protocol SystemProbe: Sendable {
    /// Current value of `net.inet.ip.forwarding` (0/1).
    func ipForwardingEnabled() -> Bool
    /// Default-route interface name (e.g. "en0"), if discoverable.
    func defaultInterface() -> String?
    /// Whether BPF devices are group-accessible (reset applied).
    func bpfAccessible() -> Bool
    /// GID of the `access_bpf` group, if it exists.
    func accessBPFGroupID() -> gid_t?
}

/// Pure-logic command dispatcher: given a request and a system probe,
/// produce the response. This is the heart of the helper and is fully
/// testable without sockets or root.
public enum CommandDispatcher {
    public static func handle(_ request: HelperRequest, probe: SystemProbe) -> HelperResponse {
        switch request {
        case .status:
            return .statusReport(
                forwarding: probe.ipForwardingEnabled(),
                interface: probe.defaultInterface(),
                bpfAccessible: probe.bpfAccessible()
            )

        // The remaining commands are implemented in later steps (ARP scan,
        // spoof, pf, forwarding, wifi). For now they acknowledge so the
        // protocol round-trips end-to-end during step 2.
        case .scanARP:
            return .error(message: "scan.arp not implemented yet (step 3)")
        case .spoofStart:
            return .error(message: "spoof.start not implemented yet (step 4)")
        case .spoofStop:
            return .error(message: "spoof.stop not implemented yet (step 4)")
        case .divertStart:
            return .error(message: "divert.start not implemented yet (force-path)")
        case .forwardEnable:
            return .error(message: "forward.enable not implemented yet (step 4)")
        case .forwardDisable:
            return .error(message: "forward.disable not implemented yet (step 4)")
        case .wifiScan:
            return .error(message: "wifi.scan not implemented yet (step 3)")
        case .wifiMonitorOn:
            return .error(message: "wifi.monitor.on not implemented yet (step 3)")
        case .wifiMonitorOff:
            return .error(message: "wifi.monitor.off not implemented yet (step 3)")
        case .deauthSend:
            return .error(message: "deauth.send not implemented yet (step 3)")
        case .sheepStart(_):
            return .error(message: "sheep.start not implemented yet (step 5)")
        case .sheepStop:
            return .error(message: "sheep.stop not implemented yet (step 5)")
        case .killSelective:
            return .error(message: "kill.selective not implemented yet (phase 3)")
        case .killSelectiveClear:
            return .error(message: "kill.selective.clear not implemented yet (phase 3)")
        case .quicStart:
            return .error(message: "quic.start not implemented yet (phase 2)")
        case .quicStop:
            return .error(message: "quic.stop not implemented yet (phase 2)")
        case .mdnsStart:
            return .error(message: "mdns.start not implemented yet (phase 4)")
        case .mdnsStop:
            return .error(message: "mdns.stop not implemented yet (phase 4)")
        case .tunnelStart:
            return .error(message: "tunnel.start not implemented yet (phase 6)")
        case .tunnelStop:
            return .error(message: "tunnel.stop not implemented yet (phase 6)")
        case .tunnelStatus:
            return .tunnelStatus(interface: nil, handshake: nil, rx: 0, tx: 0)
        case .tailscaleUp:
            return .error(message: "tailscale.up not implemented yet (phase 6)")
        case .tailscaleDown:
            return .error(message: "tailscale.down not implemented yet (phase 6)")
        case .uninstall:
            return .error(message: "uninstall not implemented yet (step 7)")
        case .portProbe:
            return .error(message: "port.probe not implemented yet (camera detection)")
        case .caTrustInstall:
            return .error(message: "ca.trust.install not implemented yet")
        case .caTrustRemove:
            return .error(message: "ca.trust.remove not implemented yet")
        case .hcxStart:
            return .error(message: "hcx.start is handled asynchronously by the daemon")
        case .hcxStop:
            return .ok(message: "hcx.stop (async daemon handles it)")
        }
    }
}

/// A mock probe for unit tests.
public struct MockSystemProbe: SystemProbe {
    public var forwarding: Bool
    public var interface: String?
    public var bpf: Bool
    public var bpfGroup: gid_t?

    public init(forwarding: Bool, interface: String?, bpf: Bool, bpfGroup: gid_t? = nil) {
        self.forwarding = forwarding
        self.interface = interface
        self.bpf = bpf
        self.bpfGroup = bpfGroup
    }

    public func ipForwardingEnabled() -> Bool { forwarding }
    public func defaultInterface() -> String? { interface }
    public func bpfAccessible() -> Bool { bpf }
    public func accessBPFGroupID() -> gid_t? { bpfGroup }
}

import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the helper command dispatcher. The dispatcher is pure
/// logic over an injected SystemProbe, so we test it with a mock and no
/// socket / root.
@Suite("Command dispatcher")
struct CommandDispatcherTests {

    @Test("status reports forwarding, interface, BPF from the probe")
    func statusReport() {
        let probe = MockSystemProbe(forwarding: true, interface: "en0", bpf: true)
        let res = CommandDispatcher.handle(.status, probe: probe)
        #expect(res == .statusReport(forwarding: true, interface: "en0", bpfAccessible: true))
    }

    @Test("status with forwarding off and no interface")
    func statusOff() {
        let probe = MockSystemProbe(forwarding: false, interface: nil, bpf: false)
        let res = CommandDispatcher.handle(.status, probe: probe)
        #expect(res == .statusReport(forwarding: false, interface: nil, bpfAccessible: false))
    }

    @Test("unimplemented commands reject with a not-implemented message")
    func unimplemented() {
        let probe = MockSystemProbe(forwarding: false, interface: nil, bpf: false)
        let cases: [(HelperRequest, String)] = [
            (.scanARP, "scan.arp"),
            (.wifiScan, "wifi.scan"),
            (.forwardEnable, "forward.enable"),
            (.forwardDisable, "forward.disable")
        ]
        for (req, tag) in cases {
            let res = CommandDispatcher.handle(req, probe: probe)
            if case .error(let msg) = res {
                #expect(msg.contains(tag), "expected rejection mentioning \(tag), got \(msg)")
            } else {
                Issue.record("expected .error for \(tag), got \(res)")
            }
        }
    }

    @Test("spoof start/stop reject")
    func spoofAck() {
        let probe = MockSystemProbe(forwarding: false, interface: nil, bpf: false)
        let start = CommandDispatcher.handle(.spoofStart(targetIP: "10.0.0.5", gatewayIP: "10.0.0.1"), probe: probe)
        let stop = CommandDispatcher.handle(.spoofStop(targetIP: "10.0.0.5"), probe: probe)
        if case .error = start {} else { Issue.record("spoof.start should reject") }
        if case .error = stop {} else { Issue.record("spoof.stop should reject") }
    }

    @Test("divert start rejects")
    func divertAck() {
        let probe = MockSystemProbe(forwarding: false, interface: nil, bpf: false)
        let bi = CommandDispatcher.handle(.divertStart(targetIP: "10.0.0.5", gatewayIP: "10.0.0.1", bidirectional: true), probe: probe)
        let uni = CommandDispatcher.handle(.divertStart(targetIP: "10.0.0.6", gatewayIP: "10.0.0.1", bidirectional: false), probe: probe)
        if case .error = bi {} else { Issue.record("divert.start bidirectional should reject") }
        if case .error = uni {} else { Issue.record("divert.start unidirectional should reject") }
    }

    @Test("wifi monitor and deauth reject")
    func wifiAck() {
        let probe = MockSystemProbe(forwarding: false, interface: nil, bpf: false)
        let on = CommandDispatcher.handle(.wifiMonitorOn(interface: "en0", channel: 6), probe: probe)
        let off = CommandDispatcher.handle(.wifiMonitorOff(interface: "en0"), probe: probe)
        let deauth = CommandDispatcher.handle(.deauthSend(targetMAC: "aa:bb:cc:dd:ee:ff", bssid: "11:22:33:44:55:66", channel: 11), probe: probe)
        if case .error = on {} else { Issue.record("wifi.monitor.on should reject") }
        if case .error = off {} else { Issue.record("wifi.monitor.off should reject") }
        if case .error = deauth {} else { Issue.record("deauth.send should reject") }
    }
}

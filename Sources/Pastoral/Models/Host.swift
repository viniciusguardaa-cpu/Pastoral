import Foundation

/// A discovered LAN host, shown in both the Kill and Sheep tabs.
///
/// `isKilled` and `isIntercepted` are UI-driven toggles backed by real
/// operations in later steps. `throughputSamples` feeds the sparkline and
/// is updated live from pcap observation (step 3+).
/// Coarse device classification — drives the "TV"/"CAM" badges and the
/// Inject tab's per-TV action.
enum HostKind: String, Hashable {
    case generic
    case tv
    case camera
}

struct Host: Identifiable, Hashable {
    let id: String          // MAC address is a stable identity
    var ip: String
    var mac: String
    var vendor: String?     // OUI lookup, offline, build-time embedded
    var hostname: String?   // PTR when available
    var kind: HostKind = .generic          // .tv when Bonjour/OUI says so
    var throughputBps: Double = 0
    var throughputSamples: [Double] = []   // recent bps samples for sparkline
    var isKilled: Bool = false
    var isDiverted: Bool = false          // force-path: traffic routed through us
    var isExcluded: Bool = false           // whitelist (self, gateway)

    // Include mutable flags in equality so SwiftUI re-renders when state
    // changes. Identity (for ForEach) is still just `id`, but equality
    // drives view diffing.
    static func == (lhs: Host, rhs: Host) -> Bool {
        lhs.id == rhs.id && lhs.isKilled == rhs.isKilled
            && lhs.isDiverted == rhs.isDiverted && lhs.isExcluded == rhs.isExcluded
            && lhs.kind == rhs.kind
    }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

extension Host {
    /// Formatted throughput in human-readable units.
    var throughputText: String {
        throughputSamples.isEmpty ? "Sem medição" : formatRate(throughputBps)
    }
}

/// Format a bytes/second rate compactly.
func formatRate(_ bps: Double) -> String {
    let units: [(Double, String)] = [
        (1_024 * 1_024 * 1_024, "GB/s"),
        (1_024 * 1_024, "MB/s"),
        (1_024, "KB/s")
    ]
    for (threshold, suffix) in units {
        if bps >= threshold {
            return String(format: "%.1f %@", bps / threshold, suffix)
        }
    }
    return String(format: "%.0f B/s", bps)
}

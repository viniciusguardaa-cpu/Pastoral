import Foundation

/// Tracks when hosts appear and disappear on the LAN over time. Pure
/// logic over an in-memory log; persistence is handled by the caller.
///
/// A "sighting" is a (mac, ip, timestamp) tuple recorded each time a host
/// is observed (e.g. by an ARP scan). The history derives appearance and
/// disappearance events by diffing consecutive sightings keyed by MAC.
public struct HostHistory: Codable, Equatable, Sendable {
    /// One observation of a host.
    public struct Sighting: Codable, Equatable, Sendable, Identifiable {
        public let id: UUID
        public let mac: String
        public let ip: String
        public let timestamp: Date
        public let vendor: String?

        public init(mac: String, ip: String, timestamp: Date, vendor: String? = nil) {
            self.id = UUID()
            self.mac = mac
            self.ip = ip
            self.timestamp = timestamp
            self.vendor = vendor
        }
    }

    /// A host appearance/disappearance event derived from sightings.
    public struct Event: Codable, Equatable, Sendable, Identifiable {
        public enum Kind: String, Codable, Sendable {
            case appeared   // first time we see this MAC
            case returned   // seen again after a gap
            case vanished   // was present, now absent
            case changedIP  // same MAC, new IP
        }
        public let id: UUID
        public let mac: String
        public let kind: Kind
        public let ip: String?
        public let previousIP: String?
        public let timestamp: Date

        public init(mac: String, kind: Kind, ip: String?, previousIP: String?, timestamp: Date) {
            self.id = UUID()
            self.mac = mac
            self.kind = kind
            self.ip = ip
            self.previousIP = previousIP
            self.timestamp = timestamp
        }
    }

    public var sightings: [Sighting] = []
    public var events: [Event] = []

    public init() {}

    /// Record a scan result (set of currently-visible hosts) at `timestamp`.
    /// Emits appearance/disappearance/change events as needed.
    /// `maxSightings` bounds the log; oldest entries are dropped.
    public mutating func recordScan(_ hosts: [(mac: String, ip: String, vendor: String?)],
                                    at timestamp: Date = Date(),
                                    maxSightings: Int = 5000) {
        // Build the set of currently-visible MACs and their IPs.
        var currentMACs: [String: String] = [:]   // mac → ip
        for h in hosts {
            currentMACs[h.mac] = h.ip
        }
        // Previous snapshot: the most recent sighting per MAC.
        var lastSeen: [String: Sighting] = [:]
        for s in sightings {
            if lastSeen[s.mac] == nil || s.timestamp > (lastSeen[s.mac]?.timestamp ?? .distantPast) {
                lastSeen[s.mac] = s
            }
        }

        // Emit events.
        for (mac, ip) in currentMACs {
            if let prev = lastSeen[mac] {
                if prev.ip != ip {
                    events.append(Event(mac: mac, kind: .changedIP, ip: ip,
                                        previousIP: prev.ip, timestamp: timestamp))
                }
                // Still present — no "returned" unless there was a vanish.
            } else {
                // New MAC.
                events.append(Event(mac: mac, kind: .appeared, ip: ip,
                                    previousIP: nil, timestamp: timestamp))
            }
        }
        // Vanished: MACs that were in the previous snapshot but not now.
        for (mac, prev) in lastSeen {
            if currentMACs[mac] == nil {
                events.append(Event(mac: mac, kind: .vanished, ip: nil,
                                    previousIP: prev.ip, timestamp: timestamp))
            }
        }

        // Record sightings for all currently-visible hosts.
        for (mac, ip) in currentMACs {
            let vendor = hosts.first { $0.mac == mac }?.vendor
            sightings.append(Sighting(mac: mac, ip: ip, timestamp: timestamp, vendor: vendor))
        }

        // Bound the logs.
        if sightings.count > maxSightings {
            sightings.removeFirst(sightings.count - maxSightings)
        }
        if events.count > maxSightings {
            events.removeFirst(events.count - maxSightings)
        }
    }

    /// All distinct MACs ever seen, with their last known IP and vendor.
    public var knownHosts: [(mac: String, lastIP: String, vendor: String?, lastSeen: Date)] {
        var latest: [String: Sighting] = [:]
        for s in sightings {
            if latest[s.mac] == nil || s.timestamp > (latest[s.mac]?.timestamp ?? .distantPast) {
                latest[s.mac] = s
            }
        }
        return latest.values.map { ($0.mac, $0.ip, $0.vendor, $0.timestamp) }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    /// Recent events, newest first.
    public var recentEvents: [Event] {
        events.reversed()
    }
}

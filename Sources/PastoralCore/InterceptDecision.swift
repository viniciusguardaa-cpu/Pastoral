import Foundation

// MARK: - Intercept decision logic (pure, testable)
//
// Given the set of selected target host IDs and the full host list, decide
// which hosts should have their traffic intercepted by the proxy. Pure
// logic — no I/O, fully testable.

/// Decides which hosts to intercept based on user selection.
public enum InterceptDecision {
    /// Determine which host IPs should be intercepted.
    /// - Parameters:
    ///   - hosts: all discovered hosts
    ///   - selectedIDs: IDs of hosts the user selected for interception
    /// - Returns: IPs of hosts that should be intercepted
    public static func targetsToIntercept(hosts: [HostInfo], selectedIDs: Set<String>) -> [String] {
        hosts.filter { selectedIDs.contains($0.id) && !$0.isExcluded }
            .map { $0.ip }
    }

    /// Check if a given host should be intercepted.
    public static func shouldIntercept(host: HostInfo, selectedIDs: Set<String>) -> Bool {
        selectedIDs.contains(host.id) && !host.isExcluded
    }
}

/// A minimal host info struct for the intercept decision (avoids coupling
/// to the UI-only Host model).
public struct HostInfo: Equatable, Sendable {
    public let id: String
    public let ip: String
    public let isExcluded: Bool

    public init(id: String, ip: String, isExcluded: Bool = false) {
        self.id = id
        self.ip = ip
        self.isExcluded = isExcluded
    }
}

import Foundation

/// Pure logic for building WireGuard and Tailscale tunnel configurations
/// (phase 6). The configs are generated as text and applied by the
/// privileged helper via `wg-quick`/`wg` or the `tailscale` CLI.
///
/// This is pure, testable logic — no I/O, no privileged operations.
/// The helper is responsible for writing the config to disk and
/// invoking the tunnel tools.

/// A WireGuard peer configuration (one side of a tunnel).
public struct WireGuardPeer: Equatable, Sendable {
    public let publicKey: String    // base64
    public let allowedIPs: [String] // CIDR ranges routed through the tunnel
    public let endpoint: String?    // host:port (nil for server-side peers)
    public let presharedKey: String? // optional PSK (base64)
    public let keepalive: Int?      // seconds; nil = no keepalive

    public init(publicKey: String, allowedIPs: [String], endpoint: String? = nil,
                presharedKey: String? = nil, keepalive: Int? = nil) {
        self.publicKey = publicKey
        self.allowedIPs = allowedIPs
        self.endpoint = endpoint
        self.presharedKey = presharedKey
        self.keepalive = keepalive
    }
}

/// A complete WireGuard interface configuration: the local interface
/// section plus a list of peers.
public struct WireGuardConfig: Equatable, Sendable {
    public let interfaceName: String  // e.g. "wg0"
    public let privateKey: String      // base64
    public let address: [String]      // interface IPs (CIDR)
    public let listenPort: Int?        // nil = random/ephemeral
    public let dns: [String]           // DNS servers for the tunnel
    public let mtu: Int?              // nil = default (1420 for WG)
    public let peers: [WireGuardPeer]

    public init(interfaceName: String, privateKey: String,
                address: [String], listenPort: Int? = nil,
                dns: [String] = [], mtu: Int? = nil,
                peers: [WireGuardPeer] = []) {
        self.interfaceName = interfaceName
        self.privateKey = privateKey
        self.address = address
        self.listenPort = listenPort
        self.dns = dns
        self.mtu = mtu
        self.peers = peers
    }

    /// Render the configuration as a wg-quick-compatible INI file.
    public func render() -> String {
        var lines: [String] = ["[Interface]"]
        lines.append("PrivateKey = \(privateKey)")
        if !address.isEmpty {
            lines.append("Address = \(address.joined(separator: ", "))")
        }
        if let port = listenPort {
            lines.append("ListenPort = \(port)")
        }
        if !dns.isEmpty {
            lines.append("DNS = \(dns.joined(separator: ", "))")
        }
        if let mtu = mtu {
            lines.append("MTU = \(mtu)")
        }
        for peer in peers {
            lines.append("")
            lines.append("[Peer]")
            lines.append("PublicKey = \(peer.publicKey)")
            if let psk = peer.presharedKey {
                lines.append("PresharedKey = \(psk)")
            }
            if !peer.allowedIPs.isEmpty {
                lines.append("AllowedIPs = \(peer.allowedIPs.joined(separator: ", "))")
            }
            if let endpoint = peer.endpoint {
                lines.append("Endpoint = \(endpoint)")
            }
            if let keepalive = peer.keepalive {
                lines.append("PersistentKeepalive = \(keepalive)")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

/// A Tailscale connection configuration. Tailscale abstracts away the
/// WireGuard key management; the operator just needs to authenticate
/// and optionally specify an exit node or advertise routes.
public struct TailscaleConfig: Equatable, Sendable, Codable {
    /// Auth key for headless login (optional; interactive login if nil).
    public let authKey: String?
    /// Routes to advertise from this node (CIDR). The remote operator
    /// reaches the LAN through these advertised routes.
    public let advertiseRoutes: [String]
    /// If true, this node acts as an exit node for the tailnet.
    public let exitNode: Bool
    /// Hostname to set for this node in the tailnet.
    public let hostname: String?
    /// If true, accept the configured exit node's routes.
    public let acceptRoutes: Bool

    public init(authKey: String? = nil, advertiseRoutes: [String] = [],
                exitNode: Bool = false, hostname: String? = nil,
                acceptRoutes: Bool = false) {
        self.authKey = authKey
        self.advertiseRoutes = advertiseRoutes
        self.exitNode = exitNode
        self.hostname = hostname
        self.acceptRoutes = acceptRoutes
    }

    /// Render the `tailscale up` command arguments. Returns nil if the
    /// config is empty (no auth key and no routes — nothing to do).
    public func renderUpArgs() -> [String]? {
        var args: [String] = ["up"]
        if let key = authKey {
            args.append("--auth-key=\(key)")
        }
        if !advertiseRoutes.isEmpty {
            args.append("--advertise-routes=\(advertiseRoutes.joined(separator: ","))")
        }
        if exitNode {
            args.append("--advertise-exit-node")
        }
        if let host = hostname {
            args.append("--hostname=\(host)")
        }
        if acceptRoutes {
            args.append("--accept-routes")
        }
        // Always: don't block on interactive login in headless mode.
        args.append("--accept-dns=false")
        return args
    }
}

/// Validates tunnel configuration inputs (pure, testable).
public enum TunnelValidator {
    /// Validate a CIDR string (e.g. "192.168.1.0/24"). Returns true if
    /// the format is valid.
    public static func isValidCIDR(_ s: String) -> Bool {
        let parts = s.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]) else { return false }
        guard prefix >= 0, prefix <= 32 else { return false }
        return isValidIPv4(String(parts[0]))
    }

    /// Validate an IPv4 address.
    public static func isValidIPv4(_ s: String) -> Bool {
        let octets = s.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { $0 >= 0 && $0 <= 255 }
    }

    /// Validate a WireGuard endpoint (host:port).
    public static func isValidEndpoint(_ s: String) -> Bool {
        guard let colon = s.lastIndex(of: ":") else { return false }
        let host = String(s[..<colon])
        let port = String(s[s.index(after: colon)...])
        guard let portNum = Int(port), portNum > 0, portNum < 65536 else { return false }
        // Host can be an IP or a hostname.
        return isValidIPv4(host) || !host.isEmpty
    }

    /// Validate a base64 key (32 bytes → 44 chars with padding).
    public static func isValidWireGuardKey(_ s: String) -> Bool {
        guard s.count == 44 else { return false }
        return s.allSatisfy { $0.isLetter || $0.isNumber || $0 == "+" || $0 == "/" || $0 == "=" }
    }
}

import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for tunnel configuration builders (phase 6).
@Suite("Tunnel config")
struct TunnelConfigTests {

    @Test("WireGuard config renders a valid INI")
    func renderWireGuard() {
        let peer = WireGuardPeer(
            publicKey: "abc123==",
            allowedIPs: ["10.0.0.0/24", "192.168.0.0/16"],
            endpoint: "1.2.3.4:51820",
            keepalive: 25
        )
        let config = WireGuardConfig(
            interfaceName: "wg0",
            privateKey: "privkey==",
            address: ["10.10.0.1/24"],
            listenPort: 51820,
            dns: ["1.1.1.1"],
            mtu: 1420,
            peers: [peer]
        )
        let ini = config.render()
        #expect(ini.contains("[Interface]"))
        #expect(ini.contains("PrivateKey = privkey=="))
        #expect(ini.contains("Address = 10.10.0.1/24"))
        #expect(ini.contains("ListenPort = 51820"))
        #expect(ini.contains("DNS = 1.1.1.1"))
        #expect(ini.contains("MTU = 1420"))
        #expect(ini.contains("[Peer]"))
        #expect(ini.contains("PublicKey = abc123=="))
        #expect(ini.contains("AllowedIPs = 10.0.0.0/24, 192.168.0.0/16"))
        #expect(ini.contains("Endpoint = 1.2.3.4:51820"))
        #expect(ini.contains("PersistentKeepalive = 25"))
    }

    @Test("WireGuard config with no peers renders just Interface section")
    func renderNoPeers() {
        let config = WireGuardConfig(
            interfaceName: "wg0",
            privateKey: "privkey==",
            address: ["10.10.0.1/24"]
        )
        let ini = config.render()
        #expect(ini.contains("[Interface]"))
        #expect(!ini.contains("[Peer]"))
    }

    @Test("WireGuard peer with preshared key")
    func presharedKey() {
        let peer = WireGuardPeer(
            publicKey: "pub==",
            allowedIPs: ["0.0.0.0/0"],
            presharedKey: "psk=="
        )
        let config = WireGuardConfig(
            interfaceName: "wg0", privateKey: "priv==",
            address: ["10.0.0.1/24"], peers: [peer]
        )
        let ini = config.render()
        #expect(ini.contains("PresharedKey = psk=="))
    }

    @Test("Tailscale config renders up args")
    func tailscaleArgs() throws {
        let config = TailscaleConfig(
            authKey: "tskey-abc123",
            advertiseRoutes: ["192.168.1.0/24"],
            hostname: "pastoral-relay"
        )
        let args = try #require(config.renderUpArgs())
        #expect(args[0] == "up")
        #expect(args.contains("--auth-key=tskey-abc123"))
        #expect(args.contains("--advertise-routes=192.168.1.0/24"))
        #expect(args.contains("--hostname=pastoral-relay"))
    }

    @Test("Tailscale exit node flag")
    func tailscaleExitNode() throws {
        let config = TailscaleConfig(exitNode: true)
        let args = try #require(config.renderUpArgs())
        #expect(args.contains("--advertise-exit-node"))
    }

    @Test("Tailscale accept routes")
    func tailscaleAcceptRoutes() throws {
        let config = TailscaleConfig(acceptRoutes: true)
        let args = try #require(config.renderUpArgs())
        #expect(args.contains("--accept-routes"))
    }

    // MARK: - Validators

    @Test("CIDR validation")
    func cidrValidation() {
        #expect(TunnelValidator.isValidCIDR("192.168.1.0/24"))
        #expect(TunnelValidator.isValidCIDR("10.0.0.0/8"))
        #expect(TunnelValidator.isValidCIDR("0.0.0.0/0"))
        #expect(!TunnelValidator.isValidCIDR("192.168.1.0/33"))
        #expect(!TunnelValidator.isValidCIDR("192.168.1.0"))
        #expect(!TunnelValidator.isValidCIDR("999.168.1.0/24"))
    }

    @Test("IPv4 validation")
    func ipv4Validation() {
        #expect(TunnelValidator.isValidIPv4("192.168.1.1"))
        #expect(TunnelValidator.isValidIPv4("10.0.0.1"))
        #expect(!TunnelValidator.isValidIPv4("999.1.1.1"))
        #expect(!TunnelValidator.isValidIPv4("192.168.1"))
    }

    @Test("Endpoint validation")
    func endpointValidation() {
        #expect(TunnelValidator.isValidEndpoint("1.2.3.4:51820"))
        #expect(TunnelValidator.isValidEndpoint("vpn.example.com:51820"))
        #expect(!TunnelValidator.isValidEndpoint("1.2.3.4"))
        #expect(!TunnelValidator.isValidEndpoint("1.2.3.4:99999"))
        #expect(!TunnelValidator.isValidEndpoint("1.2.3.4:abc"))
    }

    @Test("WireGuard key validation")
    func keyValidation() {
        // 44 chars base64
        #expect(TunnelValidator.isValidWireGuardKey("abcdefghijklmnopqrstuvwxyz1234567890ABCD+/=="))
        #expect(!TunnelValidator.isValidWireGuardKey("short"))
        #expect(!TunnelValidator.isValidWireGuardKey("with spaces  in it  not valid base64 key=="))
    }
}

import Foundation

// MARK: - Helper protocol
//
// The privileged helper (`pastoral-helper`) listens on a Unix socket and
// speaks line-delimited JSON: one request per line, one response per line.
// This enum is the canonical command set, shared by the app client and the
// helper so both sides decode identically. It is deliberately Codable and
// unit-testable in isolation.
//
// Commands (step 2 wires the socket; the enum is defined here so the
// architecture is in place from the skeleton):
//   scan.arp, spoof.start, spoof.stop, forward.enable, forward.disable,
//   wifi.scan, wifi.monitor.on, wifi.monitor.off, deauth.send, status

/// A request sent from the app to the helper over the Unix socket.
public enum HelperRequest: Codable, Equatable, Sendable {
    /// Return the full ARP table (kernel + active scan results).
    case scanARP
    /// Begin bidirectional ARP spoofing against `targetIP`, impersonating
    /// `gatewayIP` to the target and the target to the gateway.
    case spoofStart(targetIP: String, gatewayIP: String)
    /// Stop spoofing `targetIP` and restore truthful ARP entries.
    case spoofStop(targetIP: String)
    /// Force a target's traffic through us ("force path" / divert mode):
    /// ARP spoof the target so its outbound traffic flows to our MAC,
    /// and ENABLE IP forwarding so the traffic is relayed to the real
    /// gateway instead of dropped. No pf drop rules are added — the
    /// traffic must flow so Sheep (rdr/proxy) can intercept it. This is
    /// the lever that makes MITM work even when we are not the target's
    /// natural gateway. `bidirectional` controls whether we also poison
    /// the gateway (full MITM, both directions) or only the target
    /// (outbound-only, stealthier). Stopped with `spoofStop`.
    case divertStart(targetIP: String, gatewayIP: String, bidirectional: Bool)
    /// Enable IPv4 forwarding (records prior state for restore).
    case forwardEnable
    /// Restore prior forwarding state.
    case forwardDisable
    /// Scan nearby Wi-Fi networks via CoreWLAN (helper proxies to the
    /// running app, or performs the scan itself when permitted).
    case wifiScan
    /// Enable monitor mode on `interface` (channel optional).
    case wifiMonitorOn(interface: String, channel: Int?)
    /// Disable monitor mode on `interface`.
    case wifiMonitorOff(interface: String)
    /// Send deauth frames to `targetMAC` on `bssid`/`channel`.
    case deauthSend(targetMAC: String, bssid: String, channel: Int)
    /// Start Sheep interception: add a wildcard pf rdr rule redirecting
    /// ALL TCP port 80/443 entering the default interface to the local
    /// transparent proxy. No per-target selection — whatever LAN traffic
    /// flows through us (diverted hosts) is captured. `forceTCPFallback`
    /// adds a UDP/443 block that pushes QUIC/HTTP3 clients back to TCP.
    case sheepStart(forceTCPFallback: Bool)
    /// Stop Sheep interception: remove all rdr rules from the sheep anchor.
    case sheepStop
    /// Apply a selective Kill policy to a target: drop or rate-limit
    /// traffic filtered by port/protocol/DSCP, instead of the default
    /// total drop. The policy is encoded as a `KillPolicy` value. Stopped
    /// with `killSelectiveClear(targetIP:)`.
    case killSelective(policy: KillPolicy)
    /// Clear all selective Kill policies for `targetIP` from the
    /// selective/dummynet anchors.
    case killSelectiveClear(targetIP: String)
    /// Start passive QUIC/HTTP3 sniffing on `interface`: opens a BPF
    /// device, filters UDP/443, and emits `quicObservation` response
    /// lines as Initial packets are decoded. Deduped by (srcIP, SNI).
    case quicStart(interface: String)
    /// Stop QUIC sniffing and close the BPF device.
    case quicStop
    /// Start passive mDNS/LLMNR sniffing on `interface`: opens a BPF
    /// device, filters UDP 5353/5355, and emits `mdnsObservation`
    /// response lines as services/queries are parsed.
    case mdnsStart(interface: String)
    /// Stop mDNS/LLMNR sniffing and close the BPF device.
    case mdnsStop
    /// Bring up a WireGuard tunnel using the provided config text (phase 6).
    /// The helper writes the config to a temp file and invokes `wg-quick up`.
    /// Returns ok with the interface name on success, error otherwise.
    case tunnelStart(config: String)
    /// Tear down the active WireGuard tunnel (phase 6).
    case tunnelStop
    /// Query the active tunnel status (phase 6): interface name, handshake,
    /// transfer stats. Returns `tunnelStatus` on success.
    case tunnelStatus
    /// Bring up a Tailscale tunnel with the given config (phase 6). The
    /// helper invokes `tailscale up` with the rendered args.
    case tailscaleUp(config: TailscaleConfig)
    /// Disconnect Tailscale (phase 6).
    case tailscaleDown
    /// Run the uninstaller: remove LaunchDaemons, helper, pf anchors,
    /// CA from Keychain, state dir, and the injected pf includes.
    case uninstall
    /// Liveness / capability probe. Returns current forwarding state,
    /// interface, and whether BPF devices are accessible.
    case status
    /// Probe a set of TCP ports on a target IP. Used to confirm cameras
    /// that don't advertise Bonjour (many Hikvision/Dahua cameras ship
    /// with mDNS off). Returns `portProbeResult` with the open ports.
    case portProbe(targetIP: String, ports: [UInt16])

    /// Start passive Wi-Fi key capture ("caça-senha") on `interface`:
    /// opens a BPF device, filters EAPOL (0x888E) and mirrored 802.11
    /// management frames (0x888B), and emits `hcxCapture` response lines
    /// for every parseable 4-way handshake message 2 or PMKID-carrying
    /// association response. Stops itself after `seconds` (0 = until
    /// `hcxStop`). `essid`/`bssid` label the frames when provided
    /// (e.g. from `wifiScan`) — the parser can't recover them on its own
    /// from Ethernet-viewed frames.
    case hcxStart(interface: String, essid: String, bssid: String, seconds: Int)
    /// Stop Wi-Fi key capture and close the BPF device.
    case hcxStop

    /// Instala/remove a confiança da CA Pastoral no System.keychain.
    /// Só o helper (root) consegue escrever nesse keychain; o app só
    /// passa o caminho do DER exportado e recebe o resultado.
    case caTrustInstall(String)
    case caTrustRemove(String)
}

/// A response returned by the helper.
public enum HelperResponse: Codable, Equatable, Sendable {
    /// Generic success, optional message.
    case ok(message: String? = nil)
    /// Failure with a human-readable reason.
    case error(message: String)
    /// Status report: forwarding on/off, chosen interface, BPF accessible.
    case statusReport(forwarding: Bool, interface: String?, bpfAccessible: Bool)
    /// ARP scan results: list of discovered hosts.
    case arpTable(hosts: [ARPEntry])
    /// An asynchronous QUIC observation emitted while sniffing is active.
    /// Sent unsolicited by the helper after a `quicStart` request, one
    /// line per deduped Initial packet.
    case quicObservation(sourceIP: String, destIP: String, sni: String?, alpn: [String], version: UInt32)
    /// An asynchronous mDNS/LLMNR observation emitted while sniffing is
    /// active. Sent unsolicited by the helper after a `mdnsStart` request.
    /// `serviceType` is the `_service._proto.local` name (empty for
    /// pure queries); `instance` is the service instance name (empty
    /// for PTR-only or query observations); `hostname`/`port`/`addresses`
    /// describe the resolved target when available.
    case mdnsObservation(sourceIP: String, serviceType: String, instance: String,
                         hostname: String?, port: UInt16?, addresses: [String])
    /// Tunnel status (phase 6). `interface` is nil when no tunnel is up.
    /// `handshake` is the seconds since last handshake (nil if never).
    /// `rx`/`tx` are bytes received/sent through the tunnel.
    case tunnelStatus(interface: String?, handshake: Int?, rx: UInt64, tx: UInt64)
    /// Result of a TCP port probe: which of the requested ports were open.
    case portProbeResult(targetIP: String, openPorts: [UInt16])
    /// Wi-Fi scan result from the helper (`airport -I` + `airport -s`).
    /// `current` marks the network we are associated with, if any.
    case wifiNetworks(networks: [WiFiNet])
    /// An asynchronous Wi-Fi key observation emitted while an `hcxStart`
    /// capture is running: one line per parsed handshake/PMKID frame.
    case hcxCapture(capture: WpaCapture)
}

/// One Wi-Fi network as seen by the helper. `signal` is dBm (negative);
/// `security` is the human string airport prints (WPA2, 802.1X, …).
public struct WiFiNet: Codable, Equatable, Sendable, Identifiable {
    public let ssid: String
    public let bssid: String
    public let channel: Int?
    public let signal: Int?
    public let security: String
    /// True when this is the network our interface is associated with.
    public let current: Bool

    public var id: String { bssid.isEmpty ? ssid : bssid }

    public init(ssid: String, bssid: String = "", channel: Int? = nil,
                signal: Int? = nil, security: String = "", current: Bool = false) {
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.signal = signal
        self.security = security
        self.current = current
    }
}

/// A single ARP-table entry as reported by the helper.
public struct ARPEntry: Codable, Equatable, Sendable, Identifiable {
    public var id: String { ip }
    public let ip: String
    public let mac: String
    public let interface: String
    public let expires: TimeInterval?

    public init(ip: String, mac: String, interface: String, expires: TimeInterval? = nil) {
        self.ip = ip
        self.mac = mac
        self.interface = interface
        self.expires = expires
    }
}

// MARK: - Line codec

/// Line-delimited JSON framing used over the Unix socket. One message per
/// line. Kept here so both sides and the tests share the exact same codec.
public enum LineCodec {
    /// Encode a value to a single JSON line terminated by `\n`.
    public static func encode<T: Encodable & Sendable>(_ value: T) throws -> Data {
        let json = try JSONEncoder().encode(value)
        guard var string = String(data: json, encoding: .utf8) else {
            throw CodecError.invalidUTF8
        }
        // A JSON object/array never contains a raw newline, but enforce it.
        precondition(!string.contains("\n"), "encoded JSON must be single-line")
        string.append("\n")
        return Data(string.utf8)
    }

    /// Decode a single line (with or without trailing newline) into a value.
    public static func decode<T: Decodable & Sendable>(_ line: String, as type: T.Type) throws -> T {
        let trimmed = line.hasSuffix("\n") ? String(line.dropLast()) : line
        guard let data = trimmed.data(using: .utf8) else {
            throw CodecError.invalidUTF8
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}

public enum CodecError: Error, Equatable {
    case invalidUTF8
}

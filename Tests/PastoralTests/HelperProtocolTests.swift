import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the helper protocol codec. The full command set and
/// ARP-frame / packet-decode / OUI / cert tests are added in later steps;
/// this validates the line-delimited JSON framing that both sides share.
@Suite("Helper protocol codec")
struct HelperProtocolTests {

    @Test("Request round-trips through line codec")
    func requestRoundTrip() throws {
        let req = HelperRequest.spoofStart(targetIP: "10.0.0.5", gatewayIP: "10.0.0.1")
        let data = try LineCodec.encode(req)
        let line = String(decoding: data, as: UTF8.self)
        #expect(line.hasSuffix("\n"))
        // Encoded JSON must be exactly one line: only the trailing newline.
        #expect(line.filter { $0 == "\n" }.count == 1)

        let decoded = try LineCodec.decode(line, as: HelperRequest.self)
        #expect(decoded == req)
    }

    @Test("All commands encode and decode")
    func allCommands() throws {
        let cases: [HelperRequest] = [
            .scanARP,
            .spoofStart(targetIP: "10.0.0.5", gatewayIP: "10.0.0.1"),
            .spoofStop(targetIP: "10.0.0.5"),
            .divertStart(targetIP: "10.0.0.5", gatewayIP: "10.0.0.1", bidirectional: true),
            .divertStart(targetIP: "10.0.0.6", gatewayIP: "10.0.0.1", bidirectional: false),
            .forwardEnable,
            .forwardDisable,
            .wifiScan,
            .wifiMonitorOn(interface: "en0", channel: 6),
            .wifiMonitorOff(interface: "en0"),
            .deauthSend(targetMAC: "aa:bb:cc:dd:ee:ff", bssid: "11:22:33:44:55:66", channel: 11),
            .sheepStart(forceTCPFallback: true),
            .sheepStop,
            .killSelective(policy: KillPolicy(targetIP: "10.0.0.5", ports: [443], proto: .tcp, rateLimitKbit: 256)),
            .killSelectiveClear(targetIP: "10.0.0.5"),
            .quicStart(interface: "en0"),
            .quicStop,
            .mdnsStart(interface: "en0"),
            .mdnsStop,
            .tunnelStart(config: "[Interface]\nPrivateKey = test==\nAddress = 10.0.0.1/24\n"),
            .tunnelStop,
            .tunnelStatus,
            .tailscaleUp(config: TailscaleConfig(authKey: "tskey-test", advertiseRoutes: ["10.0.0.0/24"])),
            .tailscaleDown,
            .uninstall,
            .status,
            .portProbe(targetIP: "10.0.0.50", ports: [554, 3702, 8000, 80, 8080]),
            .caTrustInstall("/tmp/pastoral-ca.pem"),
            .caTrustRemove("/tmp/pastoral-ca.pem"),
            .hcxStart(interface: "en0", essid: "Casa", bssid: "aa:bb:cc:dd:ee:ff", seconds: 60),
            .hcxStop
        ]
        for req in cases {
            let data = try LineCodec.encode(req)
            let line = String(decoding: data, as: UTF8.self)
            let decoded = try LineCodec.decode(line, as: HelperRequest.self)
            #expect(decoded == req, "round-trip failed for \(req)")
        }
    }

    @Test("Response round-trips")
    func responseRoundTrip() throws {
        let res = HelperResponse.statusReport(forwarding: true, interface: "en0", bpfAccessible: true)
        let data = try LineCodec.encode(res)
        let line = String(decoding: data, as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("ARP table response decodes")
    func arpTableResponse() throws {
        let res = HelperResponse.arpTable(hosts: [
            ARPEntry(ip: "10.0.0.5", mac: "aa:bb:cc:dd:ee:ff", interface: "en0", expires: 1200)
        ])
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("Error response decodes")
    func errorResponse() throws {
        let res = HelperResponse.error(message: "permission denied")
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("QUIC observation response round-trips")
    func quicObservationResponse() throws {
        let res = HelperResponse.quicObservation(
            sourceIP: "10.0.0.5",
            destIP: "142.250.0.10",
            sni: "www.google.com",
            alpn: ["h3", "h3-29"],
            version: 0x00000001
        )
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("QUIC observation with nil SNI round-trips")
    func quicObservationNilSNI() throws {
        let res = HelperResponse.quicObservation(
            sourceIP: "10.0.0.5",
            destIP: "142.250.0.10",
            sni: nil,
            alpn: [],
            version: 0x00000001
        )
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("mDNS observation round-trips")
    func mdnsObservationRoundTrip() throws {
        let res = HelperResponse.mdnsObservation(
            sourceIP: "10.0.0.5",
            serviceType: "_ipp._tcp.local",
            instance: "MyPrinter._ipp._tcp.local",
            hostname: "printer.local",
            port: 631,
            addresses: ["192.168.1.50"]
        )
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("tunnel status round-trips")
    func tunnelStatusRoundTrip() throws {
        let res = HelperResponse.tunnelStatus(
            interface: "pastoral0", handshake: 4, rx: 12345, tx: 67890
        )
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("port probe result round-trips")
    func portProbeResultRoundTrip() throws {
        let res = HelperResponse.portProbeResult(targetIP: "10.0.0.50", openPorts: [554, 80])
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)
    }

    @Test("Wi-Fi scan result round-trips (empty and populated)")
    func wifiNetworksRoundTrip() throws {
        let empty = HelperResponse.wifiNetworks(networks: [])
        let nets = HelperResponse.wifiNetworks(networks: [
            WiFiNet(ssid: "Casa", bssid: "aa:bb:cc:dd:ee:ff", channel: 6,
                    signal: -52, security: "WPA2", current: true),
            WiFiNet(ssid: "Vizinho", bssid: "11:22:33:44:55:66", channel: 1)
        ])
        for res in [empty, nets] {
            let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
            #expect(try LineCodec.decode(line, as: HelperResponse.self) == res)
        }
    }

    @Test("EAPOL/PMKID capture observation round-trips")
    func hcxCaptureRoundTrip() throws {
        let mic = String(repeating: "c", count: 32)
        let frameHex = "deadbeef"
        let res = HelperResponse.hcxCapture(capture: WpaCapture(
            kind: .handshake(fieldNonce: String(repeating: "b", count: 64),
                             frameHex: frameHex,
                             ekeyMIC: mic,
                             messagePair: 0x13),
            bssid: "aa:bb:cc:dd:ee:ff",
            station: "11:22:33:44:55:66",
            essid: "Casa"))
        let line = String(decoding: try LineCodec.encode(res), as: UTF8.self)
        let decoded = try LineCodec.decode(line, as: HelperResponse.self)
        #expect(decoded == res)

        // And the hashcat -m 22001 line is real hcnpcapng format:
        // `WPA*02*<mic>*<macAP>*<macSTA>*<essidhex>*<nonce>*<eapolhex>*<mp>`
        let expected = "WPA*02*" + mic + "*aabbccddeeff*112233445566*43617361*"
            + String(repeating: "b", count: 64) + "*" + frameHex + "*13"
        if case let .hcxCapture(cap) = decoded {
            #expect(cap.hashcatLine == expected)
        } else {
            Issue.record("decoded response lost the hcxCapture case")
        }
    }
}

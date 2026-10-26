import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for ARP frame assembly and packet decode.
@Suite("ARP frame + packet decode")
struct ARPFrameTests {

    @Test("ARP request frame is 42 bytes and correct structure")
    func requestFrame() {
        let mac = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let frame = ARPFrame.request(
            senderMAC: mac,
            senderIP: [10, 0, 0, 2],
            targetIP: [10, 0, 0, 5]
        )
        #expect(frame.count == 42)

        // Ethernet header
        #expect(Array(frame[0..<6]) == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) // broadcast
        #expect(Array(frame[6..<12]) == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // sender
        #expect(frame[12] == 0x08 && frame[13] == 0x06) // ethertype ARP

        // ARP header
        #expect(frame[14] == 0x00 && frame[15] == 0x01) // htype Ethernet
        #expect(frame[16] == 0x08 && frame[17] == 0x00) // ptype IPv4
        #expect(frame[18] == 0x06) // hlen
        #expect(frame[19] == 0x04) // plen
        #expect(frame[20] == 0x00 && frame[21] == 0x01) // oper: request
        #expect(Array(frame[22..<28]) == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // sha
        #expect(Array(frame[28..<32]) == [10, 0, 0, 2]) // spa
        #expect(Array(frame[32..<38]) == [0, 0, 0, 0, 0, 0]) // tha: zero
        #expect(Array(frame[38..<42]) == [10, 0, 0, 5]) // tpa
    }

    @Test("ARP reply frame has correct operation and target MAC")
    func replyFrame() {
        let sender = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let target = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let frame = ARPFrame.reply(
            senderMAC: sender, senderIP: [10, 0, 0, 1],
            targetMAC: target, targetIP: [10, 0, 0, 5]
        )
        #expect(frame.count == 60) // padded to minimum Ethernet frame size
        #expect(Array(frame[0..<6]) == [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) // dst: target
        #expect(frame[20] == 0x00 && frame[21] == 0x02) // oper: reply
    }

    @Test("Decode Ethernet frame")
    func decodeEthernet() {
        let frame = ARPFrame.request(
            senderMAC: MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            senderIP: [10, 0, 0, 2],
            targetIP: [10, 0, 0, 5]
        )
        let eth = EthernetFrame.decode(frame)
        #expect(eth != nil)
        #expect(eth?.dstMAC == MAC.broadcast)
        #expect(eth?.etherType == 0x0806)
    }

    @Test("Decode ARP reply from a frame")
    func decodeARPReply() {
        let sender = MAC([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let target = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let frame = ARPFrame.reply(
            senderMAC: sender, senderIP: [10, 0, 0, 1],
            targetMAC: target, targetIP: [10, 0, 0, 5]
        )
        let eth = EthernetFrame.decode(frame)!
        let arp = ARPPacket.decode(eth.payload)!
        #expect(arp.operation == ARPOperation.reply)
        #expect(arp.senderMAC == sender)
        #expect(arp.senderIPString == "10.0.0.1")
        #expect(arp.targetMAC == target)
        #expect(arp.targetIPString == "10.0.0.5")
    }

    @Test("Decode IPv4 header")
    func decodeIPv4() {
        // Minimal IPv4 header: 20 bytes, protocol TCP(6), src 10.0.0.1, dst 10.0.0.2
        let header: [UInt8] = [
            0x45, 0x00,       // version=4, IHL=5, DSCP=0
            0x00, 0x28,       // total length = 40
            0x00, 0x01,       // identification
            0x00, 0x00,       // flags + fragment
            0x40, 0x06,       // TTL=64, protocol=TCP
            0x00, 0x00,       // checksum (0 for test)
            10, 0, 0, 1,      // src IP
            10, 0, 0, 2,      // dst IP
            // TCP payload (20 bytes)
            0x00, 0x50,       // src port 80
            0x04, 0xD2,       // dst port 1234
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x10,       // data offset=5, flags=ACK
            0x00, 0x00,       // window
            0x00, 0x00,       // checksum
            0x00, 0x00        // urgent ptr
        ]
        let ip = IPv4Header.decode(header)
        #expect(ip != nil)
        #expect(ip?.protocolNumber == 6)
        #expect(ip?.sourceIPString == "10.0.0.1")
        #expect(ip?.destIPString == "10.0.0.2")
        #expect(ip?.headerLength == 20)
    }

    @Test("Decode TCP header")
    func decodeTCP() {
        let tcpBytes: [UInt8] = [
            0x00, 0x50,       // src port 80
            0x04, 0xD2,       // dst port 1234
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x10,       // data offset=5, ACK
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]
        let tcp = TCPHeader.decode(tcpBytes)
        #expect(tcp != nil)
        #expect(tcp?.sourcePort == 80)
        #expect(tcp?.destPort == 1234)
        #expect(tcp?.isACK == true)
        #expect(tcp?.isSYN == false)
    }

    @Test("MAC string formatting and OUI prefix")
    func macFormatting() {
        let mac = MAC([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        #expect(mac.string == "aa:bb:cc:dd:ee:ff")
        #expect(mac.ouiPrefix == "AA-BB-CC")
    }

    @Test("MAC parse from string")
    func macParse() {
        let mac = MAC(string: "aa:bb:cc:dd:ee:ff")
        #expect(mac != nil)
        #expect(mac?.bytes == [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

        let mac2 = MAC(string: "AA-BB-CC-DD-EE-FF")
        #expect(mac2 != nil)
        #expect(mac2?.bytes == [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

        let bad = MAC(string: "invalid")
        #expect(bad == nil)
    }
}

/// Unit tests for OUI vendor lookup.
@Suite("OUI lookup")
struct OUILookupTests {

    @Test("Lookup vendor by MAC string")
    func lookupByString() {
        let lookup = OUILookup(entries: [
            "AABBCC": "Test Vendor, Inc.",
            "001122": "Another Corp"
        ])
        #expect(lookup.vendor(forMAC: "aa:bb:cc:dd:ee:ff") == "Test Vendor, Inc.")
        #expect(lookup.vendor(forMAC: "00:11:22:33:44:55") == "Another Corp")
        #expect(lookup.vendor(forMAC: "ff:ff:ff:ff:ff:ff") == nil)
    }

    @Test("Lookup vendor by MAC bytes")
    func lookupByBytes() {
        let lookup = OUILookup(entries: ["AABBCC": "Test Vendor"])
        #expect(lookup.vendor(forMACBytes: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) == "Test Vendor")
        #expect(lookup.vendor(forMACBytes: [0x00, 0x00, 0x00]) == nil)
    }

    @Test("Load from JSON data")
    func loadFromJSON() throws {
        let json = #"{"AABBCC":"Vendor X"}"#.data(using: .utf8)!
        let lookup = try OUILookup(jsonData: json)
        #expect(lookup.vendor(forMAC: "aa:bb:cc:00:00:00") == "Vendor X")
    }

    @Test("Handles dash-separated MACs")
    func dashSeparated() {
        let lookup = OUILookup(entries: ["AABBCC": "Dash Corp"])
        #expect(lookup.vendor(forMAC: "AA-BB-CC-DD-EE-FF") == "Dash Corp")
    }
}

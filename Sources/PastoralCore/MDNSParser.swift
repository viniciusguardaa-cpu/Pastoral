import Foundation

/// A parsed mDNS/DNS message. mDNS uses the standard DNS wire format on
/// UDP port 5353, multicast to 224.0.0.251. This parser extracts the
/// records most useful for host/service discovery: A/AAAA (host → IP),
/// PTR (service → instance), SRV (instance → host:port), and TXT
/// (instance properties).
///
/// This is a minimal parser sufficient for passive discovery — it does
/// not handle DNSSEC, EDNS(0) options, or compression pointers that loop.
/// Compression pointers are followed up to a bounded depth.
public struct MDNSMessage: Equatable, Sendable {
    public let questions: [DNSQuestion]
    public let answers: [DNSRecord]
    public let authorities: [DNSRecord]
    public let additionals: [DNSRecord]
}

public struct DNSQuestion: Equatable, Sendable {
    public let name: String
    public let type: UInt16
    public let qclass: UInt16
}

public struct DNSRecord: Equatable, Sendable {
    public let name: String
    public let type: UInt16
    public let rclass: UInt16
    public let ttl: UInt32
    public let data: RecordData

    public enum RecordData: Equatable, Sendable {
        /// A record: IPv4 address.
        case a([UInt8])
        /// AAAA record: IPv6 address.
        case aaaa([UInt8])
        /// PTR record: domain name (uncompressed).
        case ptr(String)
        /// SRV record: priority, weight, port, target.
        case srv(priority: UInt16, weight: UInt16, port: UInt16, target: String)
        /// TXT record: list of key=value strings.
        case txt([String])
        /// Raw rdata for unhandled types.
        case raw([UInt8])
    }

    /// Human-readable record type name.
    public var typeName: String {
        switch type {
        case 1: return "A"
        case 28: return "AAAA"
        case 12: return "PTR"
        case 33: return "SRV"
        case 16: return "TXT"
        case 255: return "ANY"
        default: return "TYPE\(type)"
        }
    }
}

/// Parse a UDP payload as a DNS/mDNS message.
public enum MDNSParser {

    /// Max compression-pointer depth to follow (prevents loops).
    private static let maxPointerDepth = 16

    public static func parse(_ data: [UInt8]) -> MDNSMessage? {
        guard data.count >= 12 else { return nil }
        let qdcount = readU16(data, 4)
        let ancount = readU16(data, 6)
        let nscount = readU16(data, 8)
        let arcount = readU16(data, 10)

        var offset = 12
        var questions: [DNSQuestion] = []
        for _ in 0..<qdcount {
            guard let (name, off) = readName(data, offset) else { return nil }
            offset = off
            guard offset + 4 <= data.count else { return nil }
            let type = readU16(data, offset)
            let qclass = readU16(data, offset + 2)
            offset += 4
            questions.append(DNSQuestion(name: name, type: type, qclass: qclass))
        }

        func readRecords(_ count: UInt16) -> [DNSRecord] {
            var records: [DNSRecord] = []
            for _ in 0..<count {
                guard let (name, off) = readName(data, offset) else { return records }
                offset = off
                guard offset + 10 <= data.count else { return records }
                let type = readU16(data, offset)
                let rclass = readU16(data, offset + 2)
                let ttl = readU32(data, offset + 4)
                let rdlength = Int(readU16(data, offset + 8))
                offset += 10
                guard offset + rdlength <= data.count else { return records }
                let rdata = Array(data[offset..<(offset + rdlength)])
                offset += rdlength
                records.append(DNSRecord(name: name, type: type, rclass: rclass, ttl: ttl,
                                         data: parseRdata(type: type, rdata: rdata, full: data,
                                                         rdataOffset: offset - rdlength)))
            }
            return records
        }

        let answers = readRecords(ancount)
        let authorities = readRecords(nscount)
        let additionals = readRecords(arcount)

        return MDNSMessage(questions: questions, answers: answers,
                           authorities: authorities, additionals: additionals)
    }

    // MARK: - RDATA parsing

    private static func parseRdata(type: UInt16, rdata: [UInt8], full: [UInt8], rdataOffset: Int) -> DNSRecord.RecordData {
        switch type {
        case 1: // A
            guard rdata.count == 4 else { return .raw(rdata) }
            return .a(rdata)
        case 28: // AAAA
            guard rdata.count == 16 else { return .raw(rdata) }
            return .aaaa(rdata)
        case 12: // PTR — name may use compression pointers into the full message.
            if let (name, _) = readName(full, rdataOffset) { return .ptr(name) }
            return .raw(rdata)
        case 33: // SRV
            guard rdata.count >= 7 else { return .raw(rdata) }
            let priority = readU16(rdata, 0)
            let weight = readU16(rdata, 2)
            let port = readU16(rdata, 4)
            // Target name starts at rdataOffset + 6 in the full message.
            if let (target, _) = readName(full, rdataOffset + 6) {
                return .srv(priority: priority, weight: weight, port: port, target: target)
            }
            return .raw(rdata)
        case 16: // TXT
            return .txt(parseTXT(rdata))
        default:
            return .raw(rdata)
        }
    }

    /// TXT records are a sequence of length-prefixed strings.
    private static func parseTXT(_ rdata: [UInt8]) -> [String] {
        var strings: [String] = []
        var i = 0
        while i < rdata.count {
            let len = Int(rdata[i])
            i += 1
            guard i + len <= rdata.count else { break }
            let bytes = Array(rdata[i..<(i + len)])
            if let s = String(bytes: bytes, encoding: .utf8) { strings.append(s) }
            i += len
        }
        return strings
    }

    // MARK: - Name decoding with compression

    /// Read a domain name starting at `offset`, following compression
    /// pointers. Returns the name (labels joined by ".") and the offset
    /// just past the name (in the original, non-pointer portion).
    private static func readName(_ data: [UInt8], _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var offset = start
        var depth = 0
        var firstPast = -1   // offset after the first (non-pointer) label
        while offset < data.count {
            let len = Int(data[offset])
            if len == 0 {
                if firstPast < 0 { firstPast = offset + 1 }
                let name = labels.isEmpty ? "" : labels.joined(separator: ".")
                return (name, firstPast)
            }
            // Compression pointer: top two bits set.
            if (len & 0xC0) == 0xC0 {
                if firstPast < 0 { firstPast = offset + 2 }
                guard offset + 1 < data.count else { return nil }
                let ptr = ((len & 0x3F) << 8) | Int(data[offset + 1])
                depth += 1
                if depth > maxPointerDepth { return nil }
                offset = ptr
                continue
            }
            // Normal label.
            offset += 1
            guard offset + len <= data.count else { return nil }
            let label = String(bytes: data[offset..<(offset + len)], encoding: .utf8) ?? ""
            labels.append(label)
            offset += len
        }
        return nil
    }

    // MARK: - Helpers

    private static func readU16(_ data: [UInt8], _ off: Int) -> UInt16 {
        (UInt16(data[off]) << 8) | UInt16(data[off + 1])
    }
    private static func readU32(_ data: [UInt8], _ off: Int) -> UInt32 {
        (UInt32(data[off]) << 24) | (UInt32(data[off + 1]) << 16)
            | (UInt32(data[off + 2]) << 8) | UInt32(data[off + 3])
    }
}

/// A discovered mDNS service, derived from parsed records. Aggregates
/// PTR → SRV → A/AAAA into a single service description.
public struct MDNSService: Equatable, Sendable {
    public let instance: String   // e.g. "My Printer._ipp._tcp.local"
    public let serviceType: String // e.g. "_ipp._tcp.local"
    public let hostname: String?  // target from SRV
    public let port: UInt16?      // port from SRV
    public let addresses: [String] // IPv4/IPv6 from A/AAAA
    public let txt: [String]

    /// Extract services from a parsed mDNS message by correlating PTR,
    /// SRV, and A/AAAA records.
    public static func extract(from msg: MDNSMessage) -> [MDNSService] {
        // Collect all records (answers + additionals) for correlation.
        let all = msg.answers + msg.additionals
        // Map instance name → SRV record.
        var srvs: [String: DNSRecord.RecordData] = [:]
        // Map hostname → addresses.
        var addrs: [String: [String]] = [:]
        // PTR records: serviceType → [instance names].
        var ptrs: [String: [String]] = [:]

        for r in all {
            switch r.data {
            case .ptr(let target):
                ptrs[r.name, default: []].append(target)
            case .srv(_, _, let port, let target):
                srvs[r.name] = r.data
                _ = port
            case .a(let bytes):
                addrs[r.name, default: []].append(bytes.map { String($0) }.joined(separator: "."))
            case .aaaa(let bytes):
                addrs[r.name, default: []].append(formatIPv6(bytes))
            default:
                break
            }
        }

        var services: [MDNSService] = []
        for (serviceType, instances) in ptrs {
            for instance in instances {
                var hostname: String? = nil
                var port: UInt16? = nil
                var txt: [String] = []
                if case .srv(_, _, let p, let t) = srvs[instance] {
                    hostname = t
                    port = p
                }
                // TXT for this instance.
                for r in all where r.name == instance {
                    if case .txt(let strs) = r.data { txt = strs }
                }
                let addresses = hostname.flatMap { addrs[$0] } ?? []
                services.append(MDNSService(
                    instance: instance,
                    serviceType: serviceType,
                    hostname: hostname,
                    port: port,
                    addresses: addresses,
                    txt: txt
                ))
            }
        }
        return services
    }

    /// Format 16 bytes as a colon-separated IPv6 address (compressed
    /// zero runs are not collapsed — sufficient for display).
    static func formatIPv6(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return "" }
        var parts: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            parts.append(String(format: "%02x%02x", bytes[i], bytes[i + 1]))
        }
        return parts.joined(separator: ":")
    }
}

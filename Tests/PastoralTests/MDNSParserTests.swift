import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the mDNS/DNS wire-format parser (phase 4).
@Suite("mDNS parser")
struct MDNSParserTests {

    // MARK: - Builders

    /// Build a minimal DNS message with one A record.
    func buildARecord(name: String, ip: [UInt8]) -> [UInt8] {
        var msg: [UInt8] = []
        // Header: id=0, flags=0x8400 (authoritative), qd=0, an=1, ns=0, ar=0
        msg.append(contentsOf: [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0])
        // Answer: name + type A + class IN + ttl + rdlength + rdata
        encodeName(name, into: &msg)
        msg.append(contentsOf: [0, 1])       // type A
        msg.append(contentsOf: [0, 1])       // class IN
        msg.append(contentsOf: [0, 0, 0, 120]) // ttl 120
        msg.append(contentsOf: [0, 4])       // rdlength 4
        msg.append(contentsOf: ip)
        return msg
    }

    /// Build a DNS message with a PTR + SRV + A (typical mDNS service set).
    func buildServiceMessage() -> [UInt8] {
        var msg: [UInt8] = []
        // Header: id=0, flags=0x8400, qd=0, an=3, ns=0, ar=0
        msg.append(contentsOf: [0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0])
        // Record 1: PTR _ipp._tcp.local → MyPrinter._ipp._tcp.local
        encodeName("_ipp._tcp.local", into: &msg)
        msg.append(contentsOf: [0, 12])      // type PTR
        msg.append(contentsOf: [0, 1])       // class IN
        msg.append(contentsOf: [0, 0, 0, 120]) // ttl
        let ptrName = "MyPrinter._ipp._tcp.local"
        var ptrRdata: [UInt8] = []
        encodeName(ptrName, into: &ptrRdata)
        msg.append(contentsOf: [0, UInt8(ptrRdata.count)])
        msg.append(contentsOf: ptrRdata)
        // Record 2: SRV MyPrinter._ipp._tcp.local → printer.local:631
        encodeName("MyPrinter._ipp._tcp.local", into: &msg)
        msg.append(contentsOf: [0, 33])      // type SRV
        msg.append(contentsOf: [0, 1])       // class IN
        msg.append(contentsOf: [0, 0, 0, 120]) // ttl
        var srvRdata: [UInt8] = []
        srvRdata.append(contentsOf: [0, 0])   // priority 0
        srvRdata.append(contentsOf: [0, 0])   // weight 0
        srvRdata.append(contentsOf: [2, 127]) // port 639... wait, 631 = 0x0277
        srvRdata[srvRdata.count - 2] = 0x02
        srvRdata[srvRdata.count - 1] = 0x77
        encodeName("printer.local", into: &srvRdata)
        msg.append(contentsOf: [0, UInt8(srvRdata.count)])
        msg.append(contentsOf: srvRdata)
        // Record 3: A printer.local → 192.168.1.50
        encodeName("printer.local", into: &msg)
        msg.append(contentsOf: [0, 1])       // type A
        msg.append(contentsOf: [0, 1])       // class IN
        msg.append(contentsOf: [0, 0, 0, 120]) // ttl
        msg.append(contentsOf: [0, 4])       // rdlength 4
        msg.append(contentsOf: [192, 168, 1, 50])
        return msg
    }

    /// Encode a domain name as length-prefixed labels + null terminator.
    func encodeName(_ name: String, into msg: inout [UInt8]) {
        if name.isEmpty {
            msg.append(0)
            return
        }
        for label in name.split(separator: ".") {
            msg.append(UInt8(label.count))
            msg.append(contentsOf: Array(label.utf8))
        }
        msg.append(0)
    }

    // MARK: - Tests

    @Test("Parses a single A record")
    func parseARecord() throws {
        let bytes = buildARecord(name: "host.local", ip: [192, 168, 1, 10])
        let msg = try #require(MDNSParser.parse(bytes))
        #expect(msg.answers.count == 1)
        let r = msg.answers[0]
        #expect(r.name == "host.local")
        #expect(r.type == 1)
        if case .a(let ip) = r.data {
            #expect(ip == [192, 168, 1, 10])
        } else {
            Issue.record("expected A record")
        }
    }

    @Test("Parses a PTR record")
    func parsePTR() throws {
        let bytes = buildServiceMessage()
        let msg = try #require(MDNSParser.parse(bytes))
        let ptrs = msg.answers.filter { $0.type == 12 }
        #expect(ptrs.count == 1)
        if case .ptr(let target) = ptrs[0].data {
            #expect(target == "MyPrinter._ipp._tcp.local")
        } else {
            Issue.record("expected PTR record")
        }
    }

    @Test("Parses an SRV record with port and target")
    func parseSRV() throws {
        let bytes = buildServiceMessage()
        let msg = try #require(MDNSParser.parse(bytes))
        let srvs = msg.answers.filter { $0.type == 33 }
        #expect(srvs.count == 1)
        if case .srv(_, _, let port, let target) = srvs[0].data {
            #expect(port == 631)
            #expect(target == "printer.local")
        } else {
            Issue.record("expected SRV record")
        }
    }

    @Test("Extracts correlated services from PTR+SRV+A")
    func extractServices() throws {
        let bytes = buildServiceMessage()
        let msg = try #require(MDNSParser.parse(bytes))
        let services = MDNSService.extract(from: msg)
        #expect(services.count == 1)
        let svc = services[0]
        #expect(svc.serviceType == "_ipp._tcp.local")
        #expect(svc.instance == "MyPrinter._ipp._tcp.local")
        #expect(svc.hostname == "printer.local")
        #expect(svc.port == 631)
        #expect(svc.addresses.contains("192.168.1.50"))
    }

    @Test("Parses a TXT record with multiple strings")
    func parseTXT() throws {
        var msg: [UInt8] = []
        msg.append(contentsOf: [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0])
        encodeName("dev._tcp.local", into: &msg)
        msg.append(contentsOf: [0, 16])      // type TXT
        msg.append(contentsOf: [0, 1])       // class IN
        msg.append(contentsOf: [0, 0, 0, 120]) // ttl
        var rdata: [UInt8] = []
        // "model=ABC"
        rdata.append(9)
        rdata.append(contentsOf: Array("model=ABC".utf8))
        // "ver=1"
        rdata.append(5)
        rdata.append(contentsOf: Array("ver=1".utf8))
        msg.append(contentsOf: [0, UInt8(rdata.count)])
        msg.append(contentsOf: rdata)
        let parsed = try #require(MDNSParser.parse(msg))
        if case .txt(let strs) = parsed.answers[0].data {
            #expect(strs == ["model=ABC", "ver=1"])
        } else {
            Issue.record("expected TXT record")
        }
    }

    @Test("Handles compression pointers in PTR target")
    func compressionPointer() throws {
        // Build a message where the PTR target uses a compression pointer
        // back to a name earlier in the message.
        var msg: [UInt8] = []
        msg.append(contentsOf: [0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0])
        // Record 1: A "svc.local" → 10.0.0.1 (name at offset 12)
        let nameOffset1 = UInt16(msg.count)
        encodeName("svc.local", into: &msg)
        msg.append(contentsOf: [0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1])
        // Record 2: PTR "ptr.local" → "svc.local" via compression pointer.
        encodeName("ptr.local", into: &msg)
        msg.append(contentsOf: [0, 12, 0, 1, 0, 0, 0, 120])
        var rdata: [UInt8] = []
        // Compression pointer to nameOffset1.
        rdata.append(UInt8(0xC0 | (nameOffset1 >> 8)))
        rdata.append(UInt8(nameOffset1 & 0xFF))
        msg.append(contentsOf: [0, UInt8(rdata.count)])
        msg.append(contentsOf: rdata)
        let parsed = try #require(MDNSParser.parse(msg))
        let ptr = parsed.answers.first { $0.type == 12 }
        if case .ptr(let target) = ptr?.data {
            #expect(target == "svc.local")
        } else {
            Issue.record("expected PTR with compression")
        }
    }

    @Test("Returns nil for too-short data")
    func tooShort() {
        #expect(MDNSParser.parse([0, 0, 0]) == nil)
        #expect(MDNSParser.parse([]) == nil)
    }

    @Test("Parses a question section")
    func parseQuestion() throws {
        var msg: [UInt8] = []
        // Header: id=0, flags=0, qd=1, an=0, ns=0, ar=0
        msg.append(contentsOf: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        encodeName("_ipp._tcp.local", into: &msg)
        msg.append(contentsOf: [0, 12])  // type PTR
        msg.append(contentsOf: [0, 1])   // class IN
        let parsed = try #require(MDNSParser.parse(msg))
        #expect(parsed.questions.count == 1)
        #expect(parsed.questions[0].name == "_ipp._tcp.local")
        #expect(parsed.questions[0].type == 12)
    }

    @Test("IPv6 formatting")
    func ipv6Format() {
        let bytes: [UInt8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let s = MDNSService.formatIPv6(bytes)
        #expect(s == "fe80:0000:0000:0000:0000:0000:0000:0001")
    }
}

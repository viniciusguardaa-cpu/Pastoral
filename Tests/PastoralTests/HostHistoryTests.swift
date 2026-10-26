import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for host appearance/disappearance history (phase 4).
@Suite("Host history")
struct HostHistoryTests {

    @Test("First scan records appearances")
    func firstScan() {
        var history = HostHistory()
        let now = Date()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: "Apple"),
            (mac: "aa:bb:cc:dd:ee:02", ip: "10.0.0.6", vendor: nil)
        ], at: now)
        #expect(history.sightings.count == 2)
        let appeared = history.events.filter { $0.kind == .appeared }
        #expect(appeared.count == 2)
    }

    @Test("Host that disappears emits vanished")
    func vanished() {
        var history = HostHistory()
        let t1 = Date()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: nil)
        ], at: t1)
        let t2 = t1.addingTimeInterval(60)
        history.recordScan([], at: t2)  // no hosts visible
        let vanished = history.events.filter { $0.kind == .vanished }
        #expect(vanished.count == 1)
        #expect(vanished[0].mac == "aa:bb:cc:dd:ee:01")
    }

    @Test("Host that changes IP emits changedIP")
    func changedIP() {
        var history = HostHistory()
        let t1 = Date()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: nil)
        ], at: t1)
        let t2 = t1.addingTimeInterval(60)
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.99", vendor: nil)
        ], at: t2)
        let changed = history.events.filter { $0.kind == .changedIP }
        #expect(changed.count == 1)
        #expect(changed[0].ip == "10.0.0.99")
        #expect(changed[0].previousIP == "10.0.0.5")
    }

    @Test("Stable host emits no new events on second scan")
    func stable() {
        var history = HostHistory()
        let t1 = Date()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: nil)
        ], at: t1)
        let eventsAfterFirst = history.events.count
        let t2 = t1.addingTimeInterval(60)
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: nil)
        ], at: t2)
        #expect(history.events.count == eventsAfterFirst)  // no new events
    }

    @Test("knownHosts returns latest sighting per MAC")
    func knownHosts() {
        var history = HostHistory()
        let t1 = Date()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: "Apple")
        ], at: t1)
        let t2 = t1.addingTimeInterval(60)
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.6", vendor: "Apple")
        ], at: t2)
        let known = history.knownHosts
        #expect(known.count == 1)
        #expect(known[0].lastIP == "10.0.0.6")
        #expect(known[0].vendor == "Apple")
    }

    @Test("Sightings log is bounded")
    func bounded() {
        var history = HostHistory()
        for i in 0..<100 {
            history.recordScan([
                (mac: "aa:bb:cc:dd:ee:\(String(format: "%02x", i))", ip: "10.0.0.\(i)", vendor: nil)
            ], at: Date().addingTimeInterval(TimeInterval(i)), maxSightings: 50)
        }
        #expect(history.sightings.count <= 50)
    }

    @Test("HostHistory round-trips through JSON")
    func codable() throws {
        var history = HostHistory()
        history.recordScan([
            (mac: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", vendor: "Apple")
        ])
        let data = try JSONEncoder().encode(history)
        let decoded = try JSONDecoder().decode(HostHistory.self, from: data)
        #expect(decoded.sightings.count == history.sightings.count)
        #expect(decoded.events.count == history.events.count)
    }

    @Test("Multiple hosts appear and some vanish")
    func mixed() {
        var history = HostHistory()
        let t1 = Date()
        history.recordScan([
            (mac: "aa:aa:aa:aa:aa:01", ip: "10.0.0.1", vendor: nil),
            (mac: "aa:aa:aa:aa:aa:02", ip: "10.0.0.2", vendor: nil),
            (mac: "aa:aa:aa:aa:aa:03", ip: "10.0.0.3", vendor: nil)
        ], at: t1)
        let t2 = t1.addingTimeInterval(60)
        history.recordScan([
            (mac: "aa:aa:aa:aa:aa:01", ip: "10.0.0.1", vendor: nil),
            (mac: "aa:aa:aa:aa:aa:04", ip: "10.0.0.4", vendor: nil)  // new
        ], at: t2)
        // After second scan: 02 and 03 vanished, 04 appeared.
        let vanished = history.events.filter { $0.kind == .vanished }.map(\.mac).sorted()
        #expect(vanished == ["aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:03"])
        let appeared = history.events.filter { $0.kind == .appeared && $0.timestamp == t2 }
        #expect(appeared.count == 1)
        #expect(appeared[0].mac == "aa:aa:aa:aa:aa:04")
    }
}

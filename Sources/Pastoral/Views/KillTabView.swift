import SwiftUI
import PastoralCore

/// Kill tab: list of LAN hosts with a per-row cut/release toggle, live
/// throughput sparkline, a counter of how many are cut, and a global
/// "kill everyone" button (respects the whitelist).
struct KillTabView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("Hosts")
                    .font(.headline)
                if state.isScanning {
                    ProgressView().scaleEffect(0.7)
                }
                Spacer()
                Text("\(state.killedCount) cortados")
                    .font(.callout)
                    .foregroundStyle(state.killedCount > 0 ? .red : .secondary)
                    .monospacedDigit()
                Text("\(state.divertedCount) desviados")
                    .font(.callout)
                    .foregroundStyle(state.divertedCount > 0 ? .orange : .secondary)
                    .monospacedDigit()
                Divider().frame(height: 16)
                Button(action: { Task { await state.scanARP() } }) {
                    Label("Buscar", systemImage: "antenna.radiowaves.left.and.right")
                }
                .disabled(state.isScanning)
                Toggle(isOn: $state.killShowCamerasOnly) {
                    Label("Só câmeras", systemImage: "camera")
                        .labelStyle(.titleAndIcon)
                }
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Filtrar a lista para mostrar apenas câmeras detectadas")
                Button(action: { Task { await state.divertAll() } }) {
                    Label("Divertir todos", systemImage: "arrow.triangle.branch")
                }
                .disabled(state.hosts.isEmpty)
                .help("Forçar o tráfego de todos os hosts a passar por nós (modo gateway forçado)")
                Button(role: .destructive, action: { Task { await state.killAll() } }) {
                    Label("Kill everyone", systemImage: "bolt.slash")
                }
                .disabled(state.hosts.isEmpty)
                Button(action: { Task { await state.restoreAll() } }) {
                    Label("Restaurar", systemImage: "arrow.counterclockwise")
                }
                .disabled(!state.hasPendingRecovery || state.isRestoring)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Host list
            if state.hosts.isEmpty {
                emptyState
            } else {
                List {
                    ForEach(state.hosts.filter { !state.killShowCamerasOnly || $0.kind == .camera }) { host in
                        KillHostRow(state: state, host: host)
                    }
                }
                .listStyle(.inset)
                .scrollContentBackground(.hidden)
                .sheet(item: Binding(get: {
                    state.selectiveSheetHostID.flatMap { id in state.hosts.first { $0.id == id } }
                }, set: { newValue in
                    state.selectiveSheetHostID = newValue?.id
                })) { host in
                    SelectivePolicySheet(state: state, host: host)
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "network.slash")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Nenhum dispositivo descoberto")
                .foregroundStyle(.secondary)
            Text("Use Buscar para atualizar os dispositivos da rede local.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Sheet for configuring a custom selective Kill policy: drop or
/// rate-limit, with port/protocol/DSCP filters.
struct SelectivePolicySheet: View {
    @Bindable var state: AppState
    let host: Host

    @State private var mode: SheetMode = .drop
    @State private var portText: String = ""
    @State private var protoChoice: KillProto = .tcp
    @State private var rateKbit: Int = 256
    @State private var useDSCP = false
    @State private var dscp: Int = 0
    @Environment(\.dismiss) private var dismiss

    enum SheetMode: String, CaseIterable {
        case drop = "Drop (bloquear)"
        case rateLimit = "Rate-limit (limitar banda)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Kill seletivo — \(host.ip)")
                    .font(.headline)
                Spacer()
                Button("Cancelar") { dismiss() }
            }

            Picker("Modo", selection: $mode) {
                ForEach(SheetMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            HStack {
                Text("Portas (vírgula; vazio = todas):")
                    .font(.caption)
                TextField("ex: 53, 80, 443", text: $portText)
                    .frame(maxWidth: 160)
            }

            Picker("Protocolo", selection: $protoChoice) {
                Text("TCP").tag(KillProto.tcp)
                Text("UDP").tag(KillProto.udp)
            }
            .pickerStyle(.segmented)
            .frame(width: 200)

            if mode == .rateLimit {
                HStack {
                    Text("Banda (Kbit/s):")
                    TextField("256", value: $rateKbit, format: .number)
                        .frame(width: 100)
                    Stepper("", value: $rateKbit, in: 8...102400, step: 64)
                        .labelsHidden()
                }
            }

            Toggle("Filtrar por DSCP", isOn: $useDSCP)
            if useDSCP {
                HStack {
                    Text("DSCP:")
                    TextField("0", value: $dscp, format: .number)
                        .frame(width: 80)
                }
            }

            Spacer()

            HStack {
                Spacer()
                Button("Aplicar") {
                    let ports = portText.split(separator: ",")
                        .compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }
                    let policy = KillPolicy(
                        targetIP: host.ip,
                        ports: ports,
                        proto: protoChoice,
                        dscp: useDSCP ? UInt8(clamping: dscp) : nil,
                        rateLimitKbit: mode == .rateLimit ? rateKbit : nil
                    )
                    Task {
                        await state.applySelectivePolicy(policy)
                        dismiss()
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 420, height: 360)
    }
}

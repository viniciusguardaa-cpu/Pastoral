import SwiftUI

// MARK: - Friendly naming for lay users

extension Host {
    /// Best plain-language name we can derive offline: hostname, then the
    /// card manufacturer, then the coarse kind badge.
    var easyName: String {
        if let h = hostname, !h.isEmpty { return h }
        if let v = vendor, !v.isEmpty { return v }
        switch kind {
        case .camera: return "Câmera"
        case .tv: return "TV"
        case .generic: return "Dispositivo"
        }
    }

    var easyDetails: String {
        [ip, mac].joined(separator: " · ")
    }
}

// MARK: - Wizard root

/// Guided 3-step mode for people who don't want to learn jargon:
/// pick devices → start → see what they're looking at. All the raw tools
/// stay available in Avançado mode.
struct EasyModeView: View {
    @Bindable var state: AppState
    @State private var alertMessage = ""
    @State private var showAlert = false

    var body: some View {
        VStack(spacing: 0) {
            stepHeader
            Divider()
            ZStack {
                switch state.easyStep {
                case .network: EasyNetworkStep(state: state, goNext: { attemptNext(.start) })
                case .start: EasyStartStep(state: state, goNetwork: { state.easyStep = .network })
                case .watch: EasyWatchStep(state: state, goStart: { state.easyStep = .start })
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .alert("Quase lá", isPresented: $showAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(alertMessage)
        }
    }

    private func attemptNext(_ step: EasyStep) {
        if step == .start && state.easySelectedMACs.isEmpty {
            alertMessage = "Primeiro marque pelo menos um dispositivo para observar, na etapa 1."
            showAlert = true
            return
        }
        state.easyStep = step
    }

    private func canReach(_ step: EasyStep) -> Bool {
        step == .network || !state.easySelectedMACs.isEmpty
    }

    private var stepHeader: some View {
        HStack(spacing: 0) {
            ForEach(EasyStep.allCases) { step in
                Button {
                    if canReach(step) { state.easyStep = step } else { attemptNext(step) }
                } label: {
                    HStack(spacing: 8) {
                        ZStack {
                            Circle()
                                .strokeBorder(currentColor(for: step), lineWidth: 2)
                                .frame(width: 26, height: 26)
                            Text("\(step.rawValue)")
                                .font(.callout.bold())
                                .foregroundStyle(step == state.easyStep ? .white : currentColor(for: step))
                        }
                        .background(
                            Circle()
                                .fill(step == state.easyStep ? Color.accentColor : .clear)
                                .frame(width: 26, height: 26)
                        )
                        Text(step.title)
                            .font(.callout.weight(step == state.easyStep ? .semibold : .regular))
                            .foregroundStyle(step == state.easyStep ? .primary : .secondary)
                    }
                }
                .buttonStyle(.plain)
                .disabled(step == state.easyStep)

                if step != EasyStep.watch {
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 12)
                }
            }
            Spacer()
            Text(state.helper.responding
                 ? "Modo guiado · ajuda em cada passo"
                 : "Modo guiado · helper offline")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func currentColor(for step: EasyStep) -> Color {
        if step.rawValue < state.easyStep.rawValue { return .green }
        return step == state.easyStep ? Color.accentColor : Color.secondary.opacity(0.5)
    }
}

// MARK: - Step 1: choose devices

private struct EasyNetworkStep: View {
    @Bindable var state: AppState
    let goNext: () -> Void

    var body: some View {
        VStack(spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Rede Wi-Fi: \(state.network.ssid ?? "não detectada")",
                          systemImage: "wifi")
                        .font(.headline)
                    Text(sepline)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if state.hosts.isEmpty {
                        Text("Nenhum dispositivo listado ainda — clique em “Buscar dispositivos”.")
                            .font(.callout)
                            .foregroundStyle(.orange)
                    }
                }
                Spacer()
                Button {
                    Task { await state.scanARP() }
                } label: {
                    Label(state.isScanning ? "Buscando…" : "Buscar dispositivos",
                          systemImage: state.isScanning ? "arrow.triangle.2.circlepath" : "binoculars")
                }
                .disabled(state.isScanning || !state.helper.responding)
            }

            List {
                ForEach(state.observableHosts) { host in
                    HStack(spacing: 10) {
                        Toggle(isOn: Binding(
                            get: { state.easySelectedMACs.contains(host.id) },
                            set: { on in
                                if on { state.easySelectedMACs.insert(host.id) }
                                else { state.easySelectedMACs.remove(host.id) }
                            })
                        ) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(host.easyName).font(.body)
                                    switch host.kind {
                                    case .camera:
                                        Label("", systemImage: "camera.fill")
                                            .labelStyle(.iconOnly).foregroundStyle(.purple)
                                    case .tv:
                                        Label("", systemImage: "tv.fill")
                                            .labelStyle(.iconOnly).foregroundStyle(.blue)
                                    case .generic: EmptyView()
                                    }
                                    if host.isDiverted {
                                        Label("em rota", systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                                            .font(.caption2)
                                            .foregroundStyle(.green)
                                    }
                                }
                                Text(host.easyDetails)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.checkbox)
                        .help("Marcar para observar este dispositivo")
                        Spacer()
                    }
                }
            }
            .listStyle(.inset)

            HStack {
                Text(state.easySelectedMACs.isEmpty
                     ? "Marque o que você quer observar"
                     : "\(state.easySelectedMACs.count) dispositivo(s) marcados")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(action: goNext) {
                    Label("Continuar", systemImage: "chevron.right")
                        .fontWeight(.semibold)
                }
                .buttonStyle(.borderedProminent)
                .disabled(state.easySelectedMACs.isEmpty)
            }
        }
        .padding(14)
    }

    private var sepline: String {
        var parts: [String] = []
        if let ip = state.network.localIP { parts.append("seu Mac: \(ip)") }
        if let gw = state.network.gatewayIP { parts.append("roteador: \(gw)") }
        parts.append(state.helper.responding
                     ? "tudo pronto"
                     : "instale o helper (cartão amarelo abaixo)")
        return parts.joined(separator: " · ")
    }
}

// MARK: - Step 2: one big start button

private struct EasyStartStep: View {
    @Bindable var state: AppState
    let goNetwork: () -> Void

    private var selectedHosts: [Host] {
        state.observableHosts.filter { state.easySelectedMACs.contains($0.id) }
    }

    var body: some View {
        VStack(spacing: 16) {
            if state.sheepRunning {
                runningCard
            } else {
                startCard
            }
            caNote
            if let err = state.lastError {
                Text(err)
                    .font(.callout)
                    .foregroundStyle(.red)
            }
            Spacer()
        }
        .padding(20)
    }

    private var runningCard: some View {
        VStack(spacing: 14) {
            Image(systemName: "eye.circle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("Observação ativa em \(selectedHosts.count) dispositivo(s)")
                .font(.title3.bold())
            Text(selectedHosts.map(\.easyName).joined(separator: ", "))
                .foregroundStyle(.secondary)
            Button(role: .destructive) {
                Task { await state.easyStop() }
            } label: {
                Label(state.easyBusyPhase ?? "Parar e restaurar a rede",
                      systemImage: "stop.circle.fill")
                    .font(.title3)
                    .padding(.horizontal, 8)
            }
            .buttonStyle(.borderedProminent)
            .disabled(state.easyBusyPhase != nil)
        }
        .frame(maxWidth: 460)
        .padding(.vertical, 30)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.green.opacity(0.08)))
    }

    private var startCard: some View {
        VStack(spacing: 14) {
            Image(systemName: "play.circle.fill")
                .font(.system(size: 44))
                .foregroundStyle(Color.accentColor)
            Text("Vamos observar \(selectedHosts.count) dispositivo(s)")
                .font(.title3.bold())
            Text(selectedHosts.map(\.easyName).joined(separator: ", "))
                .foregroundStyle(.secondary)
            Button {
                Task { await state.easyStart() }
            } label: {
                Label(state.easyBusyPhase ?? "Começar a observar",
                      systemImage: state.easyBusyPhase != nil ? "arrow.triangle.2.circlepath" : "play.fill")
                    .font(.title3)
                    .padding(.horizontal, 8)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(state.easyBusyPhase != nil || state.easySelectedMACs.isEmpty)

            if state.easySelectedMACs.isEmpty {
                Button("Escolher dispositivos") { goNetwork() }
                    .font(.callout)
            }
        }
        .frame(maxWidth: 460)
        .padding(.vertical, 30)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.accentColor.opacity(0.06)))
    }

    private var caNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Dica importante", systemImage: "lightbulb.fill")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.orange)
            Text("""
            Os sites comuns usam HTTPS (cadeado). Sem um pequeno arquivo de confiança \
            instalado no aparelho observado, você só verá o **nome** dos sites que ele \
            abre, não o conteúdo. O Pastoral gera esse arquivo — ele fica disponível na \
            aba Avançado (Sheep → botão CA).
            """)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: 560, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(0.07)))
    }
}

// MARK: - Step 3: what they're seeing

private struct EasyWatchStep: View {
    @Bindable var state: AppState
    let goStart: () -> Void
    @State private var search = ""

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                TextField("Buscar site ou app…", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Spacer()
                if state.sheepRunning {
                    Label("ao vivo", systemImage: "dot.radiowaves.left.and.right")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(.green)
                }
            }

            if !state.sheepRunning {
                ContentUnavailableView {
                    Label("Nada rodando agora", systemImage: "pause.circle")
                } description: {
                    Text("Vá na etapa 2 e toque em “Começar a observar”.")
                } actions: {
                    Button("Ir para Começar") { goStart() }
                        .buttonStyle(.borderedProminent)
                }
            } else if filtered.isEmpty {
                ContentUnavailableView {
                    Label("Ainda sem registros", systemImage: "magnifyingglass")
                } description: {
                    Text("""
                    Os sites aparecem aqui assim que os dispositivos observados \
                    navegam. Se só aparecerem nomes sem conteúdo, veja a dica da \
                    etapa 2 sobre o arquivo de confiança (CA).
                    """)
                }
            } else {
                List(filtered) { item in
                    HStack(spacing: 10) {
                        Image(systemName: item.isSecure ? "lock.shield.fill" : "globe")
                            .foregroundStyle(item.isSecure ? .green : .blue)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.site)
                                .font(.body.weight(.medium))
                                .lineLimit(1)
                            Text(item.count == 1
                                 ? "1 atividade"
                                 : "\(item.count) atividades")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(item.lastSeen.formatted(date: .omitted, time: .shortened))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.inset)
            }
        }
        .padding(14)
    }

    private var filtered: [AppState.SiteActivity] {
        let all = state.siteActivity
        guard !search.isEmpty else { return all }
        return all.filter { $0.site.localizedCaseInsensitiveContains(search) }
    }
}

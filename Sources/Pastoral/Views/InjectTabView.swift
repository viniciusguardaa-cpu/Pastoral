import SwiftUI
import PastoralCore

/// Inject tab: pick an image (or a folder for rotation), choose the scope,
/// and replace images in the traffic of intercepted hosts. TVs detected
/// via Bonjour/OUI get a one-click "show my image" action.
///
/// Pipeline under the hood: divert (ARP spoof) → Sheep rdr → proxy
/// response rewriting. HTTPS only rewrites where the victim trusts the
/// Pastoral CA — TVs without the CA get HTTP-only injection.
struct InjectTabView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                Circle()
                    .fill(state.injectionActive ? Color.green : Color.gray)
                    .frame(width: 10, height: 10)
                Text(state.injectionActive ? "Injetando" : "Parado")
                    .font(.headline)
                    .foregroundStyle(state.injectionActive ? .green : .secondary)

                Spacer()

                Toggle("", isOn: Binding(
                    get: { state.injectionRule.enabled },
                    set: { on in
                        state.injectionRule.enabled = on
                        if on { state.applyInjection() } else { state.stopInjection() }
                    }
                ))
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(state.injectionImages.isEmpty)

                Button(role: .destructive,
                       action: { Task { await state.revertAll() } }) {
                    Label("Reverter tudo", systemImage: "arrow.counterclockwise")
                }
                .help("Desliga injeção, interceptação e restaura a rede")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            HSplitView {
                configPanel
                    .frame(minWidth: 280, idealWidth: 320)
                tvPanel
                    .frame(minWidth: 320)
            }
        }
        .onAppear { state.startTVDetection() }
    }

    // MARK: - Left: image + scope + options

    private var configPanel: some View {
        Form {
            Section("Imagem injetada") {
                HStack {
                    if let first = state.injectionImages.first,
                       let nsImage = NSImage(data: first.data) {
                        Image(nsImage: nsImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 64, height: 64)
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                    } else {
                        Image(systemName: "photo")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                            .frame(width: 64, height: 64)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(state.injectionSourceLabel ?? "Nenhuma imagem")
                            .font(.callout)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        HStack {
                            Button("Arquivo…") { state.pickInjectionImage() }
                            Button("Pasta…") { state.pickInjectionFolder() }
                        }
                        .controlSize(.small)
                    }
                }
            }

            Section("Escopo") {
                Picker("Substituir em", selection: Binding(
                    get: { scopeKind },
                    set: { setScopeKind($0) }
                )) {
                    Text("Todas as imagens").tag(0)
                    Text("Domínios").tag(1)
                    Text("Regex no path").tag(2)
                }
                .pickerStyle(.segmented)

                if scopeKind == 1 {
                    TextField("ex: instagram.com, cdn.site.com",
                              text: domainText)
                        .textFieldStyle(.roundedBorder)
                }
                if scopeKind == 2 {
                    TextField(#"ex: /media/.*\.jpg"#,
                              text: patternText)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                }

                if !state.injectionRule.targetIPs.isEmpty {
                    LabeledContent("Alvos",
                        value: state.injectionRule.targetIPs.sorted().joined(separator: ", "))
                        .font(.caption)
                    Button("Limpar restrição de IP") {
                        state.injectionRule.targetIPs = []
                        state.applyInjection()
                    }
                    .controlSize(.small)
                }
            }

            Section("Opções") {
                Toggle("Rotacionar imagens da pasta",
                       isOn: $state.injectionRule.rotate)
                Toggle("Manter dimensões esperadas",
                       isOn: $state.injectionRule.preserveDimensions)
                    .help("Redimensiona a imagem injetada para o w/h que a página pediu")
                Toggle("Modo tela cheia (também vídeo/mídia)",
                       isOn: Binding(
                        get: { state.injectionRule.mediaScope == .imagesAndMedia },
                        set: { state.injectionRule.mediaScope = $0 ? .imagesAndMedia : .imagesOnly }
                       ))
            }

            Section {
                Text("HTTPS só é reescrito em alvos que confiam na CA Pastoral. TVs/celulares sem a CA recebem injeção apenas em HTTP.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onChange(of: state.injectionRule) { _, _ in
            if state.injectionRule.enabled { state.applyInjection() }
        }
    }

    // MARK: - Right: detected TVs

    private var tvPanel: some View {
        VStack(spacing: 0) {
            HStack {
                Text("TVs detectadas")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
                if state.tvDetectionRunning {
                    ProgressView().scaleEffect(0.6)
                    Text("Bonjour")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)

            Divider()

            let tvs = state.hosts.filter { $0.kind == .tv }
            if tvs.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "tv")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("Nenhuma TV identificada")
                        .foregroundStyle(.secondary)
                    Text("Bonjour (_airplay, _googlecast…) e OUI marcam TVs automaticamente após o Scan ARP. Smart TVs aparecem aqui.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 300)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(tvs) { host in
                        HStack {
                            Image(systemName: "tv.fill")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(host.ip)
                                    .font(.system(.body, design: .monospaced))
                                Text(host.vendor ?? host.mac.uppercased())
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button {
                                Task { await state.injectOnTV(host) }
                            } label: {
                                Label("Mostrar imagem", systemImage: "photo.badge.arrow.down")
                            }
                            .controlSize(.small)
                            .disabled(state.injectionImages.isEmpty)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    // MARK: - Scope bindings

    private var scopeKind: Int {
        switch state.injectionRule.scope {
        case .allImages: return 0
        case .domains: return 1
        case .pathPattern: return 2
        }
    }

    private func setScopeKind(_ kind: Int) {
        switch kind {
        case 1:
            if case .domains = state.injectionRule.scope { return }
            state.injectionRule.scope = .domains([])
        case 2:
            if case .pathPattern = state.injectionRule.scope { return }
            state.injectionRule.scope = .pathPattern("")
        default:
            state.injectionRule.scope = .allImages
        }
    }

    private var domainText: Binding<String> {
        Binding(
            get: {
                if case .domains(let d) = state.injectionRule.scope {
                    return d.joined(separator: ", ")
                }
                return ""
            },
            set: {
                let list = $0.split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                state.injectionRule.scope = .domains(list)
            }
        )
    }

    private var patternText: Binding<String> {
        Binding(
            get: {
                if case .pathPattern(let p) = state.injectionRule.scope {
                    return p
                }
                return ""
            },
            set: { state.injectionRule.scope = .pathPattern($0) }
        )
    }
}

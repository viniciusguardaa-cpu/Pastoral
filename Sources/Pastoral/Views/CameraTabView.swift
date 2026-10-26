import SwiftUI
import PastoralCore

/// Cameras tab: lists all detected IP cameras on the LAN with live
/// video streaming via RTSP (JPEG-over-RTP or H.264 via VideoToolbox).
/// Detection runs via Bonjour (_rtsp/_onvif/_camera/…) and OUI vendor
/// matching; cameras that don't advertise Bonjour are confirmed via a
/// TCP port probe (RTSP 554, ONVIF 3702/8000, HTTP 80).
struct CameraTabView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                Circle()
                    .fill(state.cameraDetectionRunning ? Color.green : Color.gray)
                    .frame(width: 10, height: 10)
                Text(state.cameraDetectionRunning ? "Detectando" : "Parado")
                    .font(.headline)
                    .foregroundStyle(state.cameraDetectionRunning ? .green : .secondary)

                Spacer()

                Text("\(state.cameras.count) câmeras")
                    .font(.callout)
                    .foregroundStyle(state.cameras.count > 0 ? .indigo : .secondary)
                    .monospacedDigit()

                if !state.liveStreamActive.isEmpty {
                    Text("\(state.liveStreamActive.count) ao vivo")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .monospacedDigit()
                }

                Divider().frame(height: 16)

                Button(action: {
                    state.startCameraDetection()
                    Task { await state.scanForCameras() }
                }) {
                    Label("Escanear câmeras", systemImage: "camera.metering.center.weighted")
                }
                .disabled(state.hosts.isEmpty)

                if state.cameras.isEmpty || state.liveStreamActive.isEmpty {
                    Button(action: { startAllLive() }) {
                        Label("Live todas", systemImage: "play.circle.fill")
                    }
                    .disabled(state.cameras.isEmpty)
                } else {
                    Button(action: { state.stopAllLiveStreams() }) {
                        Label("Parar todas", systemImage: "stop.circle.fill")
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Camera grid
            if state.cameras.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 12)],
                              spacing: 12) {
                        ForEach(state.cameras) { cam in
                            CameraCard(state: state, camera: cam)
                        }
                    }
                    .padding(12)
                }
            }
        }
        .onDisappear {
            state.stopCameraDetection()
            state.stopAllLiveStreams()
        }
    }

    private func startAllLive() {
        for cam in state.cameras {
            state.startLiveStream(for: cam)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "camera")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Nenhuma câmera detectada")
                .foregroundStyle(.secondary)
            Text("Faça um Scan ARP primeiro. Câmeras são detectadas via Bonjour (_rtsp/_onvif/_camera), OUI de fabricante (Hikvision, Dahua, Axis…) e portas RTSP/ONVIF/HTTP. Clique em Live para ver o vídeo em tempo real.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A single camera card: live video + metadata + actions.
struct CameraCard: View {
    @Bindable var state: AppState
    let camera: CameraInfo

    var isLive: Bool { state.liveStreamActive.contains(camera.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Live video or snapshot
            ZStack {
                if isLive {
                    CameraLiveView(cameraID: camera.id, state: state)
                        .aspectRatio(4/3, contentMode: .fit)
                } else {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(.black)
                        .aspectRatio(4/3, contentMode: .fit)
                    if let snap = state.cameraSnapshots[camera.id],
                       let nsImage = NSImage(data: snap.data) {
                        Image(nsImage: nsImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    } else if state.snapshotInProgress.contains(camera.id) {
                        ProgressView()
                            .scaleEffect(0.8)
                    } else {
                        VStack(spacing: 6) {
                            Image(systemName: "camera.fill")
                                .font(.title2)
                                .foregroundStyle(.white.opacity(0.4))
                            Text("sem snapshot")
                                .font(.caption2)
                                .foregroundStyle(.white.opacity(0.4))
                        }
                    }
                }

                // Live indicator badge (top-right)
                if isLive {
                    HStack(spacing: 3) {
                        Circle()
                            .fill(.red)
                            .frame(width: 6, height: 6)
                        Text("AO VIVO")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .foregroundStyle(.white)
                    }
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.red.opacity(0.7))
                    .clipShape(Capsule())
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                    .padding(6)
                }
            }

            // Metadata
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(camera.ip)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.medium)
                    Spacer()
                    if let note = camera.authNote {
                        Text(note)
                            .font(.caption2)
                            .fontWeight(.medium)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.orange.opacity(0.25))
                            .foregroundStyle(.orange)
                            .clipShape(Capsule())
                    }
                    Text(camera.detectionSource.label)
                        .font(.caption2)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(camera.detectionSource.color.opacity(0.2))
                        .clipShape(Capsule())
                }
                Text(camera.mac.uppercased())
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                if let vendor = camera.vendor, !vendor.isEmpty {
                    Text(vendor)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                if let codec = camera.codec {
                    Text("Stream: \(codec)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                if let path = camera.rtspPath {
                    Text("rtsp://\(camera.ip)\(path)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .help("URL RTSP descoberta via ONVIF — clicável pra copiar")
                }
                if let prog = state.liveAuthProgress[camera.id] {
                    Text("auditando — \(prog)")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                if !state.cameraOnLocalNetwork(camera) {
                    Label("Em outra rede — conecte no Wi-Fi dela",
                          systemImage: "wifi.exclamationmark")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help("Câmera em outro /24 que a Wi-Fi atual do Mac — sem ponte/VPN o live não abre")
                }
                if let err = state.liveStreamErrors[camera.id] {
                    Text(err)
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                }
            }

            // Actions
            HStack(spacing: 6) {
                // Live toggle (primary action)
                Button {
                    state.toggleLiveStream(for: camera)
                } label: {
                    Label(isLive ? "Parar" : "Live",
                          systemImage: isLive ? "stop.circle.fill" : "play.circle.fill")
                        .controlSize(.small)
                        .foregroundStyle(isLive ? .red : .green)
                }

                Button {
                    Task { await state.snapshotCamera(camera) }
                } label: {
                    Label("Snap", systemImage: "camera")
                        .controlSize(.small)
                }
                .disabled(state.snapshotInProgress.contains(camera.id) || isLive)

                // Manual credentials — needed when the camera's password
                // isn't a factory default.
                Button {
                    promptCredentials(for: camera)
                } label: {
                    Label("Senha", systemImage: "key")
                        .controlSize(.small)
                }
                .help("Definir usuário/senha RTSP desta câmera")

                // Brute-force audit — tries the bundled wordlist
                // (admin/root/user × ~770 senhas comuns).
                Button {
                    confirmBruteForce(for: camera)
                } label: {
                    Label("Força", systemImage: "bolt.fill")
                        .controlSize(.small)
                        .foregroundStyle(.orange)
                }
                .disabled(isLive)
                .help("Auditoria: testa a wordlist de senhas comuns no RTSP (lento, pode disparar lockout)")

                if let snap = state.cameraSnapshots[camera.id],
                   let nsImage = NSImage(data: snap.data) {
                    Button {
                        saveSnapshot(nsImage: nsImage, camera: camera)
                    } label: {
                        Label("Salvar", systemImage: "square.and.arrow.down")
                            .controlSize(.small)
                    }
                }
            }
        }
        .padding(10)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    /// Prompt for RTSP credentials and retry the live stream with them.
    private func promptCredentials(for camera: CameraInfo) {
        let alert = NSAlert()
        alert.messageText = "Credenciais RTSP — \(camera.ip)"
        alert.informativeText = "Usuário e senha do stream da câmera."
        alert.addButton(withTitle: "Salvar e abrir Live")
        alert.addButton(withTitle: "Cancelar")

        let userField = NSTextField(frame: NSRect(x: 0, y: 30, width: 220, height: 24))
        userField.placeholderString = "usuário"
        let passField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 220, height: 24))
        passField.placeholderString = "senha"
        if let existing = state.cameraCredentials[camera.id] {
            userField.stringValue = existing.user
            passField.stringValue = existing.pass
        }
        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: 220, height: 56))
        stack.orientation = .vertical
        stack.spacing = 6
        stack.addArrangedSubview(userField)
        stack.addArrangedSubview(passField)
        alert.accessoryView = stack
        alert.window.initialFirstResponder = userField

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let user = userField.stringValue.trimmingCharacters(in: .whitespaces)
        let pass = passField.stringValue
        guard !user.isEmpty else { return }
        state.setManualCredential(user: user, pass: pass, for: camera.id, ip: camera.ip)
        state.liveStreamErrors.removeValue(forKey: camera.id)
        if isLive {
            state.stopLiveStream(for: camera)
        }
        state.startLiveStream(for: camera)
    }

    /// Confirm and start a wordlist brute-force audit against this camera.
    private func confirmBruteForce(for camera: CameraInfo) {
        let total = AppState.wordlistPasswords.count * 3
        let alert = NSAlert()
        alert.messageText = "Auditoria de senha — \(camera.ip)"
        alert.informativeText = "Vai testar ~\(total) senhas comuns (usuários admin/root/user × wordlist) via RTSP. " +
            "Pode demorar vários minutos e algumas câmeras bloqueiam o IP após muitas falhas (lockout). " +
            "O progresso aparece no card. Continuar?"
        alert.addButton(withTitle: "Iniciar auditoria")
        alert.addButton(withTitle: "Cancelar")
        alert.alertStyle = .warning
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        state.liveStreamErrors.removeValue(forKey: camera.id)
        state.startLiveStream(for: camera, bruteForce: true)
    }

    private func saveSnapshot(nsImage: NSImage, camera: CameraInfo) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "pastoral-\(camera.ip).jpg"
        panel.allowedContentTypes = [.jpeg]
        if panel.runModal() == .OK, let url = panel.url {
            if let tiff = nsImage.tiffRepresentation,
               let rep = NSBitmapImageRep(data: tiff),
               let jpg = rep.representation(using: .jpeg, properties: [.compressionFactor: 0.9]) {
                try? jpg.write(to: url)
            }
        }
    }
}

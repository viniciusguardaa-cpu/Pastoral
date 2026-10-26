import SwiftUI
import AppKit
import PastoralCore

/// Arma tab — the command deck. Every weapon in the app on one screen:
/// global attacks, per-host actions, camera strip and one restore.
struct ArmaTabView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                attackRow
                statusLine
                roster
                if !state.cameras.isEmpty { cameraStrip }
                restoreRow
            }
            .padding(22)
        }
        .background(PastoralTheme.background)
    }

    // MARK: Header — where are we fighting?

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("QUARTEL-GERAL")
                    .font(.system(size: 15, weight: .semibold)).tracking(1.5)
                    .foregroundStyle(PastoralTheme.cream)
                Text("\(state.hosts.count) alvos · \(state.network.ssid ?? "rede local") · eu \(state.network.localIP ?? "—")")
                    .font(.system(size: 11))
                    .foregroundStyle(PastoralTheme.muted)
            }
            Spacer()
            Button {
                Task { await state.scanARP() }
            } label: {
                Label(state.isScanning ? "Varrendo…" : "VARREDURA",
                      systemImage: state.isScanning ? "arrow.triangle.2.circlepath" : "antenna.radiowaves.left.and.right")
                    .font(.system(size: 11, weight: .semibold)).tracking(0.8)
                    .padding(.horizontal, 14).padding(.vertical, 9)
            }
            .buttonStyle(.plain)
            .background(PastoralTheme.raised, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(PastoralTheme.border))
            .disabled(state.isScanning)
        }
        .padding(16)
        .background(PastoralTheme.surface, in: RoundedRectangle(cornerRadius: 18))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(PastoralTheme.border))
    }

    // MARK: Global weapons

    private var attackRow: some View {
        HStack(spacing: 10) {
            weaponButton("ESCURIDÃO", symbol: "bolt.slash.fill",
                         active: state.killGlobal, tint: .red) {
                Task { await state.killAll() }
            }
            weaponButton("SILÊNCIO", symbol: "ear.fill",
                         active: state.divertGlobal, tint: .orange) {
                Task { await state.divertAll() }
            }
            weaponButton(state.loboActive ? "LOBO ATIVO" : "LOBO AUTO",
                         symbol: "pawprint.fill",
                         active: state.loboActive, tint: .red) {
                Task { state.loboActive ? await state.loboRetreat() : await state.loboAuto() }
            }
            weaponButton("CAPTURA", symbol: "waveform.path.ecg",
                         active: state.sheepRunning, tint: .mint) {
                Task { state.sheepRunning ? await state.stopSheep() : await state.startSheep() }
            }
        }
    }

    private func weaponButton(_ label: String, symbol: String,
                              active: Bool, tint: Color,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(label, systemImage: symbol)
                .font(.system(size: 11.5, weight: .semibold)).tracking(0.8)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
        }
        .buttonStyle(.plain)
        .background((active ? tint : PastoralTheme.raised).opacity(active ? 0.22 : 1),
                    in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12)
            .stroke(active ? tint.opacity(0.7) : PastoralTheme.border))
        .foregroundStyle(active ? tint : PastoralTheme.cream)
        .help(label)
    }

    // MARK: Status line

    private var statusLine: some View {
        HStack(spacing: 14) {
            Text("\(state.killedCount) cortados")
                .foregroundStyle(state.killedCount > 0 ? .red : PastoralTheme.muted)
            Text("\(state.divertedCount) desviados")
                .foregroundStyle(state.divertedCount > 0 ? .orange : PastoralTheme.muted)
            if state.loboActive, let t = state.loboTarget {
                Text("lobo em \(t.hostname ?? t.ip)")
                    .foregroundStyle(.red)
            }
            if let cam = state.cameras.first(where: { state.liveFrames[$0.id] != nil }) {
                Text("live \(cam.ip)")
                    .foregroundStyle(PastoralTheme.mint)
            }
            Spacer()
            if state.recoveryRequired {
                Text("rede modificada — não esqueça de restaurar")
                    .foregroundStyle(.orange)
            }
        }
        .font(.system(size: 11))
        .padding(.horizontal, 4).padding(.bottom, -6)
    }

    // MARK: Roster

    private var roster: some View {
        VStack(spacing: 6) {
            ForEach(hostsShown) { host in
                rosterRow(host)
            }
            if hostsShown.isEmpty {
                Text("Nenhum alvo — rode a varredura.")
                    .font(.system(size: 12)).foregroundStyle(PastoralTheme.muted)
                    .frame(maxWidth: .infinity, minHeight: 60)
            }
        }
        .padding(14)
        .background(PastoralTheme.surface, in: RoundedRectangle(cornerRadius: 18))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(PastoralTheme.border))
    }

    private var hostsShown: [Host] {
        state.hosts.filter { !$0.isExcluded }
            .sorted { ($0.hostname ?? $0.ip).localizedCaseInsensitiveCompare($1.hostname ?? $1.ip) == .orderedAscending }
    }

    private func rosterRow(_ host: Host) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol(for: host.kind))
                .font(.system(size: 12))
                .frame(width: 18)
                .foregroundStyle(iconColor(host))
            VStack(alignment: .leading, spacing: 1) {
                Text(host.hostname ?? host.vendor ?? "desconhecido")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(PastoralTheme.cream)
                Text("\(host.ip) · \(host.throughputText)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(PastoralTheme.muted)
            }
            .frame(width: 220, alignment: .leading)
            Spacer()
            if host.isKilled {
                Text("CORTE").font(.system(size: 9, weight: .bold)).tracking(1)
                    .foregroundStyle(.red)
            }
            if host.isDiverted {
                Text("DESVIO").font(.system(size: 9, weight: .bold)).tracking(1)
                    .foregroundStyle(.orange)
            }
            if state.loboActive && state.loboTargetID == host.id {
                Text("LOBO").font(.system(size: 9, weight: .bold)).tracking(1)
                    .foregroundStyle(.red)
            }
            rowButton("bolt.fill", "Cortar internet", host.isKilled ? .red : nil) {
                Task { await state.toggleKill(host) }
            }
            rowButton("arrow.triangle.branch", "Desviar tráfego", host.isDiverted ? .orange : nil) {
                Task { await state.toggleDivert(host) }
            }
            rowButton("pawprint.fill", "Invadir (Lobo)",
                      state.loboActive && state.loboTargetID == host.id ? .red : nil) {
                Task { await state.loboOnHost(host) }
            }
        }
        .padding(.vertical, 4)
    }

    private func rowButton(_ symbol: String, _ help: String, _ on: Color?,
                           action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 11))
                .frame(width: 26, height: 22)
                .background((on ?? PastoralTheme.raised).opacity(on != nil ? 0.25 : 1),
                            in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7)
                    .stroke(on != nil ? (on ?? .white).opacity(0.6) : PastoralTheme.border))
        }
        .buttonStyle(.plain)
        .foregroundStyle(on ?? PastoralTheme.muted)
        .help(help)
    }

    private func symbol(for kind: HostKind) -> String {
        switch kind {
        case .tv: "tv"
        case .camera: "video"
        case .generic: "desktopcomputer"
        }
    }

    private func iconColor(_ host: Host) -> Color {
        switch host.kind {
        case .camera: .orange
        case .tv: .cyan
        case .generic: PastoralTheme.mint
        }
    }

    // MARK: Camera strip

    private var cameraStrip: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CÂMERAS NA REDE")
                .font(.system(size: 9, weight: .semibold)).tracking(1.5)
                .foregroundStyle(PastoralTheme.muted)
            HStack(spacing: 10) {
                ForEach(Array(state.cameras.prefix(4))) { cam in
                    cameraCell(cam)
                }
                if state.cameras.count > 4 {
                    Text("+\(state.cameras.count - 4)")
                        .font(.system(size: 11)).foregroundStyle(PastoralTheme.muted)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(PastoralTheme.raised, in: RoundedRectangle(cornerRadius: 10))
                }
            }
        }
        .padding(14)
        .background(PastoralTheme.surface, in: RoundedRectangle(cornerRadius: 18))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(PastoralTheme.border))
    }

    private func cameraCell(_ cam: CameraInfo) -> some View {
        let id = cam.id
        return VStack(alignment: .leading, spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(PastoralTheme.raised)
                    .frame(height: 84)
                if let frame = state.liveFrames[id] {
                    Image(nsImage: frame)
                        .resizable().aspectRatio(contentMode: .fill)
                        .frame(height: 84).clipShape(RoundedRectangle(cornerRadius: 8))
                } else if let snap = state.cameraSnapshots[id],
                          let img = NSImage(data: snap.data) {
                    Image(nsImage: img)
                        .resizable().aspectRatio(contentMode: .fill)
                        .frame(height: 84).clipShape(RoundedRectangle(cornerRadius: 8))
                        .opacity(0.55)
                } else {
                    Image(systemName: "video.slash")
                        .font(.system(size: 18)).foregroundStyle(PastoralTheme.muted)
                }
            }
            HStack {
                Text(cam.ip)
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(PastoralTheme.muted)
                Spacer()
                Button {
                    Task { state.toggleLiveStream(for: cam) }
                } label: {
                    Image(systemName: state.liveStreamActive.contains(id)
                          ? "stop.circle.fill" : "play.circle.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(state.liveStreamActive.contains(id) ? .red : PastoralTheme.mint)
                }
                .buttonStyle(.plain)
                .help("Live ao vivo")
            }
        }
        .frame(width: 190)
    }

    // MARK: Restore

    private var restoreRow: some View {
        Button {
            Task { _ = await state.restoreAll() }
        } label: {
            Label("RESTAURAR TUDO — DEVOLVE A REDE AO NORMAL",
                  systemImage: "arrow.uturn.backward.circle.fill")
                .font(.system(size: 11.5, weight: .semibold)).tracking(0.8)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
        .background(PastoralTheme.raised, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(PastoralTheme.border))
        .foregroundStyle(.green)
        .disabled(!state.recoveryRequired)
        .opacity(state.recoveryRequired ? 1 : 0.45)
    }
}

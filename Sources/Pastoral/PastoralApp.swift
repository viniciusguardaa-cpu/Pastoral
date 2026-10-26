import SwiftUI
import PastoralCore

@main
struct PastoralApp: App {
    @NSApplicationDelegateAdaptor(PastoralAppDelegate.self) private var delegate
    @State private var state = AppState()
    private let preview = ProcessInfo.processInfo.arguments.contains("--design-preview")

    var body: some Scene {
        WindowGroup {
            ContentView(state: state, preview: preview)
                .frame(minWidth: 1100, minHeight: 760)
                .task {
                    guard !preview else { state.loadDesignPreview(); return }
                    delegate.state = state
                    state.checkCrashRecovery()
                    await state.refreshStatus()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                    guard !preview, state.hasPendingRecovery else { return }
                    Task { await state.restoreAll() }
                }
        }
        .defaultSize(width: 1260, height: 860)
        .windowResizability(.contentMinSize)
        .windowStyle(.hiddenTitleBar)
        .commands { CommandGroup(replacing: .newItem) { } }
        MenuBarExtra("Pastoral", systemImage: "network.badge.shield.half.filled") {
            Text(preview ? "Prévia visual · dados ilustrativos" : "Pastoral")
            Button("Restaurar rede") { Task { await state.restoreAll() } }
                .disabled(preview || state.isRestoring)
            Divider()
            Button("Sair") { NSApplication.shared.terminate(nil) }
        }
    }
}

@MainActor
final class PastoralAppDelegate: NSObject, NSApplicationDelegate {
    weak var state: AppState?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let state, state.hasPendingRecovery else { return .terminateNow }
        Task {
            if await state.restoreAll() {
                sender.reply(toApplicationShouldTerminate: true)
            } else {
                let alert = NSAlert()
                alert.messageText = "A restauração ainda está pendente"
                alert.informativeText = state.lastError ?? "O serviço não confirmou a restauração."
                alert.addButton(withTitle: "Voltar ao aplicativo")
                alert.addButton(withTitle: "Sair mesmo assim")
                sender.reply(toApplicationShouldTerminate: alert.runModal() == .alertSecondButtonReturn)
            }
        }
        return .terminateLater
    }
}

struct ContentView: View {
    @Bindable var state: AppState
    var preview = false

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(PastoralTheme.border).frame(width: 1)
            VStack(spacing: 0) {
                header
                if preview {
                    Text("PRÉVIA VISUAL · DADOS ILUSTRATIVOS · AÇÕES DESATIVADAS")
                        .font(.system(size: 9, weight: .medium)).tracking(1)
                        .foregroundStyle(PastoralTheme.mint)
                        .frame(maxWidth: .infinity).padding(7)
                        .background(PastoralTheme.mint.opacity(0.06))
                }
                if state.hasPendingRecovery {
                    Label("Há operações ou restaurações pendentes nesta sessão.", systemImage: "arrow.counterclockwise.circle")
                        .font(.system(size: 12)).foregroundStyle(.orange)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(14)
                        .background(Color.orange.opacity(0.08))
                }
                if let error = state.lastError { errorBanner(error) }
                content.frame(maxWidth: .infinity, maxHeight: .infinity)
                    .disabled(preview || state.isRestoring)
                StatusBarView(state: state)
            }
        }
        .foregroundStyle(PastoralTheme.cream)
        .background(PastoralTheme.background)
        .tint(PastoralTheme.mint)
        .preferredColorScheme(.dark)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                PastoralBrandMark().frame(width: 48, height: 48)
                VStack(alignment: .leading, spacing: 4) {
                    Text("pastoral").font(.system(size: 23, weight: .semibold, design: .rounded))
                    Text("REDE LOCAL").font(.system(size: 8, weight: .medium)).tracking(2.5).foregroundStyle(PastoralTheme.muted)
                }
            }.padding(.horizontal, 22).padding(.top, 47).padding(.bottom, 34)
            navHeading("ESPAÇO DE TRABALHO")
            navItem(.overview)
            navItem(.arma)
            navItem(.kill)
            navItem(.sheep)
            navItem(.cameras)
            navHeading("FERRAMENTAS").padding(.top, 24)
            navItem(.guided)
            navItem(.lobo)
            navItem(.inject)
            navItem(.php)
            Spacer(minLength: 24)
            navItem(.settings)
            Rectangle().fill(PastoralTheme.border).frame(height: 1).padding(.horizontal, 20).padding(.vertical, 16)
            VStack(alignment: .leading, spacing: 8) {
                Text(state.network.ssid ?? "Sua rede local").font(.system(size: 12, weight: .medium)).lineLimit(1)
                Label(state.helper.responding ? "Serviço conectado" : "Verificar conexão",
                      systemImage: state.helper.responding ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .font(.system(size: 10)).foregroundStyle(state.helper.responding ? PastoralTheme.mint : Color.orange)
            }.padding(.horizontal, 24).padding(.bottom, 24)
        }.frame(width: 220).background(PastoralTheme.sidebar)
    }

    private func navHeading(_ title: String) -> some View {
        Text(title).font(.system(size: 8, weight: .semibold)).tracking(1.7)
            .foregroundStyle(PastoralTheme.muted.opacity(0.8)).padding(.horizontal, 25).padding(.bottom, 10)
    }

    private func navItem(_ item: PastoralTab) -> some View {
        let selected = state.selectedTab == item
        return Button { state.selectedTab = item } label: {
            HStack(spacing: 11) {
                Image(systemName: item.symbol).font(.system(size: 14)).frame(width: 18)
                Text(item.title).font(.system(size: 12, weight: selected ? .semibold : .regular))
                Spacer()
                if item == .kill && !state.hosts.isEmpty {
                    Text(String(state.hosts.count)).font(.system(size: 10, weight: .medium))
                        .padding(.horizontal, 6).padding(.vertical, 3)
                        .background(PastoralTheme.mint.opacity(0.09), in: RoundedRectangle(cornerRadius: 5))
                }
            }
            .foregroundStyle(selected ? PastoralTheme.mint : PastoralTheme.muted)
            .padding(.horizontal, 13).frame(height: 40)
            .background(selected ? PastoralTheme.mint.opacity(0.10) : .clear, in: RoundedRectangle(cornerRadius: 9))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).padding(.horizontal, 12).padding(.bottom, 3)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .disabled(preview)
    }

    private var header: some View {
        HStack(spacing: 20) {
            VStack(alignment: .leading, spacing: 5) {
                Text(state.selectedTab.title).font(.system(size: 20, weight: .semibold))
                Text(state.selectedTab.subtitle).font(.system(size: 11)).foregroundStyle(PastoralTheme.muted)
            }
            Spacer(minLength: 8)
            ConnectionBadge(online: state.helper.responding)
            Button { Task { await state.restoreAll() } } label: {
                Label(state.isRestoring ? "Restaurando…" : "Restaurar rede", systemImage: "arrow.counterclockwise")
                    .font(.system(size: 11, weight: .medium))
            }.controlSize(.large).disabled(preview || state.isRestoring)
        }
        .padding(.horizontal, 28).padding(.top, 25).padding(.bottom, 20)
        .overlay(alignment: .bottom) { Rectangle().fill(PastoralTheme.border).frame(height: 1) }
    }

    private func errorBanner(_ error: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.circle")
            Text(error).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            Button { state.lastError = nil } label: { Image(systemName: "xmark") }
                .buttonStyle(.plain).accessibilityLabel("Dispensar mensagem")
        }.font(.system(size: 12)).foregroundStyle(.orange).padding(14).background(Color.orange.opacity(0.05))
    }

    @ViewBuilder private var content: some View {
        switch state.selectedTab {
        case .overview: OverviewView(state: state)
        case .settings: PastoralSettingsView(state: state)
        default:
            if !state.helper.responding { HelperMissingCard(state: state) }
            else { toolContent.padding(16) }
        }
    }

    @ViewBuilder private var toolContent: some View {
        switch state.selectedTab {
        case .arma: ArmaTabView(state: state)
        case .kill: KillTabView(state: state)
        case .sheep: SheepTabView(state: state)
        case .cameras: CameraTabView(state: state)
        case .lobo: LoboTabView(state: state)
        case .inject: InjectTabView(state: state)
        case .php: PhpTabView(state: state)
        case .guided: EasyModeView(state: state)
        default: EmptyView()
        }
    }
}

extension AppState {
    /// Visual fixture: no helper connection, discovery or capture.
    func loadDesignPreview() {
        network = NetworkInfo(interfaceName: "en0", localIP: "192.0.2.20", gatewayIP: "192.0.2.1", ssid: "Estúdio · demonstração")
        helper = HelperStatus(responding: true, forwarding: false, bpfAccessible: false, interface: "en0")
        hosts = [
            Host(id: "preview-1", ip: "192.0.2.20", mac: "02:00:00:00:00:01", vendor: "Apple", hostname: "MacBook Pro", isExcluded: true),
            Host(id: "preview-2", ip: "192.0.2.1", mac: "02:00:00:00:00:02", hostname: "Roteador principal", isExcluded: true),
            Host(id: "preview-3", ip: "192.0.2.30", mac: "02:00:00:00:00:03", vendor: "Apple", hostname: "iPhone"),
            Host(id: "preview-4", ip: "192.0.2.40", mac: "02:00:00:00:00:04", hostname: "TV da sala", kind: .tv),
            Host(id: "preview-5", ip: "192.0.2.50", mac: "02:00:00:00:00:05", hostname: "Câmera do estúdio", kind: .camera)
        ]
        phpTargets = [
            PhpTarget(host: "192.0.2.14", port: 80, basePath: "/",
                      phpVersionText: "7.4.33", versionSource: "Server", passive: true,
                      report: PhpProbeReport(
                          host: "192.0.2.14", port: 80, path: "/",
                          baseline: .normal(200), oomHeaders: .crashed,
                          oomNested: .normal(0),
                          fingerprint: PhpFingerprint(headers: ["Server": "nginx/1.18.0 (php/7.4.33)"]),
                          disclosureBytes: nil),
                      lfiBase: "/cms/view.php?page=", sessionDir: "/tmp/sessions",
                      command: "id"),
            PhpTarget(host: "192.0.2.60", port: 8443, basePath: "/app/",
                      phpVersionText: "8.2.35", versionSource: "X-PHP-Version",
                      passive: false,
                      report: PhpProbeReport(
                          host: "192.0.2.60", port: 8443, path: "/app/",
                          baseline: .normal(200), oomHeaders: .normal(200),
                          oomNested: .normal(200),
                          fingerprint: PhpFingerprint(headers: ["X-PHP-Version": "8.2.35"]),
                          disclosureBytes: nil, sessionCookieEchoed: true))
        ]
        log.info("Prévia visual carregada com dados ilustrativos. Nenhuma conexão foi iniciada.")
    }
}

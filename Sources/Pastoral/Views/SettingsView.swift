import SwiftUI

struct PastoralSettingsView: View {
    @Bindable var state: AppState
    @State private var checking = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PastoralPanel {
                    VStack(alignment: .leading, spacing: 15) {
                        Label("Serviço de rede", systemImage: "network.badge.shield.half.filled")
                            .font(.headline)
                        Text("O aplicativo usa um serviço separado para as operações que exigem permissão administrativa.")
                            .font(.callout).foregroundStyle(PastoralTheme.muted)
                        ConnectionBadge(online: state.helper.responding)
                        Text(state.readiness.helperDescription)
                            .font(.callout).foregroundStyle(PastoralTheme.muted)
                        HStack {
                            Button(checking ? "Verificando…" : "Verificar conexão") {
                                checking = true
                                Task { await state.refreshStatus(); checking = false }
                            }.disabled(checking)
                            if !state.helper.responding || state.readiness.helperBuild == .differs {
                                Button(state.helper.responding ? "Atualizar serviço…" : "Instalar serviço…") { Task { await state.installHelper() } }
                            }
                        }
                    }
                }
                PastoralPanel {
                    VStack(alignment: .leading, spacing: 14) {
                        Label("Recuperação da sessão", systemImage: "arrow.counterclockwise.circle")
                            .font(.headline)
                        Text("As pendências permanecem registradas até o serviço confirmar a restauração. Dispositivos que saíram da lista também são considerados.")
                            .font(.callout).foregroundStyle(PastoralTheme.muted)
                        Button(state.isRestoring ? "Restaurando…" : "Restaurar rede") {
                            Task { await state.restoreAll() }
                        }.disabled(state.isRestoring)
                    }
                }
                PastoralPanel {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Disponibilidade dos recursos").font(.headline)
                        Text(state.readiness.wireGuardAvailable ? "WireGuard: componentes encontrados; conexão ainda precisa ser verificada." : "WireGuard: componentes não encontrados.")
                        Text(state.readiness.tailscaleAvailable ? "Tailscale: lançador encontrado; conexão ainda precisa ser verificada." : "Tailscale: componente não encontrado.")
                        Text("Velocidade por dispositivo: medição ainda indisponível.")
                        Text("Monitor Wi-Fi e desautenticação: não implementados.")
                        Text("Capturas QUIC/mDNS contínuas: operações simultâneas ainda não validadas.")
                    }.font(.callout).foregroundStyle(PastoralTheme.muted)
                }
                PastoralPanel {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Pastoral").font(.title2.weight(.semibold))
                        Text("Aplicativo nativo para macOS · SwiftUI")
                            .font(.callout).foregroundStyle(PastoralTheme.muted)
                        Text("Os registros desta sessão refletem respostas recebidas pelo aplicativo. Eles não substituem a verificação do estado real da rede.")
                            .font(.caption).foregroundStyle(PastoralTheme.muted)
                    }
                }
            }.padding(28).frame(maxWidth: 850)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

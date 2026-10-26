import SwiftUI

struct OverviewView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .center, spacing: 24) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("SEU ESPAÇO DE REDE")
                            .font(.system(size: 10, weight: .semibold)).tracking(2.2)
                            .foregroundStyle(PastoralTheme.mint)
                        Text("Sua rede, com clareza.")
                            .font(.system(size: 32, weight: .semibold, design: .rounded))
                            .foregroundStyle(PastoralTheme.cream)
                        Text("Acompanhe dispositivos, consulte o estado da sessão\ne mantenha as operações sob controle.")
                            .font(.system(size: 13)).lineSpacing(4)
                            .foregroundStyle(PastoralTheme.muted)
                    }
                    Spacer()
                    Image(systemName: "network")
                        .font(.system(size: 52, weight: .ultraLight))
                        .foregroundStyle(PastoralTheme.mint)
                        .frame(width: 112, height: 112)
                        .background(PastoralTheme.mint.opacity(0.06), in: RoundedRectangle(cornerRadius: 30))
                        .overlay(RoundedRectangle(cornerRadius: 30).stroke(PastoralTheme.mint.opacity(0.12)))
                }
                .padding(.vertical, 8)

                HStack(spacing: 14) {
                    metric("Dispositivos", value: String(state.hosts.count), detail: "Na última descoberta", icon: "desktopcomputer")
                    metric("Registros", value: String(state.requests.count), detail: "Disponíveis nesta sessão", icon: "waveform.path.ecg")
                    metric("Restauração", value: state.hasPendingRecovery ? "Pendente" : "Sem pendências",
                           detail: "Estado registrado pelo aplicativo", icon: "arrow.counterclockwise")
                }

                HStack(alignment: .top, spacing: 18) {
                    PastoralPanel {
                        VStack(alignment: .leading, spacing: 16) {
                            HStack {
                                Text("Dispositivos da rede").font(.system(size: 15, weight: .semibold))
                                Spacer()
                                Button("Ver todos") { state.selectedTab = .kill }
                                    .buttonStyle(.plain).foregroundStyle(PastoralTheme.mint)
                            }
                            if state.hosts.isEmpty {
                                VStack(spacing: 12) {
                                    Image(systemName: "desktopcomputer").font(.system(size: 26, weight: .light))
                                    Text("Sua lista começa aqui").font(.headline)
                                    Text("Busque os dispositivos para visualizar sua rede.")
                                        .font(.caption).foregroundStyle(PastoralTheme.muted)
                                    Button("Buscar dispositivos") { Task { await state.scanARP() } }
                                        .disabled(!state.helper.responding || state.isScanning)
                                }
                                .frame(maxWidth: .infinity, minHeight: 220)
                            } else {
                                ForEach(Array(state.hosts.prefix(5))) { host in
                                    HStack(spacing: 12) {
                                        Image(systemName: host.kind == .camera ? "video" : host.kind == .tv ? "tv" : "desktopcomputer")
                                            .font(.system(size: 17)).foregroundStyle(PastoralTheme.mint)
                                            .frame(width: 38, height: 38)
                                            .background(PastoralTheme.raised, in: RoundedRectangle(cornerRadius: 10))
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(host.easyName).font(.system(size: 12, weight: .medium)).lineLimit(1)
                                            Text(host.ip).font(.system(size: 11, design: .monospaced)).foregroundStyle(PastoralTheme.muted)
                                        }
                                        Spacer()
                                        Text(host.isKilled ? "Bloqueado" : host.isDiverted ? "Desviado" : host.isExcluded ? "Protegido" : "Descoberto")
                                            .font(.system(size: 10, weight: .medium))
                                            .foregroundStyle(host.isKilled || host.isDiverted ? Color.orange : PastoralTheme.muted)
                                    }
                                    if host.id != state.hosts.prefix(5).last?.id {
                                        Rectangle().fill(PastoralTheme.border).frame(height: 1)
                                    }
                                }
                            }
                        }
                    }
                    VStack(spacing: 16) {
                        PastoralPanel {
                            VStack(alignment: .leading, spacing: 14) {
                                Label("Conexão local", systemImage: "wifi").font(.system(size: 14, weight: .semibold))
                                detail("Rede", state.network.ssid ?? "Não informada")
                                detail("Interface", state.network.interfaceName ?? "—")
                                detail("Endereço", state.network.localIP ?? "—")
                                detail("Gateway", state.network.gatewayIP ?? "—")
                            }
                        }
                        PastoralPanel {
                            VStack(alignment: .leading, spacing: 10) {
                                Label("Medições transparentes", systemImage: "info.circle")
                                    .font(.system(size: 12, weight: .semibold)).foregroundStyle(PastoralTheme.mint)
                                Text("A velocidade por dispositivo ainda não tem medição ativa. Ausência de dados aparece como “Sem medição”.")
                                    .font(.system(size: 12)).foregroundStyle(PastoralTheme.muted).lineSpacing(4)
                            }
                        }
                    }.frame(width: 270)
                }

                PastoralPanel {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Atividade do aplicativo").font(.system(size: 14, weight: .semibold))
                        if state.log.entries.isEmpty {
                            Text("Os eventos e as mensagens de diagnóstico aparecerão aqui.")
                                .font(.system(size: 12)).foregroundStyle(PastoralTheme.muted)
                        }
                        ForEach(Array(state.log.entries.suffix(3).reversed())) { entry in
                            HStack(alignment: .top, spacing: 10) {
                                Circle().fill(entry.level == .error ? Color.orange : PastoralTheme.mint)
                                    .frame(width: 5, height: 5).padding(.top, 5)
                                Text(entry.message).font(.system(size: 12)).lineLimit(2)
                                Spacer()
                                Text(entry.timestamp.formatted(date: .omitted, time: .shortened))
                                    .font(.system(size: 10, design: .monospaced)).foregroundStyle(PastoralTheme.muted)
                            }
                        }
                    }
                }
            }.padding(28)
        }
    }

    private func metric(_ title: String, value: String, detail: String, icon: String) -> some View {
        PastoralPanel {
            VStack(alignment: .leading, spacing: 13) {
                HStack {
                    Text(title).font(.system(size: 12)).foregroundStyle(PastoralTheme.muted)
                    Spacer()
                    Image(systemName: icon).foregroundStyle(PastoralTheme.mint)
                }
                Text(value).font(.system(size: value.count > 8 ? 21 : 29, weight: .semibold, design: .rounded))
                    .lineLimit(1).minimumScaleFactor(0.85)
                Text(detail).font(.system(size: 10)).foregroundStyle(PastoralTheme.muted)
            }.frame(height: 88, alignment: .top)
        }
    }

    private func detail(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title).foregroundStyle(PastoralTheme.muted)
            Spacer()
            Text(value).lineLimit(1).textSelection(.enabled)
        }.font(.system(size: 11))
    }
}

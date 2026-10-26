import SwiftUI
import PastoralCore

/// A single host row in the Kill tab: a cut/release button, IP, MAC,
/// vendor, hostname, live throughput with sparkline.
struct KillHostRow: View {
    @Bindable var state: AppState
    let host: Host

    var body: some View {
        HStack(spacing: 10) {
            // Kill/release button — explicit, no stale-state Toggle bug
            Button(action: { Task { await state.toggleKill(host) } }) {
                Image(systemName: host.isKilled ? "bolt.slash.fill" : "bolt.fill")
                    .font(.body)
                    .foregroundStyle(host.isKilled ? .white : .red)
                    .frame(width: 28, height: 24)
                    .background(host.isKilled ? Color.red : Color.red.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)
            .disabled(host.isExcluded || host.isDiverted)
            .help(host.isExcluded ? "Host excluído (próprio Mac / gateway)" :
                   host.isDiverted ? "Host desviado — solte o divert antes de matar" :
                   host.isKilled ? "Clique para liberar" : "Clique para cortar")

            // Divert (force-path) button — routes the host's traffic
            // through us so Sheep can intercept it even when we are not
            // the natural gateway.
            Button(action: { Task { await state.toggleDivert(host) } }) {
                Image(systemName: host.isDiverted ? "arrow.triangle.branch.fill" : "arrow.triangle.branch")
                    .font(.body)
                    .foregroundStyle(host.isDiverted ? .white : .orange)
                    .frame(width: 28, height: 24)
                    .background(host.isDiverted ? Color.orange : Color.orange.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)
            .disabled(host.isExcluded || host.isKilled)
            .help(host.isExcluded ? "Host excluído (próprio Mac / gateway)" :
                   host.isKilled ? "Host cortado — solte o kill antes de desviar" :
                   host.isDiverted ? "Clique para parar de desviar" : "Forçar tráfego através de nós (divert)")

            // Selective Kill menu (phase 3): drop/rate-limit by port/proto.
            Menu {
                if let policy = state.selectivePolicies[host.ip] {
                    Label(policySummary(policy), systemImage: "checkmark.circle.fill")
                    Button(role: .destructive, action: { Task { await state.clearSelectivePolicy(targetIP: host.ip) } }) {
                        Label("Remover todas as políticas seletivas", systemImage: "xmark.circle")
                    }
                    Divider()
                }
                Section("Presets de drop") {
                    Button("Drop DNS (53/udp)") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, ports: [53], proto: .udp)) } }
                    Button("Drop HTTPS (443/tcp)") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, ports: [443], proto: .tcp)) } }
                    Button("Drop HTTP (80/tcp)") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, ports: [80], proto: .tcp)) } }
                }
                Section("Presets de rate-limit") {
                    Button("Limitar a 256 Kbit/s") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, rateLimitKbit: 256)) } }
                    Button("Limitar a 1 Mbit/s") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, rateLimitKbit: 1024)) } }
                    Button("Limitar a 10 Mbit/s") { Task { await state.applySelectivePolicy(KillPolicy(targetIP: host.ip, rateLimitKbit: 10240)) } }
                }
                Section("Customizar…") {
                    Button("Política customizada…") { state.selectiveSheetHostID = host.id }
                }
            } label: {
                Image(systemName: state.selectivePolicies[host.ip] != nil ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
                    .font(.body)
                    .foregroundStyle(state.selectivePolicies[host.ip] != nil ? .white : .purple)
                    .frame(width: 28, height: 24)
                    .background(state.selectivePolicies[host.ip] != nil ? Color.purple : Color.purple.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)
            .disabled(host.isExcluded)
            .help("Kill seletivo: drop ou rate-limit por porta/protocolo")

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(host.ip)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.medium)
                    if host.isKilled {
                        Text("CORTADO")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.red)
                            .foregroundStyle(.white)
                            .clipShape(Capsule())
                    }
                    if host.isDiverted {
                        Text("DESVIADO")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.orange)
                            .foregroundStyle(.white)
                            .clipShape(Capsule())
                    }
                    if host.kind == .tv {
                        Text("TV")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.teal)
                            .foregroundStyle(.white)
                            .clipShape(Capsule())
                    }
                    if host.kind == .camera {
                        Text("CAM")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.indigo)
                            .foregroundStyle(.white)
                            .clipShape(Capsule())
                    }
                    if host.isExcluded {
                        Text("excluído")
                            .font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.gray.opacity(0.2))
                            .clipShape(Capsule())
                    }
                }
                HStack(spacing: 8) {
                    Text(host.mac.uppercased())
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if let vendor = host.vendor, !vendor.isEmpty {
                        Text(vendor)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                }
                if let name = host.hostname {
                    Text(name)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer(minLength: 8)

            // Throughput + sparkline
            if !host.throughputSamples.isEmpty {
                Sparkline(samples: host.throughputSamples,
                      color: host.isKilled ? .red : (host.isDiverted ? .orange : .green))
                .frame(width: 70)
            }
            Text(host.throughputText)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(host.isKilled ? .red : (host.isDiverted ? .orange : .secondary))
                .frame(width: 100, alignment: .trailing)
        }
        .padding(.vertical, 3)
        .opacity(host.isKilled ? 0.65 : 1)
    }
}

/// Short human-readable summary of a selective Kill policy, shown in the
/// menu when a policy is active.
func policySummary(_ policy: KillPolicy) -> String {
    if let kbit = policy.rateLimitKbit {
        let label = kbit >= 1024 ? String(format: "%.0f Mbit/s", Double(kbit) / 1024) : "\(kbit) Kbit/s"
        if policy.ports.isEmpty {
            return "Rate-limit \(label)"
        }
        return "Rate-limit \(label) p/\(policy.ports.map(String.init).joined(separator: ","))"
    }
    if policy.ports.isEmpty {
        return "Drop total"
    }
    let proto = policy.proto?.rawValue ?? "any"
    return "Drop \(policy.ports.map(String.init).joined(separator: ","))/\(proto)"
}

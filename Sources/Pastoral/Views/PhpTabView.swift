import SwiftUI
import PastoralCore

/// Tab PHP — PHP2Shell (CVE-2026-109618/109619).
///
/// Três degraus por alvo:
///   1. DETECÇÃO — passiva (headers de respostas capturadas) ou manual;
///   2. SINAL — probe de OOM/crash + vazamento de memória (PHPSESSID
///      anômalo, estilo Heartbleed); a amostra vazada cai na Colheita;
///   3. RCE cadeia A — planta código no filename do upload e dispara o
///      sink LFI contra o arquivo de sessão; o output cai na Colheita.
struct PhpTabView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                introPanel
                addRow
                ForEach(state.phpTargets) { target in
                    targetCard(target)
                }
                if state.phpTargets.isEmpty {
                    emptyHint
                }
            }
            .padding(20)
        }
    }

    // MARK: - Intro

    private var introPanel: some View {
        PastoralPanel {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Text("PHP2Shell")
                        .font(.system(size: 15, weight: .semibold))
                    Text("CVE-2026-109618 · CVE-2026-109619")
                        .font(.system(size: 9, weight: .medium))
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(PastoralTheme.mint.opacity(0.10), in: Capsule())
                        .foregroundStyle(PastoralTheme.mint)
                    Spacer()
                }
                Text("RCE pré-auth no core do PHP (5.4 → 8.5.11): um fatal error/OOM mal limpo deixa estado global velho, que o próximo request do mesmo worker consome. Corrigido em 21/10/2026 (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).")
                    .font(.system(size: 11)).foregroundStyle(PastoralTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Label("Ataque ativo em servidor de terceiros: use somente com autorização.",
                      systemImage: "exclamationmark.triangle")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.orange)
                HStack(spacing: 8) {
                    Text("Intensidade do gatilho OOM:")
                        .font(.system(size: 11)).foregroundStyle(PastoralTheme.muted)
                    Picker("", selection: $state.phpIntensity) {
                        ForEach(PhpOOMIntensity.allCases, id: \.self) { i in
                            Text(i.label).tag(i)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 240)
                    Spacer()
                }
            }
        }
    }

    private var addRow: some View {
        HStack(spacing: 8) {
            TextField("ip ou host[:porta][/caminho]  —  ex.: 192.168.0.12:8080/wp-login.php",
                      text: $state.phpNewTargetText)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11, design: .monospaced))
                .onSubmit { _ = state.addPhpTarget() }
            Button {
                _ = state.addPhpTarget()
            } label: {
                Label("Adicionar", systemImage: "plus")
            }
            .controlSize(.small)
        }
    }

    private var emptyHint: some View {
        VStack(spacing: 6) {
            Image(systemName: "chevron.left.forwardslash.chevron.right")
                .font(.system(size: 22)).foregroundStyle(PastoralTheme.muted.opacity(0.5))
            Text("Nenhum alvo PHP ainda.")
                .font(.system(size: 12, weight: .medium))
            Text("Alvos que anunciam PHP nas respostas capturadas entram sozinhos aqui — ou adicione um manualmente acima.")
                .font(.system(size: 10))
                .foregroundStyle(PastoralTheme.muted)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 30)
    }

    // MARK: - Card por alvo

    private func targetCard(_ t: PhpTarget) -> some View {
        let busy = state.phpBusyIDs.contains(t.id)
        return PastoralPanel {
            VStack(alignment: .leading, spacing: 12) {
                // Cabeçalho: identificador + versão + veredito + ações
                HStack(spacing: 8) {
                    Text("\(t.host):\(t.port)")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    if t.passive {
                        Text("detecção passiva")
                            .font(.system(size: 8, weight: .medium))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(PastoralTheme.mint.opacity(0.10), in: Capsule())
                            .foregroundStyle(PastoralTheme.mint)
                    }
                    if let v = t.report?.fingerprint {
                        Text("PHP \(v.version.text)")
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(PastoralTheme.muted)
                        Text("(\(v.source))")
                            .font(.system(size: 9))
                            .foregroundStyle(PastoralTheme.muted.opacity(0.7))
                    } else if let v = t.phpVersionText {
                        Text("PHP \(v)")
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(PastoralTheme.muted)
                    }
                    Spacer()
                    verdictBadge(t)
                    Button {
                        state.probePhp(targetID: t.id)
                    } label: {
                        Label(busy ? "Verificando…" : "Verificar",
                              systemImage: busy ? "ellipsis.circle" : "waveform.path.ecg")
                    }
                    .controlSize(.small)
                    .disabled(busy)
                    Button {
                        state.runPhpRCE(targetID: t.id)
                    } label: {
                        Label("RCE", systemImage: "terminal")
                    }
                    .controlSize(.small)
                    .disabled(busy)
                    .help("Cadeia A: filename do upload → sink LFI → include() roda seu comando")
                    Button {
                        state.removePhpTarget(t.id)
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 10, weight: .semibold))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(PastoralTheme.muted)
                    .accessibilityLabel("Remover alvo \(t.id)")
                }

                if t.basePath != "/" {
                    Text("caminho base: \(t.basePath)")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(PastoralTheme.muted)
                }

                // Relatório do último probe
                if let r = t.report {
                    reportBlock(r)
                }

                // Painel de RCE
                rcePanel(t)
            }
        }
    }

    /// VULNERÁVEL / CORRIGIDO / FORA DO ADVISORY / SUSPEITO / PHP?
    private func verdictBadge(_ t: PhpTarget) -> some View {
        let (label, color): (String, Color) = {
            guard let r = t.report else { return ("PHP?", PastoralTheme.muted) }
            switch r.vulnerability {
            case .patched: return ("CORRIGIDO", PastoralTheme.mint)
            case .unlisted: return ("FORA DO ADVISORY", .orange)
            case .vulnerable: return (r.confirmed ? "VULNERÁVEL" : "SUSPEITO", r.confirmed ? .red : .orange)
            case .none: return (r.confirmed ? "VULNERÁVEL" : "SUSPEITO", r.confirmed ? .red : .orange)
            }
        }()
        return Label(label, systemImage: label == "PHP?" ? "questionmark" : "shield.lefthalf.filled")
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 8).padding(.vertical, 4)
            .background(color.opacity(0.12), in: Capsule())
            .foregroundStyle(color)
    }

    private func reportBlock(_ r: PhpProbeReport) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(r.summary)
                .font(.system(size: 11, weight: .medium))
                .fixedSize(horizontal: false, vertical: true)
            ForEach(Array(r.detailLines.enumerated()), id: \.offset) { _, line in
                Text("· \(line)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(PastoralTheme.muted)
            }
            if let sample = r.disclosureSample {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Memória vazada (\(r.disclosureBytes ?? 0) B) — na Colheita",
                          systemImage: "memorychip")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(.red)
                    Text(sample)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(PastoralTheme.muted)
                        .textSelection(.enabled)
                        .lineLimit(4)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(Color.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(PastoralTheme.raised.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - RCE cadeia A

    private func rcePanel(_ t: PhpTarget) -> some View {
        let busy = state.phpBusyIDs.contains(t.id)
        return VStack(alignment: .leading, spacing: 8) {
            Label("RCE — cadeia A", systemImage: "key")
                .font(.system(size: 11, weight: .semibold))
            fieldRow("Sink LFI", placeholder: "/vuln.php?page=",
                     keyPath: \.lfiBase, of: t.id)
            HStack(spacing: 8) {
                fieldRow("Sessão", placeholder: "/tmp/sessions",
                         keyPath: \.sessionDir, of: t.id)
                    .frame(maxWidth: 220)
                fieldRow("Comando", placeholder: "id",
                         keyPath: \.command, of: t.id)
            }
            HStack(spacing: 10) {
                Button {
                    state.runPhpRCE(targetID: t.id)
                } label: {
                    Label(busy ? "Executando…" : "Executar comando", systemImage: "terminal.fill")
                }
                .controlSize(.small)
                .disabled(busy || t.lfiBase.trimmingCharacters(in: .whitespaces).isEmpty)
                Text("Exige um sink LFI real no alvo — sem isso a planta fica sem include().")
                    .font(.system(size: 9))
                    .foregroundStyle(PastoralTheme.muted)
                Spacer()
            }
            if let out = t.rceOutput {
                Text(out.isEmpty ? "(sem saída)" : out)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, minHeight: 24, alignment: .topLeading)
                    .padding(8)
                    .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    /// Campo rotulado + TextField com binding direto no alvo por keypath.
    private func fieldRow(_ label: String, placeholder: String,
                          keyPath: WritableKeyPath<PhpTarget, String>,
                          of id: String) -> some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(PastoralTheme.muted)
            TextField(placeholder,
                      text: Binding(
                          get: { state.phpTargets.first { $0.id == id }?[keyPath: keyPath] ?? "" },
                          set: { newValue in
                              state.updatePhpTarget(id) { $0[keyPath: keyPath] = newValue }
                          }))
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 10, design: .monospaced))
        }
    }
}

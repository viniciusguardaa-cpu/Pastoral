import SwiftUI

enum PastoralTheme {
    static let background = Color(red: 0.043, green: 0.071, blue: 0.059)
    static let sidebar = Color(red: 0.059, green: 0.102, blue: 0.082)
    static let surface = Color(red: 0.082, green: 0.129, blue: 0.106)
    static let raised = Color(red: 0.110, green: 0.165, blue: 0.137)
    static let cream = Color(red: 0.957, green: 0.933, blue: 0.875)
    static let mint = Color(red: 0.48, green: 0.83, blue: 0.65)
    static let muted = Color(red: 0.63, green: 0.70, blue: 0.65)
    static let border = Color.white.opacity(0.08)
}

struct PastoralBrandMark: View {
    var body: some View {
        if let url = AppResources.bundle.url(forResource: "Pastoral", withExtension: "icns", subdirectory: "Resources"),
           let icon = NSImage(contentsOf: url) {
            Image(nsImage: icon).resizable().scaledToFit().accessibilityHidden(true)
        } else {
            Image(systemName: "leaf.fill").foregroundStyle(PastoralTheme.mint).accessibilityHidden(true)
        }
    }
}

struct PastoralPanel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(PastoralTheme.surface, in: RoundedRectangle(cornerRadius: 18))
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(PastoralTheme.border))
    }
}

struct ConnectionBadge: View {
    let online: Bool
    var body: some View {
        Label(online ? "Serviço conectado" : "Serviço indisponível",
              systemImage: online ? "checkmark.circle.fill" : "exclamationmark.circle")
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(online ? PastoralTheme.mint : Color.orange)
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background((online ? PastoralTheme.mint : Color.orange).opacity(0.09), in: Capsule())
    }
}

extension PastoralTab {
    var title: String {
        switch self {
        case .overview: "Visão geral"
        case .arma: "Arma"
        case .kill: "Dispositivos"
        case .sheep: "Tráfego"
        case .cameras: "Câmeras"
        case .lobo: "Lobo"
        case .inject: "Inject"
        case .php: "PHP"
        case .settings: "Configurações"
        case .guided: "Modo guiado"
        }
    }
    var symbol: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .arma: "target"
        case .kill: "desktopcomputer"
        case .sheep: "waveform.path.ecg"
        case .cameras: "video"
        case .lobo: "pawprint"
        case .inject: "photo.on.rectangle"
        case .php: "chevron.left.forwardslash.chevron.right"
        case .settings: "slider.horizontal.3"
        case .guided: "list.number"
        }
    }
    var subtitle: String {
        switch self {
        case .overview: "O essencial da sua rede, em um só lugar."
        case .arma: "Quartel-general: ataque e status em uma tela."
        case .kill: "Equipamentos descobertos e estado das operações."
        case .sheep: "Registros disponíveis nesta sessão."
        case .cameras: "Dispositivos de vídeo e suas conexões."
        case .lobo: "Ferramenta avançada existente."
        case .inject: "Configuração de conteúdo da sessão."
        case .php: "PHP2Shell: detecção passiva, vazamento de memória e RCE pré-auth."
        case .settings: "Conexão, recuperação e informações do aplicativo."
        case .guided: "Acesso ao fluxo guiado do Pastoral."
        }
    }
}

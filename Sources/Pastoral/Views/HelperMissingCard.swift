import SwiftUI

struct HelperMissingCard: View {
    @Bindable var state: AppState
    @State private var checking = false
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 42, weight: .light)).foregroundStyle(PastoralTheme.mint)
            Text("Vamos conectar o serviço de rede").font(.title2.weight(.semibold))
            Text("O serviço não respondeu. Ele pode estar ausente, parado ou sem permissão. Verifique a conexão antes de instalar novamente.")
                .font(.callout).foregroundStyle(PastoralTheme.muted)
                .multilineTextAlignment(.center).frame(maxWidth: 390)
            HStack(spacing: 12) {
                Button(checking ? "Verificando…" : "Verificar conexão") {
                    checking = true
                    Task { await state.refreshStatus(); checking = false }
                }.disabled(checking)
                Button("Configurações") { state.selectedTab = .settings }
            }.controlSize(.large)
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(30)
    }
}

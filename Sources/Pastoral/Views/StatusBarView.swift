import SwiftUI

struct StatusBarView: View {
    @Bindable var state: AppState
    var body: some View {
        HStack(spacing: 18) {
            Label(state.network.interfaceName ?? "Sem interface", systemImage: "network")
            Text(state.network.localIP ?? "IP não informado").textSelection(.enabled)
            Spacer()
            Text(state.isRestoring ? "Restauração em andamento" : state.hasPendingRecovery ? "Restauração disponível" : "Sem pendências registradas")
            Circle().fill(state.hasPendingRecovery ? Color.orange : PastoralTheme.mint).frame(width: 5, height: 5)
        }
        .font(.system(size: 10)).foregroundStyle(PastoralTheme.muted)
        .padding(.horizontal, 28).padding(.vertical, 12)
        .overlay(alignment: .top) { Rectangle().fill(PastoralTheme.border).frame(height: 1) }
    }
}

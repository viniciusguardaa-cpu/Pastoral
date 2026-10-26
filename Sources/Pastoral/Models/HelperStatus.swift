import Foundation

/// Aggregated helper status shown in the status bar. `responding == false`
/// triggers the "Install helper" card.
struct HelperStatus: Equatable {
    var responding: Bool
    var forwarding: Bool
    var bpfAccessible: Bool
    var interface: String?

    static let offline = HelperStatus(responding: false, forwarding: false, bpfAccessible: false, interface: nil)
}

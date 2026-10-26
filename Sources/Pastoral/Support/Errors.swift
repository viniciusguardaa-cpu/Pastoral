import Foundation

/// Typed errors surfaced to the UI. Carries the raw process output when
/// available so the user sees exactly what failed — never a generic modal.
struct AppError: LocalizedError, CustomStringConvertible {
    let kind: Kind
    let detail: String?

    enum Kind: CustomStringConvertible, Equatable {
        case helperMissing
        case helperSocketFailed(String)
        case helperCommandFailed(String)
        case arpScanFailed
        case spoofFailed(String)
        case pfFailed(String)
        case forwardingFailed(String)
        case proxyFailed(String)
        case installFailed(String)
        case restoreFailed(String)
        case invalidInput(String)

        var description: String {
            switch self {
            case .helperMissing: return "Helper não instalado"
            case .helperSocketFailed(let m): return "Falha no socket do helper: \(m)"
            case .helperCommandFailed(let m): return "Comando do helper falhou: \(m)"
            case .arpScanFailed: return "Varredura ARP falhou"
            case .spoofFailed(let m): return "ARP spoof falhou: \(m)"
            case .pfFailed(let m): return "pf falhou: \(m)"
            case .forwardingFailed(let m): return "IP forwarding falhou: \(m)"
            case .proxyFailed(let m): return "Proxy falhou: \(m)"
            case .installFailed(let m): return "Instalação falhou: \(m)"
            case .restoreFailed(let m): return "Restauração falhou: \(m)"
            case .invalidInput(let m): return "Entrada inválida: \(m)"
            }
        }
    }

    init(_ kind: Kind, detail: String? = nil) {
        self.kind = kind
        self.detail = detail
    }

    var errorDescription: String? {
        if let detail, !detail.isEmpty {
            return "\(kind.description)\n\n\(detail)"
        }
        return kind.description
    }

    var description: String { errorDescription ?? kind.description }
}

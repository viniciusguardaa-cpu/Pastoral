import Foundation
import CryptoKit

/// Read-only local checks. Availability is not proof of a working tunnel.
struct LocalReadiness {
    enum HelperBuild { case unknown, matches, differs, missing }
    var helperBuild: HelperBuild = .unknown
    var wireGuardAvailable = false
    var tailscaleAvailable = false

    static func read() -> LocalReadiness {
        let fm = FileManager.default
        let helperPath = "/usr/local/sbin/pastoral-helper"
        let expectedText = Bundle.main.url(forResource: "helper", withExtension: "sha256")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
        let expected = expectedText?.trimmingCharacters(in: .whitespacesAndNewlines)
        var build = HelperBuild.unknown
        if !fm.fileExists(atPath: helperPath) { build = .missing }
        else if let expected, !expected.isEmpty,
                let data = try? Data(contentsOf: URL(fileURLWithPath: helperPath)) {
            let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            build = actual == expected ? .matches : .differs
        }
        return LocalReadiness(helperBuild: build,
            wireGuardAvailable: fm.isExecutableFile(atPath: "/usr/local/bin/wg") && fm.isExecutableFile(atPath: "/usr/local/bin/wg-quick"),
            tailscaleAvailable: fm.isExecutableFile(atPath: "/usr/local/bin/tailscale"))
    }

    var helperDescription: String {
        switch helperBuild {
        case .unknown: "Versão do serviço ainda não conferida."
        case .matches: "O serviço instalado corresponde a esta versão do aplicativo."
        case .differs: "O serviço instalado é diferente do incluído nesta versão. A atualização requer permissão administrativa."
        case .missing: "O serviço de rede não está instalado."
        }
    }
}

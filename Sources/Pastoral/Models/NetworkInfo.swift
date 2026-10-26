import Foundation

/// Local network context shown in the permanent status bar: chosen
/// interface, local IP/MAC, detected gateway. Populated by CoreWLAN +
/// routing-socket queries in step 2+.
struct NetworkInfo: Equatable {
    var interfaceName: String?
    var localIP: String?
    var localMAC: String?
    var gatewayIP: String?
    var gatewayMAC: String?
    var ssid: String?

    static let placeholder = NetworkInfo()
}

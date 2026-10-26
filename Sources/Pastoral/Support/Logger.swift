import Foundation
import os

/// Centralized os.log logger for the whole app.
enum AppLog {
    private static let subsystem = "com.pastoral.app"

    static let app = Logger(subsystem: subsystem, category: "app")
    static let helper = Logger(subsystem: subsystem, category: "helper")
    static let arp = Logger(subsystem: subsystem, category: "arp")
    static let pf = Logger(subsystem: subsystem, category: "pf")
    static let proxy = Logger(subsystem: subsystem, category: "proxy")
    static let tls = Logger(subsystem: subsystem, category: "tls")
    static let wifi = Logger(subsystem: subsystem, category: "wifi")
    static let restore = Logger(subsystem: subsystem, category: "restore")
}

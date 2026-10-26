import Foundation
import Observation

/// A single timestamped log line, surfaced in the status bar / diagnostics.
struct LogEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: Date
    let level: Level
    let message: String

    enum Level: String, Hashable {
        case info, warning, error
    }

    var prefix: String {
        let t = timestamp.formatted(.dateTime.hour().minute().second())
        return "[\(t)] \(level.rawValue.uppercased())"
    }
}

/// Observable ring-buffer of recent log lines. Kept small for the UI.
@MainActor
@Observable
final class LogStore {
    private(set) var entries: [LogEntry] = []
    private let cap = 500

    func info(_ message: String) { append(.info, message) }
    func warn(_ message: String) { append(.warning, message) }
    func error(_ message: String) { append(.error, message) }

    private func append(_ level: LogEntry.Level, _ message: String) {
        entries.append(LogEntry(timestamp: .now, level: level, message: message))
        if entries.count > cap { entries.removeFirst(entries.count - cap) }
        AppLog.app.log("\(level.rawValue, privacy: .public): \(message, privacy: .public)")
    }

    func clear() { entries.removeAll() }
}

import Foundation
import Darwin
import PastoralCore

/// Manages pf anchors and rules for the Kill feature. Handles:
/// - Backup of /etc/pf.conf to /var/db/pastoral/pf.conf.bak (byte-exact)
/// - Adding the anchor include line to /etc/pf.conf if absent
/// - Adding/removing drop rules in the anchor via pfctl
/// - Restoring /etc/pf.conf on cleanup
final class PFManager {
    static let pfConfPath = "/etc/pf.conf"
    static let backupDir = "/var/db/pastoral"
    static let backupPath = "/var/db/pastoral/pf.conf.bak"
    /// Canonical rule file for the kill anchor — always rewritten with
    /// the *full* active set before loading (see addDropRule).
    static let anchorConfPath = "/var/db/pastoral/kill.conf"
    /// One active target IP per line — survives helper restarts.
    static let targetsPath = "/var/db/pastoral/kill.targets"
    static let anchor = PFAnchorManager.killAnchor

    private var backedUp = false
    /// Active kill targets. The anchor conf is generated from this set;
    /// `pfctl -a <anchor> -f <file>` replaces the whole anchor, so
    /// per-target temp files clobbered each other (only the last target
    /// would end up dropped).
    private var activeTargets: Set<String> = []

    init() {
        // Rebuild the set from disk so a restarted helper regenerates
        // every rule, not just the most recent target.
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: Self.targetsPath)),
              let text = String(data: data, encoding: .utf8) else { return }
        for line in text.split(whereSeparator: \.isNewline) {
            let ip = line.trimmingCharacters(in: .whitespaces)
            if !ip.isEmpty { activeTargets.insert(ip) }
        }
    }

    // MARK: - Backup

    /// Back up /etc/pf.conf byte-exact before any modification.
    func backup() {
        guard !backedUp else { return }
        let fm = FileManager.default
        try? fm.createDirectory(atPath: Self.backupDir, withIntermediateDirectories: true)
        if fm.fileExists(atPath: Self.pfConfPath) {
            try? fm.copyItem(atPath: Self.pfConfPath, toPath: Self.backupPath)
        } else {
            // pf.conf doesn't exist; create an empty backup so restore knows
            // to remove our additions entirely.
            try? Data().write(to: URL(fileURLWithPath: Self.backupPath))
        }
        backedUp = true
    }

    // MARK: - Anchor include

    /// Ensure the anchor include line is in /etc/pf.conf. Never overwrites
    /// the file — only appends the line if absent.
    func ensureAnchor() {
        backup()
        let fm = FileManager.default
        var contents = ""
        if let data = try? Data(contentsOf: URL(fileURLWithPath: Self.pfConfPath)) {
            contents = String(data: data, encoding: .utf8) ?? ""
        }
        guard !PFAnchorManager.hasKillAnchor(in: contents) else { return }
        let updated = PFAnchorManager.ensureKillAnchor(in: contents)
        try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: Self.pfConfPath))
        // Reload pf to pick up the new anchor.
        runShell("pfctl -f \(Self.pfConfPath) 2>/dev/null || true")
    }

    // MARK: - Drop rules

    /// Add a drop rule for a target IP. All active targets are re-emitted
    /// into one canonical file and loaded into the anchor in a single
    /// `pfctl -f` — additive across targets and idempotent.
    func addDropRule(for targetIP: String) {
        activeTargets.insert(targetIP)
        ensureAnchor()
        // Enable pf if it's not already running.
        let enableResult = runShell("pfctl -e 2>&1")
        FileHandle.standardError.write("PFManager: pfctl -e → \(enableResult)\n".data(using: .utf8)!)
        persistAndLoadAnchor()
    }

    /// Remove one target's rule; the remaining targets stay active.
    func removeDropRule(for targetIP: String) -> Bool {
        let previous = activeTargets
        activeTargets.remove(targetIP)
        guard persistAndLoadAnchor() else {
            activeTargets = previous
            return false
        }
        return true
    }

    /// Rewrite the canonical rule file from `activeTargets` and load it
    /// into the anchor. Needs the anchor already present in /etc/pf.conf.
    @discardableResult
    private func persistAndLoadAnchor() -> Bool {
        let fm = FileManager.default
        let targetsData = activeTargets.sorted()
            .map { $0 + "\n" }.joined().data(using: .utf8)
        let rules = activeTargets.map { PFAnchorManager.dropRule(for: $0) }
            .joined(separator: "\n")
        let confData = rules.isEmpty ? Data()
            : (rules + "\n").data(using: .utf8)!
        do {
            try fm.createDirectory(atPath: Self.backupDir, withIntermediateDirectories: true)
            try confData.write(to: URL(fileURLWithPath: Self.anchorConfPath), options: .atomic)
        } catch { return false }
        let loadResult = runShell("pfctl -a \(Self.anchor) -f \(Self.anchorConfPath) 2>&1")
        FileHandle.standardError.write("PFManager: pfctl -a \(Self.anchor) -f → \(loadResult)\n".data(using: .utf8)!)
        guard loadResult == 0 else { return false }
        do {
            try targetsData?.write(to: URL(fileURLWithPath: Self.targetsPath), options: .atomic)
            return true
        } catch { return false }
    }

    /// Remove all rules from the kill anchor.
    func clearDropRules() {
        activeTargets.removeAll()
        let fm = FileManager.default
        try? fm.removeItem(atPath: Self.targetsPath)
        try? Data().write(to: URL(fileURLWithPath: Self.anchorConfPath))
        runShell("pfctl -a \(Self.anchor) -F rules 2>/dev/null || true")
    }

    /// Remove the anchor include line from /etc/pf.conf and restore.
    func removeAnchor() {
        let fm = FileManager.default
        var contents = ""
        if let data = try? Data(contentsOf: URL(fileURLWithPath: Self.pfConfPath)) {
            contents = String(data: data, encoding: .utf8) ?? ""
        }
        let updated = PFAnchorManager.removeKillAnchor(from: contents)
        try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: Self.pfConfPath))
        runShell("pfctl -f \(Self.pfConfPath) 2>/dev/null || true")
    }

    // MARK: - Restore

    /// Restore /etc/pf.conf from the byte-exact backup. Copy to a
    /// staging file first and only replace the live file once the copy
    /// actually landed — the old remove→copy order could leave
    /// /etc/pf.conf deleted entirely when the copy failed.
    func restore() {
        clearDropRules()
        let fm = FileManager.default
        if fm.fileExists(atPath: Self.backupPath) {
            let staging = Self.pfConfPath + ".pastoral.new"
            do {
                try fm.copyItem(atPath: Self.backupPath, toPath: staging)
                guard Darwin.rename(staging, Self.pfConfPath) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                runShell("pfctl -f \(Self.pfConfPath) 2>/dev/null || true")
            } catch {
                try? fm.removeItem(atPath: staging)
                FileHandle.standardError.write("PFManager: restore falhou: \(error)\n".data(using: .utf8)!)
            }
        }
        activeTargets.removeAll()
        backedUp = false
    }

    // MARK: - Shell

    @discardableResult
    private func runShell(_ cmd: String) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", cmd]
        p.standardOutput = FileHandle.standardError
        p.standardError = FileHandle.standardError
        do { try p.run(); p.waitUntilExit() } catch { return -1 }
        return p.terminationStatus
    }
}

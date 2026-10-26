import Foundation
import Darwin
import PastoralCore

/// Real SystemProbe used by the helper daemon. Reads sysctl, parses the
/// default route, and inspects /dev/bpf* permissions.
struct LiveSystemProbe: SystemProbe {
    func ipForwardingEnabled() -> Bool {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let r = sysctlbyname("net.inet.ip.forwarding", &value, &size, nil, 0)
        return r == 0 && value != 0
    }

    /// Parse `route -n get default` for the interface and gateway. The
    /// `route` tool is a thin wrapper over AF_ROUTE; a future refinement
    /// can use a routing socket directly.
    func defaultInterface() -> String? {
        guard let output = runCapture("/sbin/route", ["-n", "get", "default"]) else { return nil }
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                return String(trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }

    func bpfAccessible() -> Bool {
        // BPF is accessible to the helper (root) if any /dev/bpf* device
        // exists. The reset step ensures the access_bpf group can read/write
        // them; here we just confirm presence.
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: "/dev") else { return false }
        return entries.contains { $0.hasPrefix("bpf") }
    }

    func accessBPFGroupID() -> gid_t? {
        // Look up the `access_bpf` group via getgrnam.
        guard let grp = getgrnam("access_bpf") else { return nil }
        return grp.pointee.gr_gid
    }

    private func runCapture(_ path: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do {
            try p.run()
            p.waitUntilExit()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }
}

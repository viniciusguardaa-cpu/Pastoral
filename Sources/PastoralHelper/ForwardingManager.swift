import Foundation
import Darwin
import PastoralCore

/// Manages IPv4 forwarding (sysctl net.inet.ip.forwarding). Records the
/// prior state before enabling so it can be restored on disable.
final class ForwardingManager {
    private var priorState: Bool? = nil

    /// Read the current forwarding state.
    func currentState() -> Bool {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let r = sysctlbyname("net.inet.ip.forwarding", &value, &size, nil, 0)
        return r == 0 && value != 0
    }

    /// Enable forwarding. Records the prior state for restore — but only
    /// the *first* call wins: once we've flipped it on, currentState() is
    /// no longer the user's original value, so re-recording would make
    /// disable() restore "on" instead of the pre-Pastoral state (e.g.
    /// kill leaves forwarding up, sheep calls enable() again, cleanup
    /// would have kept it on).
    func enable() -> Bool {
        if priorState == nil {
            priorState = currentState()
        }
        return setForwarding(true)
    }

    /// Disable while retaining the original state for subsequent cleanup.
    func disable() -> Bool {
        if priorState == nil { priorState = currentState() }
        return setForwarding(false)
    }

    /// Idempotent restoration; repeated cleanup must not overwrite the
    /// original value after it has already been restored.
    func restore() -> Bool {
        guard let target = priorState else { return true }
        guard setForwarding(target) else { return false }
        priorState = nil
        return true
    }

    private func setForwarding(_ on: Bool) -> Bool {
        var value: Int32 = on ? 1 : 0
        let r = sysctlbyname("net.inet.ip.forwarding", nil, nil, &value, MemoryLayout<Int32>.size)
        return r == 0
    }
}

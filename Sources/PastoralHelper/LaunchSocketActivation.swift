import Foundation
import Darwin

/// Bridges to launchd socket activation. launchd creates and listens on the
/// Unix socket declared in the job's `Sockets` dict; the helper retrieves
/// the listening fd via `launch_activate_socket()` (from launch.h, part of
/// libSystem). We resolve the symbol with dlsym to avoid a custom module
/// map. When not running under launchd (manual/testing), this fails with
/// ESRCH and the caller falls back to creating the socket itself.
enum LaunchSocketActivation {
    /// Socket name — must match the key in the `Sockets` dictionary of
    /// com.pastoral.helper.plist.
    static let socketName = "PastoralSocket"

    /// Try to retrieve the listening socket fd(s) from launchd.
    /// Returns the file descriptors, or nil if not under launchd / not
    /// configured (caller should create the socket itself).
    static func acquire() -> [Int32]? {
        guard let fn = symbol else { return nil }
        var fds: UnsafeMutablePointer<CInt>? = nil
        var cnt: Int = 0
        let err = fn(socketName, &fds, &cnt)
        guard err == 0, let fds, cnt > 0 else { return nil }
        defer { free(fds) }
        return (0..<cnt).map { fds[$0] }
    }

    private static let symbol: launch_activate_socket_t? = {
        guard let handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY) else { return nil }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, "launch_activate_socket") else { return nil }
        return unsafeBitCast(sym, to: launch_activate_socket_t.self)
    }()

    private typealias launch_activate_socket_t =
        @convention(c) (UnsafePointer<CChar>,
                        UnsafeMutablePointer<UnsafeMutablePointer<CInt>?>,
                        UnsafeMutablePointer<Int>) -> CInt
}

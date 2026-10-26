import Foundation
import Darwin

/// Runs the helper .pkg with admin privileges. Uses the (deprecated but
/// functional) `AuthorizationExecuteWithPrivileges` to run
/// `/usr/sbin/installer -pkg ... -target /`, resolved via dlsym so we
/// don't need a bridging header. Falls back to opening the pkg in
/// Installer.app if the authorization API is unavailable.
enum PrivilegedInstaller {
    static func install(pkg: URL) -> Bool {
        if let r = executeWithPrivileges(pkg: pkg) { return r }
        return openInInstallerApp(pkg: pkg)
    }

    // MARK: - AuthorizationExecuteWithPrivileges

    private static func executeWithPrivileges(pkg: URL) -> Bool? {
        guard let authCreate = AuthorizationCreateSymbol,
              let authExec = AuthorizationExecuteWithPrivilegesSymbol else {
            return nil   // API unavailable → caller falls back
        }

        var auth: AuthorizationRef? = nil
        // kAuthorizationFlagPreAuthorize = 1<<0
        let createErr = authCreate(nil, 1, nil, &auth)
        guard createErr == 0, let authRef = auth else { return false }
        defer { _ = AuthorizationFreeSymbol?(authRef, 8) }   // kAuthorizationFlagDestroyRights = 1<<3

        let tool = "/usr/sbin/installer"
        var args: [UnsafeMutablePointer<CChar>?] = [
            strdup("-pkg"), strdup(pkg.path), strdup("-target"), strdup("/"), nil
        ]
        defer { args.compactMap { $0 }.forEach { free($0) } }

        var pipe: UnsafeMutablePointer<FILE>? = nil
        let execErr: OSStatus = args.withUnsafeMutableBufferPointer { buf -> OSStatus in
            authExec(authRef, tool, 0, buf.baseAddress, &pipe)
        }
        if execErr != 0 { return false }
        if let pipe { fclose(pipe) }

        // Poll briefly for the socket to appear (best-effort signal).
        for _ in 0..<20 {
            if FileManager.default.fileExists(atPath: "/var/run/pastoral.sock") { return true }
            usleep(150_000)
        }
        return true
    }

    private static func openInInstallerApp(pkg: URL) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        task.arguments = [pkg.path]
        do { try task.run(); task.waitUntilExit(); return task.terminationStatus == 0 }
        catch { return false }
    }

    // MARK: - dlsym bridges to Security.framework (in libSystem)

    private typealias AuthorizationRef = OpaquePointer

    // C: AuthorizationCreate(AuthorizationRef, AuthorizationRights *,
    //                       AuthorizationFlags, AuthorizationEnvironment *,
    //                       AuthorizationRef *). We pass nil for the two
    // pointer args, so use raw OpaquePointer? to keep @convention(c) happy.
    private typealias AuthorizationCreateFn =
        @convention(c) (OpaquePointer?, UInt32, OpaquePointer?,
                        UnsafeMutablePointer<AuthorizationRef?>) -> OSStatus
    private typealias AuthorizationExecuteWithPrivilegesFn =
        @convention(c) (AuthorizationRef, UnsafePointer<CChar>, UInt32,
                        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
                        UnsafeMutablePointer<UnsafeMutablePointer<FILE>?>) -> OSStatus
    private typealias AuthorizationFreeFn =
        @convention(c) (AuthorizationRef, UInt32) -> OSStatus

    private static let AuthorizationCreateSymbol: AuthorizationCreateFn? = load("AuthorizationCreate")
    private static let AuthorizationExecuteWithPrivilegesSymbol: AuthorizationExecuteWithPrivilegesFn? =
        load("AuthorizationExecuteWithPrivileges")
    private static let AuthorizationFreeSymbol: AuthorizationFreeFn? = load("AuthorizationFree")

    private static func load<T>(_ name: String) -> T? {
        guard let handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY) else { return nil }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }
}

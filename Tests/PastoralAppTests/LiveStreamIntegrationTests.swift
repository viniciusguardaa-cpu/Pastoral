import Testing
import Foundation
import AppKit
@testable import Pastoral

/// Integration test: spins up the local fake RTSP camera
/// (Tests/fixtures/rtsp_test_server.py) and runs the real RTSPStreamClient
/// against it — digest auth, DESCRIBE/SETUP/PLAY, interleaved RTP, and
/// frame delivery for every supported codec.

@Suite("RTSP live stream integration")
struct LiveStreamIntegrationTests {

    // MARK: - Fake server plumbing

    private var fixtureDir: URL {
        URL(fileURLWithPath: #filePath)   // Tests/PastoralAppTests/LiveStreamIntegrationTests.swift
            .deletingLastPathComponent()   // Tests/PastoralAppTests
            .deletingLastPathComponent()   // Tests
            .appendingPathComponent("fixtures")
    }

    private struct FakeServer: Sendable {
        let port: Int
        let process: Process
    }

    private func freePort() -> Int {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(s) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = INADDR_LOOPBACK
        _ = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        var bound = sockaddr_in()
        _ = withUnsafeMutablePointer(to: &bound) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(s, $0, &len)
            }
        }
        return Int(UInt16(bigEndian: bound.sin_port))
    }

    private func startServer(args extra: [String]) throws -> FakeServer {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        // Port 0: the server picks a free port itself and reports the real
        // one on the READY line — binding a probe socket from Swift to pick
        // a port is unreliable on this box (loopback :0 binds intermittently
        // return EADDRINUSE, leaving freePort() stuck at 0).
        proc.arguments = [fixtureDir.appendingPathComponent("rtsp_test_server.py").path,
                          "--port", "0"] + extra
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = outPipe
        try proc.run()
        // Wait for the READY line (server fully listening) — bounded.
        var port = -1
        let deadline = Date().addingTimeInterval(10)
        var buf = Data()
        while Date() < deadline {
            buf.append(outPipe.fileHandleForReading.availableData)
            if let s = String(data: buf, encoding: .utf8)?
                .split(separator: "\n").last(where: { $0.hasPrefix("READY ") }) {
                port = Int(s.split(separator: " ").dropFirst().first ?? "") ?? -1
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard port > 0 else {
            proc.terminate()
            throw TestError("fake server did not start (no port): \(String(data: buf, encoding: .utf8) ?? "?")")
        }
        return FakeServer(port: port, process: proc)
    }

    private struct TestError: Error, CustomStringConvertible {
        let description: String
        init(_ s: String) { description = s }
    }

    /// Collects frames from the client (called on a background thread).
    private final class FrameBox: @unchecked Sendable {
        private let lock = NSLock()
        private var frames: [NSImage] = []
        private var errors: [String] = []
        func append(_ img: NSImage) { lock.lock(); frames.append(img); lock.unlock() }
        func appendError(_ msg: String) { lock.lock(); errors.append(msg); lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return frames.count }
        var errorList: [String] { lock.lock(); defer { lock.unlock() }; return errors }
        var lastFrame: NSImage? { lock.lock(); defer { lock.unlock() }; return frames.last }
    }

    private func waitFrames(_ box: FrameBox, atLeast n: Int, timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if box.count >= n || !box.errorList.isEmpty { return }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
    }

    // MARK: - Tests

    @Test("JPEG-over-RTP live stream delivers frames through Digest auth")
    func jpegLive() async throws {
        guard FileManager.default.fileExists(atPath: fixtureDir.appendingPathComponent("frame.jpg").path) else {
            Issue.record("run `swift Scripts/dev-make-test-jpeg.swift` first"); return
        }
        let srv = try startServer(args: ["--auth", "digest", "--media",
                                         fixtureDir.appendingPathComponent("frame.jpg").path])
        defer { srv.process.terminate() }

        let box = FrameBox()
        // First credential is wrong — the client must 401-retry into the right one.
        let client = RTSPStreamClient(
            host: "127.0.0.1", port: srv.port, path: "/",
            credentials: [("admin", "wrong", false), ("admin", "secret", true)])
        client.onFrame = { frame in
            switch frame {
            case .image(let img): box.append(img)
            case .error(let msg): box.appendError(msg)
            case .codecDetected: break
            }
        }
        let task = Task.detached { await client.stream() }
        defer { task.cancel() }

        try await waitFrames(box, atLeast: 3, timeout: 20)
        #expect(box.errorList.isEmpty, "unexpected errors: \(box.errorList)")
        #expect(box.count >= 3, "got \(box.count) frames (\(box.errorList))")
        #expect(box.lastFrame?.size != .zero)
    }

    @Test("H.265/HEVC live stream decodes to frames")
    func hevcLive() async throws {
        let nalFile = fixtureDir.appendingPathComponent("test.hevc.nals.txt")
        guard FileManager.default.fileExists(atPath: nalFile.path) else {
            Issue.record("run the HEVC NAL generator first (Scripts/dev-make-test-hevc.swift)"); return
        }
        let srv = try startServer(args: ["--auth", "digest", "--hevc-nals", nalFile.path])
        defer { srv.process.terminate() }

        let box = FrameBox()
        let client = RTSPStreamClient(
            host: "127.0.0.1", port: srv.port, path: "/",
            credentials: [("admin", "secret", true)])
        client.onFrame = { frame in
            switch frame {
            case .image(let img): box.append(img)
            case .error(let msg): box.appendError(msg)
            case .codecDetected: break
            }
        }
        let task = Task.detached { await client.stream() }
        defer { task.cancel() }

        try await waitFrames(box, atLeast: 3, timeout: 25)
        #expect(box.errorList.isEmpty, "unexpected errors: \(box.errorList)")
        #expect(box.count >= 3, "got \(box.count) frames (\(box.errorList))")
    }
}

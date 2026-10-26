import Testing
import Foundation
import Network
@testable import PastoralProxy
import PastoralCore

/// Integration test: start the proxy, make a local HTTP request through it
/// via a raw TCP socket, verify the captured log.
@Suite("Proxy integration")
struct ProxyIntegrationTests {

    @Test("Proxy captures a plain HTTP request")
    func captureHTTP() async throws {
        // Start a tiny origin HTTP server on a fixed port.
        let originPort: UInt16 = 19090
        let origin = try await startOriginServer(port: originPort)
        defer { origin.cancel() }

        // Start the proxy on a test port.
        let proxyPort: UInt16 = 18080
        let captures = ProxyCaptureStore()
        let proxy = TransparentProxy(port: proxyPort) { ex in
            captures.add(ex)
        }
        try await proxy.start()
        defer { proxy.stop() }

        // Give both a moment to start listening.
        try await Task.sleep(for: .milliseconds(300))

        // Connect to the proxy and send a raw HTTP request targeting the
        // origin server (Host: 127.0.0.1:19090).
        let request = "GET /test HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n"
        let response = try await sendThroughProxy(proxyPort: proxyPort, request: request)

        // Verify we got a 200 back from the origin (through the proxy).
        #expect(response.contains("200 OK"))
        #expect(response.contains("hello"))

        // Wait for the capture to arrive.
        try await Task.sleep(for: .milliseconds(500))

        let all = captures.all()
        #expect(!all.isEmpty)
        let first = all.first { $0.method == "GET" }
        #expect(first != nil)
        #expect(first?.host == "127.0.0.1")
        #expect(first?.path.contains("/test") == true)
        #expect(first?.status == 200)
    }

    @Test("Proxy rewrites an image response with the injected body")
    func rewriteImage() async throws {
        // Origin serves a "real" image.
        let originPort: UInt16 = 19091
        let origin = try await startImageOrigin(port: originPort)
        defer { origin.cancel() }

        // Proxy with the injection engine loaded.
        let proxyPort: UInt16 = 18081
        let captures = ProxyCaptureStore()
        let proxy = TransparentProxy(port: proxyPort) { ex in
            captures.add(ex)
        }
        let injected = PreparedImage(data: Data("OWNED".utf8),
                                     contentType: "image/png")
        proxy.injection = InjectionEngine(
            rule: InjectionRule(scope: .allImages), images: [injected])
        try await proxy.start()
        defer { proxy.stop() }

        try await Task.sleep(for: .milliseconds(300))

        let request = "GET /pic.png HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n"
        let response = try await sendThroughProxy(proxyPort: proxyPort, request: request)

        // The client receives our bytes, not the origin's.
        #expect(response.contains("Content-Type: image/png"))
        #expect(response.contains("Content-Length: 5"))
        #expect(response.contains("OWNED"))
        #expect(!response.contains("REAL-IMAGE-BYTES"))

        try await Task.sleep(for: .milliseconds(500))
        let first = captures.all().first { $0.method == "GET" }
        #expect(first?.wasRewritten == true)
    }

    @Test("Portal harvests a fake-login POST and serves the CA profile")
    func portalCred() async throws {
        let proxyPort: UInt16 = 18082
        let captures = ProxyCaptureStore()
        let box = CredBox()
        let proxy = TransparentProxy(port: proxyPort) { ex in captures.add(ex) }
        proxy.portalRule = PortalRule(targetIP: "127.0.0.1",
                                      html: Data("<html>PAGINA-LOBO</html>".utf8),
                                      caProfile: Data("PROFILE-BYTES".utf8))
        proxy.portalSSID = "Casa"
        proxy.onCredential = { cred in box.add(cred) }
        try await proxy.start()
        defer { proxy.stop() }
        try await Task.sleep(for: .milliseconds(300))

        // The diverted target (clientIP 127.0.0.1 here) submits the form.
        let body = "user=joao%40x.com&pass=a+b&page=iCloud"
        let post = "POST \(CredentialPortal.credPath) HTTP/1.1\r\n"
                 + "Host: 127.0.0.1\r\n"
                 + "Content-Type: application/x-www-form-urlencoded\r\n"
                 + "Content-Length: \(body.utf8.count)\r\n"
                 + "Connection: close\r\n\r\n\(body)"
        let resp = try await sendThroughProxy(proxyPort: proxyPort, request: post)
        #expect(resp.contains("200 OK"))

        try await Task.sleep(for: .milliseconds(300))
        let creds = box.items()
        #expect(creds.count == 1)
        #expect(creds.first?.user == "joao@x.com")
        #expect(creds.first?.pass == "a b")
        #expect(creds.first?.page == "iCloud")
        #expect(creds.first?.ssid == "Casa")

        // The success page is captured like any other request.
        #expect(captures.all().contains { $0.host == "pastoral-portal" })

        // The CA trap profile comes back byte-for-byte.
        let get = "GET \(CredentialPortal.caProfilePath) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        let respCA = try await sendThroughProxy(proxyPort: proxyPort, request: get)
        #expect(respCA.contains("PROFILE-BYTES"))
        #expect(respCA.contains("application/x-apple-asymmetric-config"))
    }
    @Test("Occupied port fails startup instead of reporting running")
    func occupiedPort() async throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let blocker = try NWListener(using: params)
        blocker.newConnectionHandler = { $0.cancel() }
        defer { blocker.cancel() }
        let port: UInt16 = try await withCheckedThrowingContinuation { cont in
            blocker.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    blocker.stateUpdateHandler = nil
                    cont.resume(returning: blocker.port!.rawValue)
                case .failed(let error):
                    blocker.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                default: break
                }
            }
            blocker.start(queue: .global())
        }
        let proxy = TransparentProxy(port: port) { _ in }
        defer { proxy.stop() }
        do {
            try await proxy.start()
            Issue.record("An occupied port must not be reported ready")
        } catch { }
        #expect(!proxy.isRunning)
    }

    @Test("Stop clears readiness after a successful local startup")
    func stopReadiness() async throws {
        let proxy = TransparentProxy(port: 0) { _ in }
        try await proxy.start()
        #expect(proxy.isRunning)
        proxy.stop()
        #expect(!proxy.isRunning)
    }

}

/// Thread-safe storage for captured exchanges in tests.
final class ProxyCaptureStore: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [CapturedExchange] = []

    func add(_ ex: CapturedExchange) {
        lock.lock()
        items.append(ex)
        lock.unlock()
    }

    func all() -> [CapturedExchange] {
        lock.lock()
        defer { lock.unlock() }
        return items
    }
}

/// Thread-safe sink for portal credentials in tests.
final class CredBox: @unchecked Sendable {
    private let lock = NSLock()
    private var creds: [CapturedCredential] = []

    func add(_ c: CapturedCredential) {
        lock.lock()
        creds.append(c)
        lock.unlock()
    }

    func items() -> [CapturedCredential] {
        lock.lock()
        defer { lock.unlock() }
        return creds
    }
}

// MARK: - Helpers

/// Start a tiny origin HTTP server that responds with 200 OK + "hello".
func startOriginServer(port: UInt16) async throws -> NWListener {
    let params = NWParameters.tcp
    params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
    let listener = try NWListener(using: params)
    listener.newConnectionHandler = { conn in
        conn.start(queue: .global())
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { _, _, _, _ in
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
                .data(using: .utf8)!
            conn.send(content: resp, completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
    }
    listener.start(queue: .global())
    return listener
}

/// Start a tiny origin HTTP server that responds with image/png bytes.
func startImageOrigin(port: UInt16) async throws -> NWListener {
    let params = NWParameters.tcp
    params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
    let listener = try NWListener(using: params)
    listener.newConnectionHandler = { conn in
        conn.start(queue: .global())
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { _, _, _, _ in
            let body = "REAL-IMAGE-BYTES"
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: \(body.count)\r\nContent-Type: image/png\r\nETag: \"x\"\r\nCache-Control: max-age=999\r\n\r\n\(body)"
                .data(using: .utf8)!
            conn.send(content: resp, completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
    }
    listener.start(queue: .global())
    return listener
}

/// Send a raw HTTP request through the proxy and return the response.
func sendThroughProxy(proxyPort: UInt16, request: String) async throws -> String {
    return try await withCheckedThrowingContinuation { cont in
        let conn = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(integerLiteral: proxyPort),
            using: NWParameters.tcp
        )
        conn.start(queue: .global())
        conn.send(content: request.data(using: .utf8)!, completion: .contentProcessed { error in
            if let error { cont.resume(throwing: error); return }
            // Read the full response.
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, _ in
                let resp = String(data: data ?? Data(), encoding: .utf8) ?? ""
                if isComplete {
                    cont.resume(returning: resp)
                } else {
                    // Read more if needed.
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data2, _, _, _ in
                        cont.resume(returning: resp + (String(data: data2 ?? Data(), encoding: .utf8) ?? ""))
                    }
                }
            }
        })
    }
}

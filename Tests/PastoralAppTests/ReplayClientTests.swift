import Testing
import Foundation
import Network
import PastoralCore
@testable import Pastoral

@Suite("Replay transport regressions")
struct ReplayClientTests {
    private func exchange(body: Data? = nil) -> CapturedExchange {
        CapturedExchange(host: "127.0.0.1", method: body == nil ? "GET" : "POST", path: "/check",
                         requestHeaders: ["Host": "127.0.0.1"], requestBody: body)
    }

    @Test("Binary body survives construction and local HTTP transport")
    func binary() async throws {
        let server = try LocalHTTPServer(response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        let port = try await server.start()
        defer { server.stop() }
        let payload = Data([0xff, 0, 0x80, 1])
        let result = await ReplayClient(timeout: 3).replay(exchange(body: payload), port: port)
        #expect(result.error == nil)
        #expect(result.status == 200)
        #expect(result.responseBody == Data("OK".utf8))
        #expect(HTTPRequestParser.parse(server.request)?.body == payload)
        #expect(HTTPRequestParser.parse(result.requestBytes)?.body == payload)
    }

    @Test("Content-Length response finishes while server keeps connection open")
    func keepAlive() async throws {
        let server = try LocalHTTPServer(response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello")
        let port = try await server.start()
        defer { server.stop() }
        let result = await ReplayClient(timeout: 2).replay(exchange(), port: port)
        #expect(result.error == nil)
        #expect(result.responseBody == Data("hello".utf8))
    }

    @Test("A silent server produces a bounded timeout, not success")
    func silentServer() async throws {
        let server = try LocalHTTPServer(response: nil)
        let port = try await server.start()
        defer { server.stop() }
        let result = await ReplayClient(timeout: 1).replay(exchange(), port: port)
        #expect(result.error != nil)
        #expect(result.status == nil)
    }

    @Test("Truncated responses are errors")
    func incomplete() async throws {
        let server = try LocalHTTPServer(response: "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nx", closeAfterSend: true)
        let port = try await server.start()
        defer { server.stop() }
        let result = await ReplayClient(timeout: 2).replay(exchange(), port: port)
        #expect(result.error != nil)
    }

    @Test("Redirect is returned without contacting its destination")
    func redirect() async throws {
        let server = try LocalHTTPServer(response: "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/no\r\nContent-Length: 0\r\n\r\n")
        let port = try await server.start()
        defer { server.stop() }
        let result = await ReplayClient(timeout: 2).replay(exchange(), port: port)
        #expect(result.error == nil)
        #expect(result.status == 302)
    }

    @Test("Response size is bounded")
    func sizeLimit() async throws {
        let server = try LocalHTTPServer(response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        let port = try await server.start()
        defer { server.stop() }
        let result = await ReplayClient(timeout: 2, maximumResponseBytes: 4).replay(exchange(), port: port)
        #expect(result.error?.contains("limite") == true)
    }

    @Test("Path cannot override the chosen server")
    func rejectAuthority() async {
        let result = await ReplayClient().replay(exchange(), modifications: .init(path: "//example.invalid/test"))
        #expect(result.error != nil)
    }

    @Test("Header line injection is rejected before making a connection")
    func invalidHeader() async {
        let result = await ReplayClient().replay(exchange(), modifications: .init(setHeaders: ["X-Test": "x\r\nX-Other: y"]))
        #expect(result.error != nil)
    }
}

/// Fixture binds only to loopback and never talks to the installed helper.
private final class LocalHTTPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "pastoral.replay.test")
    private let lock = NSLock()
    private var received = Data()
    private var connections: [NWConnection] = [] // queue-confined
    private let response: Data?
    private let closeAfterSend: Bool
    var request: Data { lock.lock(); defer { lock.unlock() }; return received }

    init(response: String?, closeAfterSend: Bool = false) throws {
        self.response = response.map { Data($0.utf8) }
        self.closeAfterSend = closeAfterSend
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: params)
    }

    func start() async throws -> UInt16 {
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { conn.cancel(); return }
            self.connections.append(conn)
            conn.start(queue: self.queue)
            self.read(conn, accumulated: Data())
        }
        return try await withCheckedThrowingContinuation { cont in
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.listener.stateUpdateHandler = nil
                    cont.resume(returning: self.listener.port!.rawValue)
                case .failed(let error):
                    self.listener.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    private func read(_ conn: NWConnection, accumulated: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self else { return }
            var all = accumulated
            if let data { all.append(data) }
            guard let end = HTTPRequestParser.findHeaderEnd(in: all),
                  let parsed = HTTPRequestParser.parse(all) else {
                if !done && error == nil { self.read(conn, accumulated: all) }
                return
            }
            let length = Int(parsed.headers.first { $0.key.lowercased() == "content-length" }?.value ?? "0") ?? 0
            if all.count < end + 4 + length {
                if !done && error == nil { self.read(conn, accumulated: all) }
                return
            }
            self.lock.lock(); self.received = all; self.lock.unlock()
            if let response = self.response {
                conn.send(content: response, completion: .contentProcessed { _ in
                    if self.closeAfterSend { conn.cancel() }
                })
            }
        }
    }

    func stop() {
        queue.sync {
            listener.cancel()
            connections.forEach { $0.cancel() }
            connections.removeAll()
        }
    }
}

import Foundation
import PastoralCore

/// One explicit HTTP request. Uses system certificate validation and an
/// isolated session without shared cookies, credentials or cache.
actor ReplayClient {
    struct ReplayResult: Sendable {
        /// Logical HTTP/1.1 representation; URLSession may normalize headers.
        let requestBytes: Data
        let status: Int?
        let responseHeaders: [String: String]
        let responseBody: Data?
        let error: String?
    }

    private let timeout: TimeInterval
    private let maximumResponseBytes: Int

    init(timeout: TimeInterval = 15, maximumResponseBytes: Int = 1_000_000) {
        self.timeout = max(0.1, timeout)
        self.maximumResponseBytes = max(1, maximumResponseBytes)
    }

    func replay(_ exchange: CapturedExchange,
                modifications: ReplayBuilder.Modifications = .init(),
                host: String? = nil,
                port: UInt16? = nil,
                useTLS: Bool? = nil) async -> ReplayResult {
        let tls = useTLS ?? exchange.isTLS
        let targetHost = host ?? exchange.host
        let targetPort = port ?? (tls ? 443 : 80)
        let method = (modifications.method ?? exchange.method).uppercased()
        let path = modifications.path ?? exchange.path
        let headers = modifications.setHeaders.merging(exchange.requestHeaders) { explicit, _ in explicit }
        guard !(modifications.host ?? "").contains("\r"), !(modifications.host ?? "").contains("\n"),
              !targetHost.isEmpty, targetPort != 0,
              !method.isEmpty, method.utf8.allSatisfy({ (65...90).contains($0) }),
              path.hasPrefix("/"), !path.contains("\r"), !path.contains("\n"),
              headers.allSatisfy({ key, value in
                  !key.isEmpty && !key.contains(":") && !key.contains("\r") && !key.contains("\n") &&
                  !value.contains("\r") && !value.contains("\n")
              }),
              let raw = ReplayBuilder.buildRequest(from: exchange, modifications: modifications),
              let parsed = HTTPRequestParser.parse(raw) else {
            return failure("Requisição inválida.")
        }
        // Parse path/query separately so a supplied path cannot change the host.
        var components = URLComponents()
        components.scheme = tls ? "https" : "http"
        components.host = targetHost
        components.port = Int(targetPort)
        guard let origin = components.url,
              let url = URL(string: path, relativeTo: origin)?.absoluteURL,
              url.host == origin.host, url.port == origin.port, url.scheme == origin.scheme else {
            return failure("Destino inválido.", request: raw)
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = parsed.body
        request.timeoutInterval = timeout
        for (key, value) in parsed.headers {
            // The transport computes framing and connection headers itself.
            if ["content-length", "transfer-encoding", "connection", "expect"].contains(key.lowercased()) { continue }
            request.setValue(value, forHTTPHeaderField: key)
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.httpShouldSetCookies = false
        let session = URLSession(configuration: config, delegate: ReplayRedirectPolicy(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let response = response as? HTTPURLResponse else {
                return failure("Resposta HTTP inválida.", request: raw)
            }
            var body = Data()
            for try await byte in bytes {
                try Task.checkCancellation()
                guard body.count < maximumResponseBytes else {
                    return failure("Resposta excede o limite de \(maximumResponseBytes) bytes.", request: raw)
                }
                body.append(byte)
            }
            var responseHeaders: [String: String] = [:]
            for (key, value) in response.allHeaderFields {
                responseHeaders[String(describing: key)] = String(describing: value)
            }
            return ReplayResult(requestBytes: raw, status: response.statusCode,
                                responseHeaders: responseHeaders, responseBody: body, error: nil)
        } catch {
            return failure("Requisição interrompida: \(error.localizedDescription)", request: raw)
        }
    }

    private func failure(_ message: String, request: Data = Data()) -> ReplayResult {
        ReplayResult(requestBytes: request, status: nil, responseHeaders: [:], responseBody: nil, error: message)
    }
}

/// Do not resend captured headers or credentials to a redirect destination.
private final class ReplayRedirectPolicy: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

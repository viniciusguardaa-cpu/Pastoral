import Foundation
import CryptoKit

// MARK: - RTSP authentication (Basic + Digest, pure logic, testable)
//
// Most IP cameras answer DESCRIBE with `401 Unauthorized` and a
// `WWW-Authenticate` challenge. This module parses the challenge and
// builds the `Authorization` header for Basic and Digest (RFC 2617,
// MD5 — qop=auth and no-qop). MD5 covers the vast majority of cameras;
// SHA-256/qop=auth-int are rare and unsupported.
//
// The client is expected to keep the parsed challenge, a cnonce, and a
// nonce-count that increments per authenticated request.

/// A parsed WWW-Authenticate challenge.
public struct RTSPAuthChallenge: Equatable, Sendable {
    public enum Scheme: String, Sendable {
        case basic
        case digest
    }

    public let scheme: Scheme
    public let realm: String
    public let nonce: String?      // digest only
    public let qop: String?        // e.g. "auth" or "auth,auth-int"
    public let opaque: String?
    public let algorithm: String   // "MD5" when absent

    public init(scheme: Scheme, realm: String, nonce: String?,
                qop: String?, opaque: String?, algorithm: String) {
        self.scheme = scheme
        self.realm = realm
        self.nonce = nonce
        self.qop = qop
        self.opaque = opaque
        self.algorithm = algorithm
    }
}

public enum RTSPAuth {

    // MARK: - Challenge parsing

    /// Parse a WWW-Authenticate header value into a challenge.
    /// Returns nil for unsupported schemes.
    public static func parseChallenge(_ header: String) -> RTSPAuthChallenge? {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        let lower = trimmed.lowercased()

        let scheme: RTSPAuthChallenge.Scheme
        let rest: String
        if lower.hasPrefix("digest ") {
            scheme = .digest
            rest = String(trimmed.dropFirst(7))
        } else if lower == "digest" {
            scheme = .digest
            rest = ""
        } else if lower.hasPrefix("basic ") {
            scheme = .basic
            rest = String(trimmed.dropFirst(6))
        } else if lower == "basic" {
            scheme = .basic
            rest = ""
        } else {
            return nil
        }

        let params = parseParams(rest)
        let realm = params["realm"] ?? ""
        if scheme == .basic {
            return RTSPAuthChallenge(scheme: .basic, realm: realm,
                                     nonce: nil, qop: nil,
                                     opaque: nil, algorithm: "MD5")
        }
        guard let nonce = params["nonce"], !nonce.isEmpty else { return nil }
        return RTSPAuthChallenge(scheme: .digest, realm: realm, nonce: nonce,
                                 qop: params["qop"], opaque: params["opaque"],
                                 algorithm: params["algorithm"] ?? "MD5")
    }

    /// Split "k=v, k2=\"v2\"" into a lowercase-keyed dict. Handles quoted
    /// values containing commas or '='.
    private static func parseParams(_ s: String) -> [String: String] {
        var out: [String: String] = [:]
        var current = ""
        var inQuotes = false
        func flush() {
            guard let eq = current.firstIndex(of: "=") else { current = ""; return }
            let key = current[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            var val = current[current.index(after: eq)...]
                .trimmingCharacters(in: .whitespaces)
            if val.count >= 2, val.hasPrefix("\""), val.hasSuffix("\"") {
                val = String(val.dropFirst().dropLast())
            }
            if !key.isEmpty { out[key] = val }
            current = ""
        }
        for ch in s {
            if ch == "\"" {
                inQuotes.toggle()
                current.append(ch)
            } else if ch == ",", !inQuotes {
                flush()
            } else {
                current.append(ch)
            }
        }
        flush()
        return out
    }

    // MARK: - Authorization header

    /// Build the Authorization header value for one RTSP request.
    /// - Parameters:
    ///   - method: RTSP method (DESCRIBE, SETUP, PLAY…)
    ///   - uri: the request URI exactly as sent on the request line
    ///   - nonceCount: request count for this nonce (1-based, hex-encoded)
    ///   - cnonce: client nonce, random per session
    public static func authorizationHeader(
        method: String, uri: String,
        challenge: RTSPAuthChallenge,
        username: String, password: String,
        nonceCount: Int = 1, cnonce: String = ""
    ) -> String {
        switch challenge.scheme {
        case .basic:
            let token = Data("\(username):\(password)".utf8).base64EncodedString()
            return "Basic \(token)"

        case .digest:
            let ha1 = md5Hex("\(username):\(challenge.realm):\(password)")
            let ha2 = md5Hex("\(method):\(uri)")
            let nonce = challenge.nonce ?? ""
            var fields = [
                "username=\"\(username)\"",
                "realm=\"\(challenge.realm)\"",
                "nonce=\"\(nonce)\"",
                "uri=\"\(uri)\""
            ]
            if let opaque = challenge.opaque {
                fields.append("opaque=\"\(opaque)\"")
            }
            // Pick "auth" when the server lists several qop options.
            if let qopRaw = challenge.qop {
                let options = qopRaw.split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                let qop = options.contains("auth") ? "auth" : options.first ?? "auth"
                let nc = String(format: "%08x", nonceCount)
                let response = md5Hex("\(ha1):\(nonce):\(nc):\(cnonce):\(qop):\(ha2)")
                fields.append("response=\"\(response)\"")
                fields.append("qop=\(qop)")
                fields.append("nc=\(nc)")
                fields.append("cnonce=\"\(cnonce)\"")
            } else {
                let response = md5Hex("\(ha1):\(nonce):\(ha2)")
                fields.append("response=\"\(response)\"")
            }
            return "Digest " + fields.joined(separator: ", ")
        }
    }

    // MARK: - MD5

    private static func md5Hex(_ s: String) -> String {
        Insecure.MD5.hash(data: Data(s.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

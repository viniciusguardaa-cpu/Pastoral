import Foundation
import CryptoKit

/// Parsed view of a TLS ClientHello record — enough for diagnostics
/// (which TLS version/ciphers/extensions the client offered) and for
/// fingerprint mirroring on the origin-facing connection.
///
/// JA3 (https://github.com/salesforce/ja3): MD5 of
/// `version,ciphers,extensions,groups,ec_point_formats` with GREASE
/// values stripped. Two clients with the same JA3 almost certainly share
/// the same TLS stack — a cheap way to tell "Safari" from "OkHttp app".
public struct ClientHelloInfo: Sendable, Equatable {
    /// `client_version` field in the handshake (0x0301..0x0304).
    public var recordVersion: UInt16 = 0
    /// Versions from supported_versions ext (43); empty if absent.
    public var supportedVersions: [UInt16] = []
    public var cipherSuites: [UInt16] = []
    public var extensions: [UInt16] = []
    public var sni: String?
    public var alpn: [String] = []
    public var supportedGroups: [UInt16] = []
    public var ecPointFormats: [UInt8] = []
    public var signatureAlgorithms: [UInt16] = []

    /// Highest TLS version the client offers (supported_versions wins
    /// over the legacy client_version field).
    public var maxVersion: UInt16 {
        supportedVersions.max() ?? recordVersion
    }
    public var minVersion: UInt16 {
        supportedVersions.min() ?? recordVersion
    }

    public var offersH2: Bool { alpn.contains("h2") }
    public var offersH3: Bool { alpn.contains("h3") }

    /// JA3 string: decimal lists joined by "-", GREASE removed.
    public var ja3String: String {
        func list(_ v: [UInt16]) -> String {
            v.filter { !Self.isGREASE($0) }.map(String.init).joined(separator: "-")
        }
        return [
            String(recordVersion), list(cipherSuites), list(extensions),
            list(supportedGroups),
            ecPointFormats.map(String.init).joined(separator: "-")
        ].joined(separator: ",")
    }

    /// JA3 fingerprint = MD5(ja3String), hex.
    public var ja3: String {
        Insecure.MD5.hash(data: Data(ja3String.utf8))
            .map { String(format: "%02x", $0) }.joined()
    }

    /// Short human summary for logs/UI.
    public var summary: String {
        "TLS 0x\(String(maxVersion, radix: 16)) ciphers=\(cipherSuites.count) "
            + "ext=\(extensions.count) alpn=[\(alpn.joined(separator: ","))] ja3=\(ja3.prefix(8))"
    }

    /// GREASE values (RFC 8701): 0x?a?a — ignore in fingerprints.
    public static func isGREASE(_ v: UInt16) -> Bool {
        v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
    }

    /// Parse a ClientHello out of a TLS record. Returns nil when the
    /// bytes are not a ClientHello or are truncated.
    public static func parse(_ data: Data) -> ClientHelloInfo? {
        guard data.count >= 5, data[0] == 0x16 else { return nil }
        var info = ClientHelloInfo()
        info.recordVersion = UInt16(data[1]) << 8 | UInt16(data[2])

        var pos = 5
        guard data.count > pos + 4, data[pos] == 0x01 else { return nil }
        // handshake: type(1) length(3) version(2) random(32)
        pos += 4
        guard pos + 34 <= data.count else { return nil }
        pos += 34

        // session_id
        guard pos < data.count else { return nil }
        pos += 1 + Int(data[pos])

        // cipher_suites
        guard pos + 2 <= data.count else { return nil }
        let cipherLen = Int(data[pos]) << 8 | Int(data[pos + 1])
        pos += 2
        guard pos + cipherLen <= data.count else { return nil }
        for i in stride(from: pos, to: pos + cipherLen - 1, by: 2) {
            info.cipherSuites.append(UInt16(data[i]) << 8 | UInt16(data[i + 1]))
        }
        pos += cipherLen

        // compression_methods
        guard pos < data.count else { return info }
        pos += 1 + Int(data[pos])

        // extensions
        guard pos + 2 <= data.count else { return info }
        let extLen = Int(data[pos]) << 8 | Int(data[pos + 1])
        pos += 2
        let extEnd = min(pos + extLen, data.count)

        while pos + 4 <= extEnd {
            let type = UInt16(data[pos]) << 8 | UInt16(data[pos + 1])
            let len = Int(data[pos + 2]) << 8 | Int(data[pos + 3])
            pos += 4
            guard pos + len <= extEnd else { break }
            let body = data.subdata(in: pos..<(pos + len))
            info.extensions.append(type)

            switch type {
            case 0x0000: // server_name
                if body.count >= 5, body[2] == 0x00 {
                    let nl = Int(body[3]) << 8 | Int(body[4])
                    if 5 + nl <= body.count {
                        info.sni = String(data: body.subdata(in: 5..<(5 + nl)),
                                          encoding: .utf8)
                    }
                }
            case 0x0010: // ALPN: list_len(2) then (len(1) proto)*
                var p = 2
                while p < body.count {
                    let l = Int(body[p]); p += 1
                    guard p + l <= body.count else { break }
                    if let s = String(data: body.subdata(in: p..<(p + l)),
                                      encoding: .utf8) {
                        info.alpn.append(s)
                    }
                    p += l
                }
            case 0x002b: // supported_versions: len(1) versions*
                var p = 1
                while p + 1 < body.count {
                    info.supportedVersions.append(
                        UInt16(body[p]) << 8 | UInt16(body[p + 1]))
                    p += 2
                }
            case 0x000a: // supported_groups: len(2) groups*
                var p = 2
                while p + 1 < body.count {
                    info.supportedGroups.append(
                        UInt16(body[p]) << 8 | UInt16(body[p + 1]))
                    p += 2
                }
            case 0x000b: // ec_point_formats: len(1) formats*
                var p = 1
                while p < body.count {
                    info.ecPointFormats.append(body[p]); p += 1
                }
            case 0x000d: // signature_algorithms: len(2) pairs*
                var p = 2
                while p + 1 < body.count {
                    info.signatureAlgorithms.append(
                        UInt16(body[p]) << 8 | UInt16(body[p + 1]))
                    p += 2
                }
            default:
                break
            }
            pos += len
        }
        return info
    }
}

/// Minimal TLS Alert record parser — used to classify handshake failures
/// (unknown_ca → CA not trusted; close without alert → likely pinning).
public struct TLSAlert: Sendable, Equatable {
    public enum Level: UInt8, Sendable { case warning = 1, fatal = 2 }
    public var level: Level = .fatal
    public var code: UInt8 = 0

    public var descriptionName: String {
        switch code {
        case 0: return "close_notify"
        case 40: return "handshake_failure"
        case 42: return "bad_certificate"
        case 46: return "certificate_unknown"
        case 48: return "unknown_ca"
        case 49: return "access_denied"
        case 70: return "protocol_version"
        case 80: return "internal_error"
        case 90: return "user_canceled"
        case 109: return "missing_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 115: return "unknown_psk_identity"
        case 116: return "certificate_required"
        default: return "alert_\(code)"
        }
    }

    /// First alert found in a TLS record stream, if any.
    public static func parse(_ data: Data) -> TLSAlert? {
        var pos = 0
        while pos + 5 <= data.count {
            let type = data[pos]
            let len = Int(data[pos + 3]) << 8 | Int(data[pos + 4])
            guard pos + 5 + len <= data.count else { return nil }
            if type == 0x15, len >= 2 {  // alert record
                return TLSAlert(
                    level: Level(rawValue: data[pos + 5]) ?? .fatal,
                    code: data[pos + 6])
            }
            pos += 5 + len
        }
        return nil
    }
}

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - QUIC Initial packet parser (passive SNI extraction)
//
// QUIC (RFC 9000) carries HTTP/3 over UDP/443. Unlike TCP+TLS, QUIC
// cannot be redirected by a TCP proxy — the rdr rules only catch TCP.
// The only way to see HTTP/3 traffic is passively, via pcap. The QUIC
// Initial packet is encrypted, but the keys are derived deterministically
// from the Destination Connection ID using a well-known salt, so we CAN
// decrypt it and extract the TLS ClientHello (which carries the SNI).
//
// This is pure logic over raw bytes — fully testable without sockets.
// The caller feeds a UDP/443 payload captured by pcap; we return the SNI
// (and ALPN, if present) from the embedded ClientHello.

/// Result of parsing a QUIC Initial packet.
public struct QUICClientHello: Equatable, Sendable {
    /// The SNI (server_name) from the TLS ClientHello, if present.
    public let sni: String?
    /// The ALPN protocol list from the ClientHello, if present
    /// (e.g. ["h3", "h3-29", "h2"]).
    public let alpn: [String]
    /// The QUIC version from the long header.
    public let version: UInt32
}

/// Parse QUIC Initial packets to extract the SNI/ALPN from the embedded
/// TLS ClientHello. QUIC v1 (0x00000001) and the draft versions use
/// version-specific initial salts; we try the known salts.
public enum QUICParser {

    /// QUIC v1 initial salt (RFC 9000).
    static let v1Salt: [UInt8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc5, 0x90, 0x9, 0x4d, 0x4f, 0x77, 0xfe
    ]
    /// QUIC v2 (RFC 9369) initial salt.
    static let v2Salt: [UInt8] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
        0x81, 0x93, 0x81, 0xa5, 0x0c, 0x3e, 0x90, 0x60, 0x9, 0xc0, 0xbf, 0x0f
    ]

    /// Parse a UDP payload as a QUIC Initial packet and extract the SNI.
    /// Returns nil if the packet is not a QUIC Initial, is too short, or
    /// decryption/parsing fails (e.g. unknown version, GREASE, coalesced
    /// packets we don't handle).
    public static func parseInitial(_ data: [UInt8]) -> QUICClientHello? {
        guard let header = parseLongHeader(data) else { return nil }
        guard header.packetType == .initial else { return nil }

        // Pick the salt based on version.
        let salt: [UInt8]
        if header.version == 0x00000001 {
            salt = v1Salt
        } else if header.version == 0x6b3343cf {
            // QUIC v2 version number.
            salt = v2Salt
        } else {
            // Draft versions and unknowns: try v1 salt as a best effort.
            salt = v1Salt
        }

        // Derive the client Initial keys from the DCID.
        guard let keys = deriveInitialKeys(dcid: header.dcid, salt: salt) else {
            return nil
        }

        // Decrypt the Initial packet payload.
        guard let plaintext = decryptInitial(
            packet: data, header: header, keys: keys
        ) else { return nil }

        // Find the CRYPTO frame (type 0x00) and extract the ClientHello.
        guard let cryptoData = extractCryptoFrame(from: plaintext) else {
            return nil
        }

        // Parse the TLS ClientHello inside the CRYPTO frame.
        return parseClientHello(cryptoData, version: header.version)
    }

    // MARK: - Long header

    struct LongHeader {
        let packetType: PacketType
        let version: UInt32
        let dcid: [UInt8]
        let scid: [UInt8]
        /// Byte offset where the token-length field begins.
        let tokenOffset: Int
        /// Offset of the first byte of the full QUIC packet (always 0).
        let packetStart: Int
    }

    enum PacketType: Int {
        case initial = 0
        case zeroRTT = 1
        case handshake = 2
        case retry = 3
    }

    private static func parseLongHeader(_ data: [UInt8]) -> LongHeader? {
        guard data.count >= 6 else { return nil }
        // First byte: bit 7 must be 1 (long header).
        guard (data[0] & 0x80) != 0 else { return nil }
        // Packet type is bits 4-5 (0x30 mask), shifted by 4.
        let typeBits = Int((data[0] & 0x30) >> 4)
        guard let ptype = PacketType(rawValue: typeBits) else { return nil }
        // Version (bytes 1-4).
        let version = (UInt32(data[1]) << 24) | (UInt32(data[2]) << 16)
            | (UInt32(data[3]) << 8) | UInt32(data[4])
        guard version != 0 else { return nil }  // version 0 = short header

        var pos = 5
        // DCID.
        guard pos < data.count else { return nil }
        let dcidLen = Int(data[pos]); pos += 1
        guard pos + dcidLen <= data.count, dcidLen > 0 else { return nil }
        let dcid = Array(data[pos..<(pos + dcidLen)]); pos += dcidLen
        // SCID.
        guard pos < data.count else { return nil }
        let scidLen = Int(data[pos]); pos += 1
        guard pos + scidLen <= data.count else { return nil }
        let scid = Array(data[pos..<(pos + scidLen)]); pos += scidLen

        // For Initial, there's a token field next. We record the token
        // offset so the caller can skip it; we parse it in decryptInitial.
        // (The packet-number length lives in the protected first byte —
        // it can only be read after removing header protection.)
        return LongHeader(
            packetType: ptype, version: version,
            dcid: dcid, scid: scid,
            tokenOffset: pos, packetStart: 0
        )
    }

    // MARK: - Key derivation (HKDF-Extract / HKDF-Expand-Label)

    struct InitialKeys {
        let key: SymmetricKey   // 16 bytes (AES-128)
        let iv: [UInt8]          // 12 bytes
        let hp: SymmetricKey     // 16 bytes (header protection)
    }

    private static func deriveInitialKeys(dcid: [UInt8], salt: [UInt8]) -> InitialKeys? {
        // initial_secret = HKDF-Extract(salt, dcid)
        // CryptoKit: extract(inputKeyMaterial: SymmetricKey, salt: Data)
        //   -> HashedAuthenticationCode<SHA256>; convert to SymmetricKey.
        let initialHMAC = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: Data(dcid)),
            salt: Data(salt)
        )
        let initialBytes: [UInt8] = initialHMAC.withUnsafeBytes { buf in
            var arr = [UInt8](repeating: 0, count: buf.count)
            arr.withUnsafeMutableBufferPointer { dest in
                buf.copyBytes(to: dest)
            }
            return arr
        }
        let initialSecret = SymmetricKey(data: Data(initialBytes))
        // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        guard let clientSecret = expandLabel(
            secret: initialSecret, label: "client in", context: [], length: 32
        ) else { return nil }

        let clientSecretKey = SymmetricKey(data: Data(clientSecret))
        let clientKeyData = expandLabel(
            secret: clientSecretKey, label: "quic key",
            context: [], length: 16
        ) ?? []
        let clientIV = expandLabel(
            secret: clientSecretKey, label: "quic iv",
            context: [], length: 12
        ) ?? []
        let clientHP = expandLabel(
            secret: clientSecretKey, label: "quic hp",
            context: [], length: 16
        ) ?? []

        return InitialKeys(
            key: SymmetricKey(data: Data(clientKeyData)),
            iv: clientIV,
            hp: SymmetricKey(data: Data(clientHP))
        )
    }

    /// HKDF-Expand-Label as defined in RFC 8446 §7.1 (used by QUIC).
    /// Label is prefixed with "tls13 ". Returns the expanded key material
    /// as raw bytes.
    private static func expandLabel(secret: SymmetricKey, label: String,
                                     context: [UInt8], length: Int) -> [UInt8]? {
        let fullLabel = "tls13 " + label
        var info: [UInt8] = []
        info.append(UInt8(length >> 8))
        info.append(UInt8(length & 0xff))
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(UInt8(context.count))
        info.append(contentsOf: context)
        // CryptoKit: expand(pseudoRandomKey: SymmetricKey, info: Data,
        //                   outputByteCount: Int) -> SymmetricKey
        let expanded = HKDF<SHA256>.expand(
            pseudoRandomKey: secret, info: Data(info), outputByteCount: length
        )
        // Convert SymmetricKey -> [UInt8] via copyBytes (avoids the
        // [UInt8](hexString:) initializer collision in ARPFrame.swift).
        return expanded.withUnsafeBytes { buf in
            var arr = [UInt8](repeating: 0, count: buf.count)
            arr.withUnsafeMutableBufferPointer { dest in
                buf.copyBytes(to: dest)
            }
            return arr
        }
    }

    // MARK: - Decryption

    private static func decryptInitial(packet: [UInt8], header: LongHeader,
                                        keys: InitialKeys) -> [UInt8]? {
        // Skip the token field (Initial only).
        var pos = header.tokenOffset
        guard pos < packet.count else { return nil }
        // Token length is a varint.
        let (tokenLen, tokenLenBytes) = readVarint(packet, at: pos)
        pos += tokenLenBytes
        guard pos + Int(tokenLen) <= packet.count else { return nil }
        pos += Int(tokenLen)

        // Packet length (varint) — length of the rest of the packet
        // (packet number + encrypted payload).
        let (pktLen, pktLenBytes) = readVarint(packet, at: pos)
        pos += pktLenBytes
        let payloadEnd = pos + Int(pktLen)
        guard payloadEnd <= packet.count else { return nil }

        // The packet number is 1-4 bytes starting at pnStart, then the
        // ciphertext+tag. The header-protection sample is always 16 bytes
        // starting exactly 4 bytes after the start of the PN field
        // (RFC 9000 §5.4.2), regardless of the actual PN length.
        let pnStart = pos
        let sampleOffset = pnStart + 4
        guard sampleOffset + 16 <= payloadEnd else { return nil }
        let sample = Array(packet[sampleOffset..<(sampleOffset + 16)])

        // mask = AES-ECB(hp, sample)
        let mask = aesECB(key: keys.hp, block: sample)
        guard let mask else { return nil }

        // Remove header protection from the first byte: for long headers,
        // the low 4 bits are masked (RFC 9000 §5.4.1). Only then can we
        // read the real packet-number length.
        var firstByte = packet[0]
        firstByte ^= (mask[0] & 0x0f)
        let pnLength = Int(firstByte & 0x03) + 1

        // Reconstruct the unprotected header: first byte through the PN.
        var unprotectedHeader = Array(packet[0..<pnStart])
        unprotectedHeader[0] = firstByte
        // Unmask the packet number bytes.
        var pnBytes: [UInt8] = []
        guard pnStart + pnLength <= payloadEnd else { return nil }
        for i in 0..<pnLength {
            let b = packet[pnStart + i] ^ mask[1 + i]
            pnBytes.append(b)
            unprotectedHeader.append(b)
        }

        // The actual packet number (we don't strictly need it for SNI
        // extraction, but it's part of the AAD).
        // For Initial, the pn is truncated; we use the decoded value.

        // Ciphertext + tag start after the (still-encrypted) pn bytes.
        let ctStart = pnStart + pnLength
        guard ctStart < payloadEnd else { return nil }
        let ctEnd = payloadEnd
        let ciphertext = Array(packet[ctStart..<ctEnd])

        // AES-128-GCM decrypt. The nonce is iv XOR packet number (padded).
        var nonce = keys.iv
        // XOR the last pnLength bytes of the nonce with the pn bytes.
        for i in 0..<pnLength {
            nonce[12 - pnLength + i] ^= pnBytes[i]
        }

        // AAD = unprotected header (first byte through pn bytes).
        let aad = Data(unprotectedHeader)

        do {
            let sealed = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: Data(nonce)),
                ciphertext: Data(ciphertext.dropLast(16)),
                tag: Data(ciphertext.suffix(16))
            )
            let plaintext = try AES.GCM.open(sealed, using: keys.key,
                                             authenticating: aad)
            return [UInt8](plaintext)
        } catch {
            return nil
        }
    }

    /// AES-ECB encrypt a single 16-byte block (for header protection).
    private static func aesECB(key: SymmetricKey, block: [UInt8]) -> [UInt8]? {
        guard block.count == 16 else { return nil }
        // CryptoKit doesn't expose raw AES-ECB directly, but we can use
        // AES.GCM's underlying block cipher via a single-block "counter"
        // trick: AES-ECB(block) == AES-CTR with nonce=0, counter=0 applied
        // to the block. We use the counter mode with a zero nonce.
        // Actually CryptoKit has no public ECB. We implement AES-ECB via
        // the low-level AES._block if available; otherwise fall back to
        // a manual approach. CryptoKit exposes AES.GCM only.
        //
        // Workaround: AES-ECB(single block) = AES-ECB. We can compute it
        // by using AES-GCM with an all-zero nonce and a single-block
        // counter... but that gives CTR, not ECB.
        //
        // The cleanest path: use the CommonCrypto/CommonCrypto SPI via
        // CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECB, ...). We
        // bridge to C for this one call.
        return aesECBCommonCrypto(key: key, block: block)
    }

    // MARK: - CRYPTO frame extraction

    private static func extractCryptoFrame(from plaintext: [UInt8]) -> [UInt8]? {
        // QUIC frames: type (varint) + frame-specific fields.
        // CRYPTO frame type = 0x00. Fields: offset (varint) + length (varint)
        // + crypto data.
        var pos = 0
        while pos < plaintext.count {
            let (frameType, typeBytes) = readVarint(plaintext, at: pos)
            pos += typeBytes
            if frameType == 0x00 {
                // CRYPTO frame: offset (varint) + length (varint) + data.
                let (offset, offBytes) = readVarint(plaintext, at: pos)
                pos += offBytes
                _ = offset
                let (length, lenBytes) = readVarint(plaintext, at: pos)
                pos += lenBytes
                guard pos + Int(length) <= plaintext.count else { return nil }
                return Array(plaintext[pos..<(pos + Int(length))])
            }
            // Skip other frame types we don't care about. We'd need to
            // know their length to skip properly; for robustness, if we
            // hit a non-CRYPTO frame before finding one, bail.
            return nil
        }
        return nil
    }

    // MARK: - TLS ClientHello parsing (inside the CRYPTO frame)

    private static func parseClientHello(_ data: [UInt8], version: UInt32) -> QUICClientHello? {
        // TLS handshake: type(1) length(3) version(2) random(32) session_id...
        guard data.count >= 4, data[0] == 0x01 else { return nil }  // ClientHello
        var pos = 4 + 2 + 32  // skip type, length, version, random
        guard pos < data.count else { return nil }
        // Session ID (legacy_session_id).
        let sessionIdLen = Int(data[pos]); pos += 1 + sessionIdLen
        // Cipher suites.
        guard pos + 2 <= data.count else { return nil }
        let cipherLen = Int(data[pos]) << 8 | Int(data[pos + 1]); pos += 2 + cipherLen
        // Compression methods.
        guard pos < data.count else { return nil }
        let compLen = Int(data[pos]); pos += 1 + compLen
        // Extensions.
        guard pos + 2 <= data.count else { return nil }
        let extLen = Int(data[pos]) << 8 | Int(data[pos + 1]); pos += 2
        let extEnd = pos + extLen
        guard extEnd <= data.count else { return nil }

        var sni: String? = nil
        var alpn: [String] = []

        while pos + 4 <= extEnd {
            let extType = Int(data[pos]) << 8 | Int(data[pos + 1])
            let extDataLen = Int(data[pos + 2]) << 8 | Int(data[pos + 3])
            pos += 4
            guard pos + extDataLen <= extEnd else { break }
            let extData = Array(data[pos..<(pos + extDataLen)])
            pos += extDataLen

            if extType == 0x0000 {
                // server_name
                sni = parseSNIExtension(extData) ?? sni
            } else if extType == 0x0010 {
                // ALPN
                alpn = parseALPNExtension(extData)
            }
        }

        return QUICClientHello(sni: sni, alpn: alpn, version: version)
    }

    private static func parseSNIExtension(_ data: [UInt8]) -> String? {
        // server_name list: total_len(2) + entries.
        guard data.count >= 2 else { return nil }
        var pos = 2  // skip total list length
        while pos + 3 <= data.count {
            let nameType = data[pos]
            let nameLen = Int(data[pos + 1]) << 8 | Int(data[pos + 2])
            pos += 3
            guard pos + nameLen <= data.count else { return nil }
            if nameType == 0x00 {  // host_name
                return String(data: Data(data[pos..<(pos + nameLen)]), encoding: .utf8)
            }
            pos += nameLen
        }
        return nil
    }

    private static func parseALPNExtension(_ data: [UInt8]) -> [String] {
        // ALPN: list_len(2) + entries(name_len(1) + name).
        guard data.count >= 2 else { return [] }
        let listLen = Int(data[0]) << 8 | Int(data[1])
        var pos = 2
        let end = min(2 + listLen, data.count)
        var protocols: [String] = []
        while pos < end {
            let nameLen = Int(data[pos]); pos += 1
            guard pos + nameLen <= end else { break }
            if let name = String(data: Data(data[pos..<(pos + nameLen)]), encoding: .ascii) {
                protocols.append(name)
            }
            pos += nameLen
        }
        return protocols
    }

    // MARK: - QUIC varint (RFC 9000 §16)

    /// Read a QUIC variable-length integer at `offset`. Returns (value, bytes_consumed).
    private static func readVarint(_ data: [UInt8], at offset: Int) -> (UInt64, Int) {
        guard offset < data.count else { return (0, 0) }
        let first = data[offset]
        let lengthBits = Int(first >> 6)  // top 2 bits
        let length = 1 << lengthBits       // 1, 2, 4, or 8 bytes
        guard offset + length <= data.count else { return (0, 0) }
        var value: UInt64 = UInt64(first & 0x3f)
        for i in 1..<length {
            value = (value << 8) | UInt64(data[offset + i])
        }
        return (value, length)
    }
}

// MARK: - AES-ECB via CommonCrypto (header protection mask)
//
// CryptoKit doesn't expose raw AES-ECB. QUIC header protection needs a
// single-block AES-ECB encryption to compute the mask. We bridge to
// CommonCrypto's CCCrypt with kCCOptionECB for this one-block operation.

private func aesECBCommonCrypto(key: SymmetricKey, block: [UInt8]) -> [UInt8]? {
    guard block.count == 16 else { return nil }
    var keyBytes = [UInt8](repeating: 0, count: 32)
    let keyData = key.withUnsafeBytes { Data($0) }
    let kLen = min(keyData.count, 32)
    keyBytes.replaceSubrange(0..<kLen, with: [UInt8](keyData.prefix(kLen)))

    var out = [UInt8](repeating: 0, count: 16)
    var outLen = 0
    let status = keyBytes.withUnsafeBufferPointer { keyPtr in
        block.withUnsafeBufferPointer { blockPtr in
            out.withUnsafeMutableBufferPointer { outPtr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyPtr.baseAddress, kLen,
                    nil,
                    blockPtr.baseAddress, 16,
                    outPtr.baseAddress, 16,
                    &outLen
                )
            }
        }
    }
    return status == kCCSuccess ? out : nil
}

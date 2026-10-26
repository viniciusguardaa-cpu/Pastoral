import Testing
import Foundation
import CryptoKit
import CommonCrypto
@testable import PastoralCore

/// Unit tests for the QUIC Initial packet parser. We construct a real QUIC
/// Initial packet (encrypt a TLS ClientHello with a known SNI/ALPN using the
/// QUIC v1 Initial salt) and verify that `QUICParser.parseInitial` decrypts
/// it and extracts the SNI/ALPN.
@Suite("QUIC Initial parser")
struct QUICParserTests {

    // MARK: - Varint

    @Test("QUIC varint: 1-byte encoding")
    func varint1Byte() {
        // 0x25 = 0b00_100101 → length=1 byte, value=0x25=37
        let (val, len) = readVarintTest([0x25], at: 0)
        #expect(val == 37)
        #expect(len == 1)
    }

    @Test("QUIC varint: 2-byte encoding")
    func varint2Byte() {
        // 0x7bbd = 0b01_111011_10111101 → length=2, value=0x3bbd=15293
        let (val, len) = readVarintTest([0x7b, 0xbd], at: 0)
        #expect(val == 15293)
        #expect(len == 2)
    }

    @Test("QUIC varint: 4-byte encoding")
    func varint4Byte() {
        // 0x9d7f3e7d → length=4, value=0x1d7f3e7d=494878333
        let (val, len) = readVarintTest([0x9d, 0x7f, 0x3e, 0x7d], at: 0)
        #expect(val == 494878333)
        #expect(len == 4)
    }

    @Test("QUIC varint: 8-byte encoding")
    func varint8Byte() {
        // 8-byte varint: first byte 0xc0 (top-2-bits = 11) + 7 payload bytes.
        // value = (0x00 << 56) | 0x12345678 = 305419896
        let bytes: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]
        let (val, len) = readVarintTest(bytes, at: 0)
        #expect(val == 0x12345678)
        #expect(len == 8)
    }

    /// Access the private readVarint via a test helper. Since readVarint is
    /// private, we reimplement the same logic here for unit testing.
    private func readVarintTest(_ data: [UInt8], at offset: Int) -> (UInt64, Int) {
        guard offset < data.count else { return (0, 0) }
        let first = data[offset]
        let lengthBits = Int(first >> 6)
        let length = 1 << lengthBits
        guard offset + length <= data.count else { return (0, 0) }
        var value: UInt64 = UInt64(first & 0x3f)
        for i in 1..<length {
            value = (value << 8) | UInt64(data[offset + i])
        }
        return (value, length)
    }

    // MARK: - Full round-trip: construct + parse

    @Test("Parse QUIC Initial extracts SNI and ALPN")
    func parseInitialSNI() throws {
        let dcid: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let sni = "example.com"
        let alpn = ["h3", "h2"]

        let packet = try constructInitialPacket(
            dcid: dcid, sni: sni, alpn: alpn, packetNumber: 0
        )
        let result = QUICParser.parseInitial(packet)

        #expect(result != nil, "parseInitial should succeed on a valid Initial packet")
        #expect(result?.sni == sni)
        #expect(result?.alpn == alpn)
        #expect(result?.version == 0x00000001)
    }

    @Test("Parse QUIC Initial with empty ALPN")
    func parseInitialNoALPN() throws {
        let dcid: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]
        let sni = "cloudflare.com"

        let packet = try constructInitialPacket(
            dcid: dcid, sni: sni, alpn: [], packetNumber: 42
        )
        let result = QUICParser.parseInitial(packet)

        #expect(result != nil)
        #expect(result?.sni == sni)
        #expect(result?.alpn.isEmpty == true)
    }

    @Test("Parse non-Initial packet returns nil")
    func parseNonInitial() {
        // A short header (bit 7 = 0) should fail.
        let short: [UInt8] = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05]
        #expect(QUICParser.parseInitial(short) == nil)
    }

    @Test("Parse too-short packet returns nil")
    func parseTooShort() {
        #expect(QUICParser.parseInitial([0xc0, 0x00]) == nil)
        #expect(QUICParser.parseInitial([]) == nil)
    }

    // MARK: - QUIC Initial packet construction (test helper)

    /// Construct a QUIC v1 Initial packet containing a TLS ClientHello with
    /// the given SNI and ALPN. This is the inverse of parseInitial — we
    /// derive the same keys from the DCID and encrypt.
    private func constructInitialPacket(dcid: [UInt8], sni: String,
                                          alpn: [String], packetNumber: Int) throws -> [UInt8] {
        // 1. Build the TLS ClientHello.
        let clientHello = buildClientHello(sni: sni, alpn: alpn)

        // 2. Wrap in a CRYPTO frame (type 0x00, offset 0, length).
        var cryptoFrame: [UInt8] = [0x00]  // CRYPTO frame type
        cryptoFrame.append(0x00)  // offset = 0 (1-byte varint)
        cryptoFrame.append(contentsOf: encodeVarint(UInt64(clientHello.count)))
        cryptoFrame.append(contentsOf: clientHello)

        // 3. Derive Initial keys from DCID (same as parseInitial).
        let salt = QUICParser.v1Salt
        let initialHMAC = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: Data(dcid)),
            salt: Data(salt)
        )
        let initialSecret = initialHMAC.withUnsafeBytes { buf in
            var arr = [UInt8](repeating: 0, count: buf.count)
            arr.withUnsafeMutableBufferPointer { dest in buf.copyBytes(to: dest) }
            return SymmetricKey(data: Data(arr))
        }
        let clientSecret = expandLabelTest(secret: initialSecret, label: "client in", length: 32)
        let clientSecretKey = SymmetricKey(data: Data(clientSecret))
        let key = SymmetricKey(data: Data(expandLabelTest(secret: clientSecretKey, label: "quic key", length: 16)))
        let iv = expandLabelTest(secret: clientSecretKey, label: "quic iv", length: 12)
        let hp = SymmetricKey(data: Data(expandLabelTest(secret: clientSecretKey, label: "quic hp", length: 16)))

        // 4. Build the header (before packet number).
        let pnLen = 1  // 1-byte packet number
        var header: [UInt8] = []
        // First byte: 1(long) 1(form) 00(initial type) 00(reserved) 00(pn_len=1)
        // = 0b11000000 = 0xC0
        header.append(0xC0 | UInt8(pnLen - 1))
        // Version: QUIC v1 = 0x00000001
        header += [0x00, 0x00, 0x00, 0x01]
        // DCID
        header.append(UInt8(dcid.count))
        header += dcid
        // SCID (same as DCID for simplicity)
        header.append(UInt8(dcid.count))
        header += dcid
        // Token (empty): token length = 0 (1-byte varint)
        header.append(0x00)

        // 5. Encrypt the payload (CRYPTO frame) with AES-128-GCM.
        // Nonce = iv XOR packet_number (padded to 12 bytes).
        var nonce = iv
        let pnBytes: [UInt8] = [UInt8(packetNumber & 0xff)]
        for i in 0..<pnBytes.count {
            nonce[12 - pnBytes.count + i] ^= pnBytes[i]
        }

        // The ciphertext length is pnLen + cryptoFrame.count + 16 (tag).
        // We need the packet length field BEFORE sealing, because it's
        // part of the AAD. ciphertext length = plaintext + 16-byte tag.
        let pktLen = pnLen + cryptoFrame.count + 16
        let pktLenBytes = encodeVarint(UInt64(pktLen))

        // AAD = unprotected header through the PN bytes, i.e.
        // first-byte..token + packet-length field + pn bytes.
        var aad = header
        aad += pktLenBytes
        aad += pnBytes

        let sealed = try AES.GCM.seal(
            Data(cryptoFrame),
            using: key,
            nonce: AES.GCM.Nonce(data: Data(nonce)),
            authenticating: Data(aad)
        )
        // sealed.ciphertext + sealed.tag (16 bytes)
        let ciphertext = [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)

        // 6. Apply header protection to the first byte and packet number.
        // Sample = 16 bytes starting exactly 4 bytes after the start of
        // the packet-number field (RFC 9000 §5.4.2). The PN field begins
        // right after the packet-length field; with pnLen=1, ciphertext
        // starts at offset 1 within the packet payload, so the sample is
        // ciphertext[4-pnLen ..< 4-pnLen+16].
        let sampleStart = 4 - pnLen
        let sample = Array(ciphertext[sampleStart..<(sampleStart + 16)])
        let mask = aesECBEncrypt(key: hp, block: sample)

        // Build the final packet.
        var packet = header
        packet += pktLenBytes  // packet length field
        // Protected first byte and PN.
        var firstByte = packet[0]
        firstByte ^= (mask[0] & 0x0f)
        packet[0] = firstByte
        // Protected PN.
        var protectedPN: [UInt8] = []
        for i in 0..<pnLen {
            protectedPN.append(pnBytes[i] ^ mask[1 + i])
        }
        packet += protectedPN
        packet += ciphertext

        return packet
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1).
    private func expandLabelTest(secret: SymmetricKey, label: String, length: Int) -> [UInt8] {
        let fullLabel = "tls13 " + label
        var info: [UInt8] = []
        info.append(UInt8(length >> 8))
        info.append(UInt8(length & 0xff))
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(0x00)  // empty context
        let expanded = HKDF<SHA256>.expand(
            pseudoRandomKey: secret, info: Data(info), outputByteCount: length
        )
        return expanded.withUnsafeBytes { buf in
            var arr = [UInt8](repeating: 0, count: buf.count)
            arr.withUnsafeMutableBufferPointer { dest in buf.copyBytes(to: dest) }
            return arr
        }
    }

    /// AES-ECB single-block encrypt (for header protection mask).
    private func aesECBEncrypt(key: SymmetricKey, block: [UInt8]) -> [UInt8] {
        var keyBytes = [UInt8](repeating: 0, count: 32)
        let keyData = key.withUnsafeBytes { Data($0) }
        let kLen = min(keyData.count, 32)
        keyBytes.replaceSubrange(0..<kLen, with: [UInt8](keyData.prefix(kLen)))
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        _ = keyBytes.withUnsafeBufferPointer { keyPtr in
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
        return out
    }

    /// Encode a QUIC variable-length integer.
    private func encodeVarint(_ value: UInt64) -> [UInt8] {
        if value < 64 {
            return [UInt8(value)]
        } else if value < 16384 {
            return [UInt8(0x40 | UInt8(value >> 8)), UInt8(value & 0xff)]
        } else if value < 1073741824 {
            return [
                UInt8(0x80 | UInt8(value >> 24)),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ]
        } else {
            var bytes: [UInt8] = [UInt8(0xc0 | UInt8(value >> 56))]
            for i in stride(from: 48, through: 0, by: -8) {
                bytes.append(UInt8((value >> i) & 0xff))
            }
            return bytes
        }
    }

    /// Build a minimal TLS ClientHello with SNI and ALPN extensions.
    private func buildClientHello(sni: String, alpn: [String]) -> [UInt8] {
        // Extensions.
        var extensions: [UInt8] = []
        // SNI extension (type 0x0000).
        if !sni.isEmpty {
            let sniBytes = Array(sni.utf8)
            let nameEntry = [UInt8(0x00)] +  // name_type: host_name
                [UInt8(sniBytes.count >> 8), UInt8(sniBytes.count & 0xff)] + sniBytes
            let sniList = [UInt8(nameEntry.count >> 8), UInt8(nameEntry.count & 0xff)] + nameEntry
            extensions += [0x00, 0x00]  // type: server_name
            extensions += [UInt8(sniList.count >> 8), UInt8(sniList.count & 0xff)]
            extensions += sniList
        }
        // ALPN extension (type 0x0010).
        if !alpn.isEmpty {
            var alpnList: [UInt8] = []
            for proto in alpn {
                let p = Array(proto.utf8)
                alpnList.append(UInt8(p.count))
                alpnList += p
            }
            let alpnListWithLen = [UInt8(alpnList.count >> 8), UInt8(alpnList.count & 0xff)] + alpnList
            extensions += [0x00, 0x10]  // type: ALPN
            extensions += [UInt8(alpnListWithLen.count >> 8), UInt8(alpnListWithLen.count & 0xff)]
            extensions += alpnListWithLen
        }
        // Extensions with total length.
        let extensionsWithLen = [UInt8(extensions.count >> 8), UInt8(extensions.count & 0xff)] + extensions

        // ClientHello body.
        var body: [UInt8] = []
        body += [0x03, 0x03]  // legacy_version: TLS 1.2
        body += [UInt8](repeating: 0, count: 32)  // random
        body += [0x00]  // legacy_session_id: empty
        body += [0x00, 0x02, 0x13, 0x01]  // cipher_suites: TLS_AES_128_GCM_SHA256
        body += [0x01, 0x00]  // compression_methods: null
        body += extensionsWithLen

        // Handshake header: type(1) + length(3).
        var hello: [UInt8] = [0x01]  // ClientHello
        hello += [0x00, UInt8(body.count >> 8), UInt8(body.count & 0xff)]
        hello += body
        return hello
    }
}

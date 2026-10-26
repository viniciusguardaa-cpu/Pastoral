import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the Wi-Fi "caça-senha" stack: EAPOL 4-way parsing
/// (message 1/2/3, real RFC 3923/4202 layout), association-response
/// PMKID, and the hcnpcapng line rendering hashcat 22000/22001 accepts.
///
/// Frame layout authority: hashcat master `src/modules/module_22001.c`
/// `struct auth_packet` — exactly what the `WPA*02` eapol token casts
/// onto — and ZerBea hcxtools `include/ieee80211.h` (eapauth_t /
/// wpakey_t / WPA_KEY_INFO_* masks), which is what hcxpcapngtool writes.
/// An EAPOL-Key frame as captured on en0 (bytes after EtherType 0x888E):
///
/// ```
/// [0]      version (0x02)
/// [1]      type    (0x03 = EAPOL-Key)
/// [2..3]   length  (big-endian)
/// [4]      key descriptor type (0/1)
/// [5..6]   key info (BE): ver=bits 0–2, pairwise=bit 3, install=6,
///          ack=7, mic=8, secure=9, encrkeydata=12
/// [7..8]   key length (BE)
/// [9..16]  replay counter
/// [17..48] key nonce   (M1/M3 = ANONCE, M2/M4 = SNONCE)
/// [49..64] key IV       (zeroed)
/// [65..72] key RSC      (zeroed)
/// [73..80] key ID       (zeroed)
/// [81..96] key MIC      (sender's; the verified value)
/// [97..98] key data length (BE)
/// [99…]    key data
/// ```

@Suite("WpaCapture (Wi-Fi key capture)")
struct WpaCaptureTests {

    // MARK: Frame builders

    private static let nonceSTA = (1...32).map(UInt8.init)      // 0x01…0x20
    private static let nonceAP  = (33...64).map(UInt8.init)     // 0x21…0x40
    private static let micSeed  = (100...115).map(UInt8.init)   // "d"×16

    /// One EAPOL-Key frame body (the bytes after EtherType 0x888E) in the
    /// exact layout hashcat's `auth_packet_t` expects.
    ///
    /// Key Info ground truth (iPXE wpa.h / hcxtools ieee80211.h — both
    /// match every real capture): ver=bits 0–2 (2=WPA2), pairwise=bit 3,
    /// install=bit 6, ack=bit 7 ("a response is required", all messages
    /// except 4), secure=bit 9 (messages 3 and 4 only). So:
    /// - M1 = ver|pw|ack            = 0x008A
    /// - M2 = ver|pw                = 0x000A
    /// - M3 = ver|pw|ack|install|secure = 0x02CA
    /// - M4 = ver|pw|ack|secure     = 0x028A
    private static func eapolPayload(flags: UInt16, kdt: UInt8 = 0x01,
                                     keyLen: Int = 0,
                                     nonce: [UInt8], mic: [UInt8]? = nil) -> [UInt8] {
        var p: [UInt8] = []
        p.append(0x02)                                          // EAPOL version
        p.append(0x03)                                          // type: EAPOL-Key
        p.append(0x00); p.append(0x00)                          // length (fixed after)
        p.append(kdt)                                          // key descriptor type (RSN)
        p.append(UInt8(flags >> 8)); p.append(UInt8(flags & 0xFF))
        p.append(UInt8(keyLen >> 8)); p.append(UInt8(keyLen & 0xFF))
        p.append(contentsOf: (0x10...0x17).map(UInt8.init))     // replay counter
        p.append(contentsOf: nonce)                             // key nonce
        p.append(contentsOf: (49..<65).map { _ in 0 })          // key IV (zeroed)
        p.append(contentsOf: (65..<73).map { _ in 0 })          // key RSC (zeroed)
        p.append(contentsOf: (73..<81).map { _ in 0 })          // key ID  (zeroed)
        p.append(contentsOf: mic ?? Self.micSeed)               // key MIC
        p.append(UInt8(keyLen >> 8)); p.append(UInt8(keyLen & 0xFF))
        if keyLen > 0 {
            p.append(contentsOf: (99..<(99 + keyLen)).map(UInt8.init))
        }
        let len = UInt16(p.count)
        p[2] = UInt8(len >> 8); p[3] = UInt8(len & 0xFF)
        return p
    }

    /// RSN IE with one PMKID, wrapped in a couple of sibling IEs.
    private static func assocBody() -> [UInt8] {
        var body: [UInt8] = []
        // SSID IE (id 0): "TESTE"
        body.append(0x00)
        body.append(5); body.append(contentsOf: Array("TESTE".utf8))
        // RSN IE (id 0x30): ver(2) pairwise(n=1, 4B) akm(n=1, 4B) cap(2) nPMKID(1) pmkid(16)
        var rsn: [UInt8] = []
        rsn += [0x00, 0x00]                                  // version
        rsn += [0x00, 0x04, 0x00, 0x0F, 0xAC, 0x04]          // 1× CCMP
        rsn += [0x00, 0x02, 0x00, 0x8C, 0x00, 0x00]          // 1× PSK
        rsn += [0x00, 0x00]                                  // capabilities
        rsn += [0x01]                                        // 1 PMKID
        rsn += Self.micSeed                                  // the PMKID itself
        body.append(0x30)
        body.append(UInt8(rsn.count))
        body.append(contentsOf: rsn)
        // A trailing vendor IE (id 221) we must skip cleanly.
        body += [0xDD, 0x02, 0x00, 0x50]
        return body
    }

    // MARK: EAPOL

    @Test("message 2 parses: STA nonce (SNONCE), zeroed-MIC blob")
    func messageTwo() {
        let p = Self.eapolPayload(flags: 0x000A, nonce: Self.nonceSTA)
        let f = WpaCaptureParser.parseEAPOL(p)
        #expect(f?.message == 2)
        #expect(f?.nonce == Self.hex(Self.nonceSTA))
        #expect(f?.keyMic == Self.hex(Self.micSeed))
        // The exported blob is the full frame with its own MIC zeroed.
        var zeroed = p
        for i in 81..<97 { zeroed[i] = 0 }
        #expect(f?.frameHex == Self.hex(zeroed))
    }

    @Test("message 1 parses: AP nonce (ANONCE), carries 32-byte key data")
    func messageOne() {
        let p = Self.eapolPayload(flags: 0x008A, keyLen: 32, nonce: Self.nonceAP)
        let f = WpaCaptureParser.parseEAPOL(p)
        #expect(f?.message == 1)
        #expect(f?.nonce == Self.hex(Self.nonceAP))
    }

    @Test("message 3 parses: Secure|Ack|Install|pairwise, ANONCE repeated")
    func messageThree() {
        let p = Self.eapolPayload(flags: 0x02CA, nonce: Self.nonceAP)
        let f = WpaCaptureParser.parseEAPOL(p)
        #expect(f?.message == 3)
        #expect(f?.nonce == Self.hex(Self.nonceAP))
    }

    @Test("message 4 (Secure|MIC, no ACK) is recognised, not crashed on")
    func messageFour() {
        // Real M4 Key Info: SECURE (0x0200) + MIC (0x0100) + pairwise (0x0008)
        // + version 2 (0x0002), with the ACK bit clear — hcxtools' getkeyinfo()
        // only reads SECURE when ACK is clear.
        #expect(WpaCaptureParser.messagePair(from: 0x030A) == 4)
        let p = Self.eapolPayload(flags: 0x030A, nonce: Self.nonceSTA)
        let f = WpaCaptureParser.parseEAPOL(p)
        #expect(f?.message == 4)
    }

    @Test("group-key frames carry the pairwise bit clear and are filtered")
    func groupKeyRejected() {
        // Same flags as M1 minus the pairwise bit (group rekey).
        let p = Self.eapolPayload(flags: 0x0082, keyLen: 32, nonce: Self.nonceAP)
        #expect(WpaCaptureParser.parseEAPOL(p) == nil)
    }

    @Test("a zeroed key MIC means uncrackable: rejected")
    func zeroMICRejected() {
        let zeros = [UInt8](repeating: 0, count: 16)
        let p = Self.eapolPayload(flags: 0x0408, nonce: Self.nonceSTA, mic: zeros)
        #expect(WpaCaptureParser.parseEAPOL(p) == nil)
    }

    @Test("unsupported protocol version bits are rejected")
    func badVersionRejected() {
        // ver = 0 (bits 0–2 all clear) is not WPA/WPA2/WPA3.
        let p = Self.eapolPayload(flags: 0x0008, nonce: Self.nonceSTA)
        #expect(WpaCaptureParser.parseEAPOL(p) == nil)
    }

    @Test("short or wrong-type payloads are rejected, not crashed on")
    func junk() {
        #expect(WpaCaptureParser.parseEAPOL([0x02]) == nil)
        #expect(WpaCaptureParser.parseEAPOL([0x03]) == nil)
        // Right shape but only half the fixed part: no room for the MIC.
        let half = Array(Self.eapolPayload(flags: 0x000A, nonce: Self.nonceSTA).prefix(50))
        #expect(WpaCaptureParser.parseEAPOL(half) == nil)
        // Non-EAPOL leading bytes.
        let bad = [0x01, 0x00, 0x00, 0x63, 0x00]
            + Array(Self.eapolPayload(flags: 0x000A, nonce: Self.nonceSTA)[5...])
        #expect(WpaCaptureParser.parseEAPOL(bad) == nil)
    }

    // MARK: PMKID

    @Test("association response with an RSN PMKID cache entry parses")
    func pmkid() {
        let cap = WpaCaptureParser.parseAssociationResponse(Self.assocBody(),
                                                            apMAC: "aa-bb-cc-dd-ee-ff",
                                                            stationMAC: "11:22:33:44:55:66")
        guard case .pmkid(let pk) = cap?.kind else {
            Issue.record("expected a pmkid capture"); return
        }
        #expect(pk == Self.hex(Self.micSeed))
        #expect(cap?.bssid == "aa:bb:cc:dd:ee:ff")
        #expect(cap?.station == "11:22:33:44:55:66")
    }

    @Test("association response without any RSN IE yields nothing")
    func noPmkid() {
        var body = Self.assocBody()
        // Strip the RSN IE (everything from id 0x30 onward, keep leading SSID IE).
        if let i = body.firstIndex(of: 0x30) { body = Array(body[..<i]) }
        #expect(WpaCaptureParser.parseAssociationResponse(body,
                                                          apMAC: "AA:BB:CC:DD:EE:FF",
                                                          stationMAC: "11:22:33:44:55:66") == nil)
        #expect(WpaCaptureParser.parseAssociationResponse([],
                                                          apMAC: "AA:BB:CC:DD:EE:FF",
                                                          stationMAC: "11:22:33:44:55:66") == nil)
    }

    // MARK: hashcat lines (hcnpcapng text format)

    @Test("a 3/4 handshake line has the hashcat -m 22001 token shape")
    func handshakeLine() {
        let mic      = String(repeating: "c", count: 32)
        let snonce   = String(repeating: "b", count: 64)
        let frameHex = String(repeating: "d", count: 10)
        let cap = WpaCapture(kind: .handshake(
            fieldNonce: snonce, frameHex: frameHex,
            ekeyMIC: mic, messagePair: 0x13),
            bssid: "AA:BB:CC:DD:EE:FF",
            station: "11:22:33:44:55:66",
            essid: "hashcat-essid")
        // Byte-for-byte the same shape module_22001.c writes:
        // WPA*02*mic32*macAP12*macSTA12*essidhex*nonce64*eapolhex*mp
        #expect(cap.hashcatLine ==
            "WPA*02*" + mic +
            "*aabbccddeeff" +
            "*112233445566" +
            "*686173686361742d6573736964" +
            "*" + snonce +
            "*" + frameHex +
            "*13")
        // And the ST_HASH reference line for m22001 must round-trip
        // through the same token count.
        let st = "WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*"
            + "accd10fb464e*686173686361742d6573736964***"
        #expect(st.split(separator: "*", omittingEmptySubsequences: false).count
            == cap.hashcatLine.split(separator: "*", omittingEmptySubsequences: false).count)
    }

    @Test("a pmkid line has the -m 22000 shape, placeholder STA mac")
    func pmkidLine() {
        let cap = WpaCapture(kind: .pmkid(pmKid: String(repeating: "e", count: 32)),
                             bssid: "aa:bb:cc:dd:ee:ff",
                             station: "",
                             essid: "")
        // WPA*01*pmkid32*macAP12*macSTA12*essidhex***  → with an empty ESSID the
        // three trailing separators collapse into four asterisks total.
        #expect(cap.hashcatLine ==
            "WPA*01*" + String(repeating: "e", count: 32)
            + "*aabbccddeeff"
            + "*" + String(repeating: "0", count: 12)
            + "****")
    }

    @Test("unknown station macs fall back to twelve zeros, never colons")
    func macFallback() {
        let cap = WpaCapture(kind: .pmkid(pmKid: String(repeating: "e", count: 32)),
                             bssid: "not-a-mac",
                             station: "11:22:33:44:55:66",
                             essid: "café ☕")
        let f = cap.hashcatLine.split(separator: "*").map(String.init)
        #expect(f[3] == String(repeating: "0", count: 12))  // AP fallback
        #expect(f[4] == "112233445566")
        // essid slot is raw UTF-8 bytes.
        #expect(f[5] == Self.hex(Array("café ☕".utf8)))
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

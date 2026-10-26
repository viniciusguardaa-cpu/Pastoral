import Foundation

/// Wi-Fi "caça-senha": decode the two frame types that matter for
/// offline cracking of a WPA/WPA2 key, and render them as hashcat lines.
///
/// Two capture kinds:
/// - **PMKID** from an (re)association response carrying an RSN IE with
///   a PMKID cache entry — hashcat `-m 22000`.
/// - **4-Way Handshake** EAPOL-Key frames — hashcat `-m 22001`.
///
/// Lines are emitted in **hcnpcapng text format** — the exact layout that
/// ZerBea's `hcxpcapngtool` writes and hashcat's module 22001/22002 parse
/// (`src/modules/module_22001.c::module_hash_decode`, 9 `*`-separated
/// tokens):
///
/// ```
/// WPA*01*<pmkid 32hex>*<macAP 12hex>*<macSTA 12hex>*<essid hex>***
/// WPA*02*<keymic 32hex>*<macAP 12hex>*<macSTA 12hex>*<essid hex>*
///       <nonce 64hex>*<EAPOL frame hex, own Key MIC zeroed>*<mp byte>
/// ```
///
/// Everything here is pure byte parsing — unit tested against synthetic
/// frames in `WpaCaptureTests`.

public struct WpaCapture: Codable, Equatable, Sendable {
    public enum Kind: Codable, Equatable, Sendable {
        /// PMKID from an association response; `pmKid` = 32 hex chars.
        case pmkid(pmKid: String)
        /// Crackable EAPOL material.
        /// - `fieldNonce`: the nonce that is NOT inside `frameHex`
        ///   (for a 3/4 export it is SNONCE, for a 2/4 export it is
        ///   ANONCE) — 64 hex chars.
        /// - `frameHex`: full EAPOL-Key frame (the one whose Key MIC is
        ///   verified by hashcat) with its own 16-byte Key MIC zeroed,
        ///   as hcxpcapngtool emits it.
        /// - `ekeyMIC`: that frame's real Key MIC — 32 hex chars.
        /// - `messagePair`: export pair, `0x13` (M3), `0x02` (M2).
        case handshake(fieldNonce: String, frameHex: String,
                       ekeyMIC: String, messagePair: Int)
    }

    /// What we saw.
    public let kind: Kind
    /// The AP (BSSID), lowercased colon-form.
    public let bssid: String
    /// The station MAC when known ("" when the frame carried only one).
    public let station: String
    /// The network's SSID ("" when not recoverable from the frame).
    public let essid: String

    public init(kind: Kind, bssid: String, station: String, essid: String) {
        self.kind = kind
        self.bssid = bssid
        self.station = station
        self.essid = essid
    }

    /// hcnpcapng line for `hashcat -m 22000` / `-m 22001`.
    public var hashcatLine: String {
        let apMac = Self.mac12(bssid)
        let staMac = Self.mac12(station.isEmpty ? "00:00:00:00:00:00" : station)
        let essidHex = WpaCaptureParser.hex(Array(essid.utf8))
        switch kind {
        case .pmkid(let pk):
            return "WPA*01*\(pk)*\(apMac)*\(staMac)*\(essidHex)***"
        case .handshake(let fieldNonce, let frameHex, let mic, let mp):
            return "WPA*02*\(mic)*\(apMac)*\(staMac)*\(essidHex)*"
                + "\(fieldNonce)*\(frameHex)*\(String(format: "%02x", mp))"
        }
    }

    /// MAC in hcnpcapng form: lowercase, no colons, exactly 12 chars.
    static func mac12(_ mac: String) -> String {
        let t = mac.lowercased().replacingOccurrences(of: ":", with: "")
        guard t.count == 12 else { return String(repeating: "0", count: 12) }
        return t
    }
}

public enum WpaCaptureParser {

    /// EtherType for EAPOL key exchange frames.
    public static let etherTypeEAPOL: UInt16 = 0x888E

    /// EtherType for 802.11 management frames mirrored onto Ethernet
    /// (association response / (re)auth response).
    public static let etherType80211Mgmt: UInt16 = 0x888B

    // MARK: - EAPOL

    /// EAPOL-Key frame field positions (RFC 4202 §4 / IEEE 802.11i —
    /// identical to the `auth_packet_t` hashcat casts the `WPA*02` eapol
    /// token onto):
    /// `[0] version(0x02) [1] type(0x03) [2..3] len(BE) [4] kdt (0x00/0x01/0xFE)`
    /// `[5..6] key info(BE) [7..8] key len(BE) [9..16] replay counter`
    /// `[17..48] key nonce(32) [49..64] IV(16) [65..72] RSC(8)`
    /// `[73..80] ID(8) [81..96] key MIC(16) [97..98] data len(BE) [99…]`
    public static let eapolMinSize = 99
    public static let eapolNonceRange = 17..<49
    public static let eapolMicRange = 81..<97

    /// Key Info bit masks (iPXE `net/802_11/wpa.h` and ZerBea hcxtools
    /// `include/ieee80211.h` — the two agree with each other and with
    /// every real capture: WPA_KEY_INFO_VERSION bits 0–2, KEY_TYPE
    /// pairwise bit 3, INSTALL bit 6, ACK bit 7 = "a response is
    /// required" i.e. set on M1–M3 only, SECURE bit 9 = messages 3/4.
    public static let kiTypeMask: UInt16 = 0x0007   // bits 0–2: 1=WPA, 2=WPA2, 3=WPA3
    public static let kiKeyType: UInt16 = 0x0008   // bit 3: 1 = pairwise, 0 = group
    public static let kiInstall: UInt16 = 0x0040   // bit 6
    public static let kiAck: UInt16 = 0x0080       // bit 7
    public static let kiSecure: UInt16 = 0x0200    // bit 9

    /// One EAPOL-Key frame of the 4-way handshake.
    ///
    /// Each frame carries exactly one 32-byte nonce in the Key Nonce
    /// field: M1/M3 carry ANONCE, M2/M4 carry SNONCE. Which export frame
    /// to use and which nonce to put in the field slot is decided in the
    /// hound (`WiFiHound`) following hcxpcapngtool's pairing rules.
    public struct EapolKeyFrame: Equatable, Sendable {
        /// 1, 2, 3 or 4 — from `messagePair(from:)`.
        public let message: Int
        /// The frame's Key Nonce field (64 hex chars).
        public let nonce: String
        /// The frame's real Key MIC octets (32 hex chars).
        public let keyMic: String
        /// Full EAPOL frame hex with the 16-byte Key MIC zeroed out
        /// (hashcat re-reads the mic from its own token; hcxpcapngtool
        /// zero-copies the same way).
        public let frameHex: String
    }

    /// Message number from Key Info, exactly as hcxtools' `getkeyinfo()`
    /// does (ACK → Install ? M3 : M1; otherwise Secure ? M4 : M2).
    public static func messagePair(from keyInfo: UInt16) -> Int {
        if keyInfo & kiAck != 0 {
            return keyInfo & kiInstall != 0 ? 3 : 1
        }
        return keyInfo & kiSecure != 0 ? 4 : 2
    }

    /// Decode one EAPOL frame (the bytes after EtherType 0x888E).
    /// Returns nil unless this is a usable pairwise-key handshake frame
    /// (M1–M4 with a non-zero Key MIC).
    public static func parseEAPOL(_ payload: [UInt8]) -> EapolKeyFrame? {
        guard payload.count >= eapolMinSize else { return nil }
        let kdt = payload[4]
        guard payload[0] == 0x02,      // EAPOL version
              payload[1] == 0x03,      // EAPOL type: key
              kdt == 0x00 || kdt == 0x01 || kdt == 0xFE   // legacy/RSN/WPA-v1
        else { return nil }
        let keyInfo = (UInt16(payload[5]) << 8) | UInt16(payload[6])
        // Pairwise key only — bit 3 must be SET (group rekeys carry it
        // clear); protocol version bits must be 1 (WPA), 2 (WPA2) or
        // 3 (WPA3) — the same filter hashcat's m22001 decoder applies.
        guard keyInfo & kiKeyType != 0,
              (1...3).contains(Int(keyInfo & kiTypeMask)) else { return nil }
        let mic = Array(payload[eapolMicRange])
        guard mic.contains(where: { $0 != 0 }) else { return nil }

        var frame = payload
        frame.replaceSubrange(eapolMicRange, with: [UInt8](repeating: 0, count: 16))
        return EapolKeyFrame(message: messagePair(from: keyInfo),
                             nonce: hex(Array(payload[eapolNonceRange])),
                             keyMic: hex(mic),
                             frameHex: hex(frame))
    }

    /// Parse an association/reassociation response body (the part after
    /// the 2-byte sequence control in a real 802.11 frame, or the whole
    /// payload when the management frame was mirrored over Ethernet).
    /// Looks for an RSN IE (id 0x30) with at least one PMKID cache entry;
    /// also picks up the SSID IE (id 0) so the line carries the network
    /// name instead of an empty salt.
    public static func parseAssociationResponse(_ body: [UInt8],
                                                 apMAC: String,
                                                 stationMAC: String) -> WpaCapture? {
        var essid = ""
        var pmkid: String?
        var off = 0
        while off + 2 <= body.count {
            let id = body[off]
            let len = Int(body[off + 1])
            let start = off + 2
            let end = start + len
            guard end <= body.count else { break }
            switch id {
            case 0x00 where essid.isEmpty:
                if let s = String(bytes: Array(body[start..<end]), encoding: .utf8),
                   s.allSatisfy({ $0.isASCII }) {
                    essid = s
                }
            case 0x30 where pmkid == nil:
                if let pk = parseRSNIE(Array(body[start..<end])) {
                    pmkid = pk
                }
            default:
                break
            }
            off = end
        }
        guard let pk = pmkid else { return nil }
        return WpaCapture(kind: .pmkid(pmKid: pk),
                          bssid: normalize(apMAC),
                          station: normalize(stationMAC),
                          essid: essid)
    }

    /// RSN IE: version(2), pairwise suites(n*…), auth&key-mgmt(m*…),
    /// capabilities(2), numPMKIDs(1), pmkid*(16 each).
    private static func parseRSNIE(_ rsn: [UInt8]) -> String? {
        guard rsn.count >= 5 else { return nil }
        var off = 2                               // version
        // Pairwise cipher suite list.
        guard off + 2 <= rsn.count else { return nil }
        let nPair = (Int(rsn[off]) << 8) | Int(rsn[off + 1])
        off += 2 + nPair * 2
        // Auth and key management list.
        guard off + 2 <= rsn.count else { return nil }
        let nAKM = (Int(rsn[off]) << 8) | Int(rsn[off + 1])
        off += 2 + nAKM * 2
        // Capabilities.
        guard off + 2 <= rsn.count else { return nil }
        off += 2
        guard off < rsn.count else { return nil }
        let numPMKIDs = Int(rsn[off]); off += 1
        guard numPMKIDs > 0, off + 16 <= rsn.count else { return nil }
        return hex(Array(rsn[off..<(off+16)]))
    }

    // MARK: - Helpers

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func normalize(_ mac: String) -> String {
        mac.lowercased().replacingOccurrences(of: "-", with: ":")
    }
}

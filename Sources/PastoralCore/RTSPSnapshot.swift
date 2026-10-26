import Foundation
import Darwin

// MARK: - RTSP snapshot (pure logic, testable)
//
// A minimal RTSP client that grabs a single JPEG frame from an IP camera
// over TCP-interleaved RTSP. No external libs — just socket + RTSP text
// framing + RTP/JPEG (RFC 2435 subset) parsing.
//
// Flow:
//   1. OPTIONS (optional, probes liveness)
//   2. DESCRIBE → SDP (finds the video track + control URL)
//   3. SETUP → session id + interleaved channel
//   4. PLAY → server starts sending RTP frames on the channel
//   5. Read RTP packets until a complete JPEG frame is assembled
//      (marker bit set = end of frame), then TEARDOWN.
//
// Only the JPEG-over-RTP payload type (26) is decoded. H.264/H.265
// cameras are detected and reported but not snapshotted — decoding NAL
// units to an image needs a real codec. Many cameras expose a JPEG
// "snapshot" URL (/cgi-bin/.../snapshot.jpg, /ISAPI/Streaming/channels/
// 101/picture) as a fallback; we try that when RTSP doesn't yield JPEG.

/// A captured snapshot: the image bytes + the MIME type + the source URL.
public struct CameraSnapshot: Equatable, Sendable {
    public let data: Data
    public let contentType: String
    public let sourceURL: String

    public init(data: Data, contentType: String, sourceURL: String) {
        self.data = data
        self.contentType = contentType
        self.sourceURL = sourceURL
    }
}

/// Description of a camera's video track, parsed from SDP.
public struct RTSPTrack: Equatable, Sendable {
    public let trackID: String          // "trackID=0" control path
    public let payloadType: Int         // RTP payload type (26 = JPEG)
    public let codec: String            // "JPEG", "H264", "H265", ...
    public let clockRate: Int
}

public enum RTSPSnapshot {

    // MARK: - SDP parsing (pure)

    /// Parse an SDP body into video tracks. Only media lines (m=) with
    /// video are kept; rtpmap attributes give the codec + payload type.
    public static func parseSDP(_ sdp: String) -> [RTSPTrack] {
        var tracks: [RTSPTrack] = []
        var currentMedia: (kind: String, port: Int, payload: Int)?
        var rtpmaps: [Int: (codec: String, clock: Int)] = [:]
        var controlPaths: [Int: String] = [:]

        for rawLine in sdp.components(separatedBy: "\r\n").joined(separator: "\n").split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.hasPrefix("m=video ") {
                // Format: m=video <port> <transport> <payloadType> [<pt2> ...]
                let parts = line.dropFirst("m=video ".count).split(separator: " ")
                if let port = parts.first.flatMap({ Int($0) }),
                   let payload = parts.last.flatMap({ Int($0) }) {
                    currentMedia = ("video", port, payload)
                }
            } else if line.hasPrefix("m=") {
                // Non-video media line ends the current video block.
                if let media = currentMedia {
                    tracks.append(track(from: media, rtpmaps: rtpmaps, controls: controlPaths))
                }
                currentMedia = nil
                rtpmaps.removeAll()
                controlPaths.removeAll()
            } else if line.hasPrefix("a=rtpmap:") {
                // a=rtpmap:<pt> <codec>/<clockrate>
                let rest = String(line.dropFirst("a=rtpmap:".count))
                if let space = rest.firstIndex(of: " ") {
                    let ptStr = String(rest[..<space])
                    let spec = String(rest[rest.index(after: space)...])
                    if let pt = Int(ptStr) {
                        let codecPart = spec.split(separator: "/").first.map(String.init) ?? spec
                        let clock = spec.split(separator: "/").dropFirst().first.flatMap({ Int($0) }) ?? 90000
                        rtpmaps[pt] = (codecPart, clock)
                    }
                }
            } else if line.hasPrefix("a=control:") {
                let path = String(line.dropFirst("a=control:".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if let media = currentMedia {
                    controlPaths[media.payload] = path
                }
            }
        }
        if let media = currentMedia {
            tracks.append(track(from: media, rtpmaps: rtpmaps, controls: controlPaths))
        }
        return tracks
    }

    private static func track(from media: (kind: String, port: Int, payload: Int),
                              rtpmaps: [Int: (codec: String, clock: Int)],
                              controls: [Int: String]) -> RTSPTrack {
        let rm = rtpmaps[media.payload]
        let codec = rm?.codec ?? "unknown"
        let clock = rm?.clock ?? 90000
        let control = controls[media.payload] ?? "trackID=\(media.payload)"
        return RTSPTrack(trackID: control, payloadType: media.payload,
                        codec: codec, clockRate: clock)
    }

    // MARK: - RTP/JPEG parsing (pure, RFC 2435 subset)

    /// A parsed RTP header (first 12 bytes minimum).
    public struct RTPHeader: Equatable {
        public let version: Int
        public let padding: Bool
        public let extensionBit: Bool
        public let csrcCount: Int
        public let marker: Bool
        public let payloadType: Int
        public let sequence: Int
        public let timestamp: UInt32
        public let ssrc: UInt32
    }

    /// Parse the RTP header from the first bytes of a packet. Returns the
    /// header and the offset where the payload begins (12 + 4*csrcCount).
    public static func parseRTPHeader(_ bytes: [UInt8]) -> (RTPHeader, Int)? {
        guard bytes.count >= 12 else { return nil }
        let v = Int(bytes[0] >> 6)
        let p = (bytes[0] & 0x20) != 0
        let x = (bytes[0] & 0x10) != 0
        let cc = Int(bytes[0] & 0x0F)
        let m = (bytes[1] & 0x80) != 0
        let pt = Int(bytes[1] & 0x7F)
        let seq = (Int(bytes[2]) << 8) | Int(bytes[3])
        let ts = (UInt32(bytes[4]) << 24) | (UInt32(bytes[5]) << 16)
               | (UInt32(bytes[6]) << 8) | UInt32(bytes[7])
        let ssrc = (UInt32(bytes[8]) << 24) | (UInt32(bytes[9]) << 16)
                 | (UInt32(bytes[10]) << 8) | UInt32(bytes[11])
        let payloadStart = 12 + cc * 4
        guard bytes.count >= payloadStart else { return nil }
        return (RTPHeader(version: v, padding: p, extensionBit: x, csrcCount: cc,
                         marker: m, payloadType: pt, sequence: seq,
                         timestamp: ts, ssrc: ssrc), payloadStart)
    }

    /// Strip the RFC 2435 headers from a JPEG RTP payload and return the
    /// JPEG fragment bytes. Handles the optional headers the fixed 8-byte
    /// strip misses:
    ///   - Restart Marker header: 8 extra bytes when Type is 64–127.
    ///   - Quantization Table header: 4 + Length bytes when Q ≥ 128. The
    ///     transmitted tables are wrapped in a DQT segment and injected
    ///     after SOI so the fragment stays decodable.
    /// Returns nil when the payload is too short or truncated.
    public static func jpegFragment(fromRTPPayload payload: [UInt8]) -> [UInt8]? {
        guard payload.count >= 8 else { return nil }
        let type = Int(payload[4])
        let q = Int(payload[5])
        var offset = 8
        if type >= 64 && type <= 127 {
            offset += 8   // restart marker header
        }
        var dqt: [UInt8]? = nil
        if q >= 128 {
            // Quantization Table header: MBZ(1) Precision(1) Length(2).
            guard offset + 4 <= payload.count else { return nil }
            let qtLen = (Int(payload[offset + 2]) << 8) | Int(payload[offset + 3])
            guard offset + 4 + qtLen <= payload.count else { return nil }
            let tables = Array(payload[(offset + 4)..<(offset + 4 + qtLen)])
            // DQT segment: FF DB + 2-byte length (= 2 + table bytes) + tables.
            let segLen = qtLen + 2
            dqt = [0xFF, 0xDB, UInt8(segLen >> 8), UInt8(segLen & 0xFF)] + tables
            offset += 4 + qtLen
        }
        guard offset <= payload.count else { return nil }
        var body = Array(payload[offset...])
        // Inject the transmitted tables as a DQT segment right after SOI —
        // only the first fragment of a frame (fragment offset 0) starts
        // with the SOI marker.
        if let dqt, body.count >= 2, body[0] == 0xFF, body[1] == 0xD8 {
            body = [0xFF, 0xD8] + dqt + body.dropFirst(2)
        }
        return body
    }

    /// Reassemble JPEG fragments from a sequence of RTP/JPEG packets.
    /// The marker bit on a packet signals the end of a frame; we collect
    /// payloads until then and concatenate. Returns the JPEG bytes when a
    /// complete frame is seen, or nil if the stream ended without one.
    ///
    /// RFC 2435 JPEG header (4 bytes main + optional Restart + Q tables):
    ///   0: Type-specific (usually 0)
    ///   1-3: Fragment offset (24-bit big-endian)
    ///   4: Type (1=Huffman tables present, etc.)
    ///   5: Q (quantization table)
    ///   6-7: Width/8, Height/8
    /// Headers are stripped per-packet by `jpegFragment(fromRTPPayload:)`.
    /// Only baseline JPEG is expected — sufficient for the vast majority
    /// of IP cameras.
    public static func reassembleJPEG(_ packets: [[UInt8]]) -> Data? {
        var frame: [UInt8] = []
        var sawMarker = false
        for pkt in packets {
            guard let (hdr, payloadStart) = parseRTPHeader(pkt) else { continue }
            guard hdr.payloadType == 26 else { continue }   // JPEG only
            let payload = Array(pkt[payloadStart...])
            guard let jpegBody = jpegFragment(fromRTPPayload: payload) else { continue }
            frame.append(contentsOf: jpegBody)
            if hdr.marker { sawMarker = true; break }
        }
        guard sawMarker, !frame.isEmpty else { return nil }
        // Many cameras already emit a complete JFIF stream in the payload
        // (after the 8-byte RTP header). If it starts with the JPEG SOI
        // marker (FFD8) we trust it; otherwise we can't reliably rebuild
        // tables, so we bail.
        guard frame.count >= 2, frame[0] == 0xFF, frame[1] == 0xD8 else { return nil }
        return Data(frame)
    }

    // MARK: - RTSP request building (pure)

    /// Build a complete RTSP request string.
    public static func buildRequest(method: String, url: String,
                                     cseq: Int, session: String? = nil,
                                     extraHeaders: [String: String] = [:]) -> Data {
        var req = "\(method) \(url) RTSP/1.0\r\n"
        req += "CSeq: \(cseq)\r\n"
        req += "User-Agent: Pastoral\r\n"
        if let session { req += "Session: \(session)\r\n" }
        for (k, v) in extraHeaders { req += "\(k): \(v)\r\n" }
        req += "\r\n"
        return Data(req.utf8)
    }

    /// Parse a complete RTSP response (status line + headers). Returns nil
    /// if the buffer doesn't contain a full response head (terminated by
    /// \r\n\r\n).
    public static func parseResponse(_ buffer: Data) -> (status: Int, headers: [String: String], bodyStart: Int)? {
        // O fim do cabeçalho pode já vir seguido de RTP binário no mesmo
        // pacote (o servidor inicia o stream logo após responder 200) — decodificar
        // o buffer inteiro como UTF-8 daria nil. Localizamos o \r\n\r\n nos bytes
        // crus e decodificamos só o cabeçalho (texto puro).
        let sep = [UInt8](Array("\r\n\r\n".utf8))
        var arr = [UInt8](buffer)
        guard let end = findBytes(sep, in: &arr) else { return nil }
        let head = String(decoding: arr[0..<end], as: UTF8.self)
        let lines = head.components(separatedBy: "\r\n")
        guard let first = lines.first else { return nil }
        let parts = first.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            if let colon = line.firstIndex(of: ":") {
                let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
                let val = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                headers[key.lowercased()] = val
            }
        }
        let bodyStart = end + sep.count
        return (status, headers, bodyStart)
    }

    /// Posição do primeiro `needle` em `haystack`, ou nil.
    private static func findBytes(_ needle: [UInt8], in haystack: inout [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        let last = haystack.count - needle.count
        for i in 0...last where Array(haystack[i..<(i + needle.count)]) == needle {
            return i
        }
        return nil
    }

    /// Extract the Content-Length from parsed headers, if present.
    public static func contentLength(in headers: [String: String]) -> Int? {
        headers["content-length"].flatMap(Int.init)
    }
}

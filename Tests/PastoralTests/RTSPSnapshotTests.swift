import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the RTSP snapshot pure logic: SDP parsing, RTP/JPEG
/// reassembly, and RTSP request/response framing. No sockets, no I/O.
@Suite("RTSP snapshot")
struct RTSPSnapshotTests {

    // MARK: - SDP parsing

    @Test("Parses a video track with JPEG codec from SDP")
    func parseSDPJPEG() {
        let sdp = """
        v=0\r
        o=- 0 0 IN IP4 10.0.0.50\r
        s=Session\r
        c=IN IP4 0.0.0.0\r
        t=0 0\r
        m=video 0 RTP/AVP 26\r
        a=rtpmap:26 JPEG/90000\r
        a=control:trackID=0\r
        """
        let tracks = RTSPSnapshot.parseSDP(sdp)
        #expect(tracks.count == 1)
        #expect(tracks[0].payloadType == 26)
        #expect(tracks[0].codec == "JPEG")
        #expect(tracks[0].clockRate == 90000)
        #expect(tracks[0].trackID == "trackID=0")
    }

    @Test("Parses an H.264 track (detected but not snapshotted)")
    func parseSDPH264() {
        let sdp = """
        v=0\r
        m=video 0 RTP/AVP 96\r
        a=rtpmap:96 H264/90000\r
        a=control:trackID=1\r
        """
        let tracks = RTSPSnapshot.parseSDP(sdp)
        #expect(tracks.count == 1)
        #expect(tracks[0].codec == "H264")
        #expect(tracks[0].payloadType == 96)
    }

    @Test("Ignores audio-only SDP")
    func parseSDPAudioOnly() {
        let sdp = """
        v=0\r
        m=audio 0 RTP/AVP 0\r
        a=rtpmap:0 PCMU/8000\r
        """
        let tracks = RTSPSnapshot.parseSDP(sdp)
        #expect(tracks.isEmpty)
    }

    // MARK: - RTP header parsing

    @Test("Parses RTP header with marker bit set")
    func parseRTPHeaderMarker() {
        // Version 2, no padding, no extension, no CSRC, marker=1, PT=26
        // seq=1234, timestamp=0x01020304, ssrc=0x0A0B0C0D
        let bytes: [UInt8] = [
            0x80,       // V=2, P=0, X=0, CC=0
            0xE0,       // M=1, PT=26 (0x80 | 26 = 0x9A... wait: M is top bit)
            // M=1 → 0x80 | 26 = 0x9A
        ]
        // Recompute: 0x80 (M=1) | 26 = 0x9A
        let pkt: [UInt8] = [
            0x80, 0x9A,             // V=2, M=1, PT=26
            0x04, 0xD2,             // seq=1234
            0x01, 0x02, 0x03, 0x04, // timestamp
            0x0A, 0x0B, 0x0C, 0x0D  // ssrc
        ]
        guard let (hdr, payloadStart) = RTSPSnapshot.parseRTPHeader(pkt) else {
            Issue.record("header should parse"); return
        }
        #expect(hdr.version == 2)
        #expect(hdr.marker == true)
        #expect(hdr.payloadType == 26)
        #expect(hdr.sequence == 1234)
        #expect(hdr.timestamp == 0x01020304)
        #expect(hdr.ssrc == 0x0A0B0C0D)
        #expect(payloadStart == 12)
    }

    @Test("Rejects too-short RTP packet")
    func parseRTPHeaderTooShort() {
        #expect(RTSPSnapshot.parseRTPHeader([0x80, 0x9A]) == nil)
    }

    // MARK: - JPEG reassembly

    @Test("Reassembles a single-packet JPEG frame (marker set)")
    func reassembleSinglePacketJPEG() {
        // One RTP packet: PT=26, marker=1, 8-byte RFC2435 header, then FFD8...FFD9
        let jpegBody: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0xFF, 0xD9]
        let rtpHeader: [UInt8] = [
            0x80, 0x9A,             // V=2, M=1, PT=26
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01  // ssrc
        ]
        let rfc2435Header: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let pkt = rtpHeader + rfc2435Header + jpegBody
        guard let jpeg = RTSPSnapshot.reassembleJPEG([pkt]) else {
            Issue.record("should reassemble"); return
        }
        #expect(jpeg.count == jpegBody.count)
        #expect(jpeg[0] == 0xFF)
        #expect(jpeg[1] == 0xD8)
    }

    @Test("Returns nil when no marker bit is seen")
    func reassembleNoMarker() {
        let rtpHeader: [UInt8] = [
            0x80, 0x1A,             // V=2, M=0, PT=26
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        ]
        let rfc2435Header: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let jpegBody: [UInt8] = [0xFF, 0xD8, 0xFF, 0xD9]
        let pkt = rtpHeader + rfc2435Header + jpegBody
        #expect(RTSPSnapshot.reassembleJPEG([pkt]) == nil)
    }

    @Test("Returns nil for non-JPEG payload type")
    func reassembleNonJPEG() {
        let rtpHeader: [UInt8] = [
            0x80, 0xE0,             // V=2, M=1, PT=96 (H.264)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        ]
        let body: [UInt8] = [0xFF, 0xD8, 0xFF, 0xD9]
        let pkt = rtpHeader + body
        #expect(RTSPSnapshot.reassembleJPEG([pkt]) == nil)
    }

    // MARK: - RTSP request/response framing

    @Test("Builds a DESCRIBE request with CSeq")
    func buildRequest() {
        let data = RTSPSnapshot.buildRequest(method: "DESCRIBE", url: "rtsp://10.0.0.50/",
                                             cseq: 1,
                                             extraHeaders: ["Accept": "application/sdp"])
        let str = String(data: data, encoding: .utf8) ?? ""
        #expect(str.hasPrefix("DESCRIBE rtsp://10.0.0.50/ RTSP/1.0\r\n"))
        #expect(str.contains("CSeq: 1\r\n"))
        #expect(str.contains("Accept: application/sdp\r\n"))
        #expect(str.hasSuffix("\r\n\r\n"))
    }

    @Test("Parses a 200 OK response with Content-Length")
    func parseResponse() {
        let body = "v=0\r\nm=video 0 RTP/AVP 26\r\n"
        let head = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: \(body.utf8.count)\r\n"
        let raw = Data((head + "\r\n" + body).utf8)
        guard let parsed = RTSPSnapshot.parseResponse(raw) else {
            Issue.record("should parse"); return
        }
        #expect(parsed.status == 200)
        #expect(parsed.headers["content-type"] == "application/sdp")
        #expect(RTSPSnapshot.contentLength(in: parsed.headers) == body.utf8.count)
    }

    @Test("Returns nil for incomplete response head")
    func parseResponseIncomplete() {
        #expect(RTSPSnapshot.parseResponse(Data("RTSP/1.0 200 OK\r\n".utf8)) == nil)
    }

    // MARK: - RFC 2435 optional headers

    @Test("Strips restart marker header (Type 64-127)")
    func jpegFragmentRestartHeader() {
        // Type=64 → 8-byte restart marker header after the main header.
        var payload: [UInt8] = [0, 0, 0, 0, 64, 0, 0, 0]
        payload += [UInt8](repeating: 0, count: 8)   // restart header
        payload += [0xFF, 0xD8, 0xFF, 0xD9]
        let frag = RTSPSnapshot.jpegFragment(fromRTPPayload: payload)
        #expect(frag == [0xFF, 0xD8, 0xFF, 0xD9])
    }

    @Test("Injects DQT when Q >= 128")
    func jpegFragmentQuantTables() {
        // Q=255 → quant table header + tables; tables become a DQT after SOI.
        let tables: [UInt8] = [0x00] + [UInt8](repeating: 0x11, count: 64)
        var payload: [UInt8] = [0, 0, 0, 0, 0, 255, 0, 0]
        payload += [0, 0, 0, UInt8(tables.count)]   // MBZ, Precision, Length
        payload += tables
        payload += [0xFF, 0xD8, 0xFF, 0xD9]
        let frag = RTSPSnapshot.jpegFragment(fromRTPPayload: payload)
        // Expect SOI + DQT segment + rest.
        let segLen = tables.count + 2
        var expected: [UInt8] = [0xFF, 0xD8, 0xFF, 0xDB,
                                 UInt8(segLen >> 8), UInt8(segLen & 0xFF)]
        expected += tables
        expected += [0xFF, 0xD9]
        #expect(frag == expected)
    }

    // MARK: - RTSP authentication

    @Test("Parses a Digest challenge")
    func parseDigestChallenge() {
        let ch = RTSPAuth.parseChallenge(
            "Digest realm=\"cam\", nonce=\"abc123\", qop=\"auth\"")
        #expect(ch?.scheme == .digest)
        #expect(ch?.realm == "cam")
        #expect(ch?.nonce == "abc123")
        #expect(ch?.qop == "auth")
    }

    @Test("Parses a Basic challenge")
    func parseBasicChallenge() {
        let ch = RTSPAuth.parseChallenge("Basic realm=\"camera\"")
        #expect(ch?.scheme == .basic)
        #expect(ch?.realm == "camera")
    }

    @Test("Digest authorization matches RFC 2617 example")
    func digestRFC2617Vector() {
        // Canonical example from RFC 2617 §3.5.
        let ch = RTSPAuthChallenge(
            scheme: .digest, realm: "testrealm@host.com",
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            qop: "auth", opaque: nil, algorithm: "MD5")
        let header = RTSPAuth.authorizationHeader(
            method: "GET", uri: "/dir/index.html",
            challenge: ch,
            username: "Mufasa", password: "Circle Of Life",
            nonceCount: 1, cnonce: "0a4f113b")
        #expect(header.hasPrefix("Digest "))
        #expect(header.contains("username=\"Mufasa\""))
        #expect(header.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""))
        #expect(header.contains("nc=00000001"))
        #expect(header.contains("cnonce=\"0a4f113b\""))
        #expect(header.contains("response=\"6629fae49393a05397450978507c4ef1\""))
    }

    @Test("Digest without qop")
    func digestNoQop() {
        let ch = RTSPAuthChallenge(
            scheme: .digest, realm: "cam",
            nonce: "n", qop: nil, opaque: nil, algorithm: "MD5")
        let header = RTSPAuth.authorizationHeader(
            method: "DESCRIBE", uri: "rtsp://10.0.0.1/",
            challenge: ch, username: "u", password: "p")
        #expect(header.contains("response=\""))
        #expect(!header.contains("qop="))
    }

    @Test("Basic authorization is base64 user:pass")
    func basicAuthHeader() {
        let ch = RTSPAuthChallenge(
            scheme: .basic, realm: "cam",
            nonce: nil, qop: nil, opaque: nil, algorithm: "MD5")
        let header = RTSPAuth.authorizationHeader(
            method: "DESCRIBE", uri: "rtsp://10.0.0.1/",
            challenge: ch, username: "test", password: "123")
        #expect(header == "Basic dGVzdDoxMjM=")
    }
}

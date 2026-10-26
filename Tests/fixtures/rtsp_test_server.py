#!/usr/bin/env python3
"""Minimal RTSP test camera for Pastoral integration tests.

Serves a JPEG-over-RTP live stream (RFC 2435) on TCP-interleaved RTSP,
optionally protected with Basic or Digest-MD5 auth. Used to validate
RTSPStreamClient / RTSPSnapshotClient end to end without real hardware.

Usage:
  python3 rtsp_test_server.py --port 15540 --media /path/frame.jpg \
      [--auth none|basic|digest] [--user admin] [--pass secret]
"""
import argparse
import base64
import hashlib
import http.server
import re
import socket
import socketserver
import struct
import sys
import threading
import time
import uuid

SSRC = 0x0A0B0C0D


def log(msg):
    print(f"[fakecam] {msg}", flush=True)


class ClientHandler(threading.Thread):
    """One TCP connection: RTSP control channel + interleaved RTP."""

    _ACTIVE = set()

    def __init__(self, sock, args):
        super().__init__(daemon=True)
        self.sock = sock
        self.args = args
        # Hold a strong ref for the thread's lifetime: socketserver closes its own
        # copy of the socket in shutdown_request as soon as finish_request returns,
        # and GC would close this one too.
        self._ACTIVE.add(self)
        self.session = uuid.uuid4().hex[:8]
        self.authed = False
        self.nonce = uuid.uuid4().hex
        self.playing = threading.Event()
        self.running = True

    # ---- auth ----

    def check_auth(self, method, uri, headers):
        auth = headers.get("authorization", "")
        if not auth:
            return False
        if self.args.auth == "basic":
            expect = "Basic " + base64.b64encode(
                f"{self.args.user}:{self.args.pass_}".encode()).decode()
            return auth.strip() == expect
        if self.args.auth == "digest":
            m = re.search(r'response="([^"]+)"', auth)
            if not m:
                return False
            given = m.group(1)
            ha1 = hashlib.md5(
                f"{self.args.user}:{'FakeCam'}:{self.args.pass_}".encode()).hexdigest()
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
            qop = re.search(r'qop=([a-z-]+)', auth)
            if qop:
                nc = re.search(r'nc=([0-9a-f]+)', auth).group(1)
                cnonce = re.search(r'cnonce="([^"]*)"', auth).group(1)
                resp = hashlib.md5(f"{ha1}:{self.nonce}:{nc}:{cnonce}:{qop.group(1)}:{ha2}".encode()).hexdigest()
            else:
                resp = hashlib.md5(f"{ha1}:{self.nonce}:{ha2}".encode()).hexdigest()
            return resp == given
        return True  # none

    def challenge(self):
        if self.args.auth == "basic":
            return 'Basic realm="FakeCam"'
        return f'Digest realm="FakeCam", nonce="{self.nonce}", qop="auth"'

    # ---- RTSP ----

    def read_request(self):
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                chunk = self.sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return parts[0].upper(), parts[1] if len(parts) > 1 else "", headers, rest

    def respond(self, status, cseq, extra="", body=b"", reason=None):
        reason = reason or ({200: "OK", 401: "Unauthorized", 501: "Not Implemented"}.get(status, "??"))
        head = f"RTSP/1.0 {status} {reason}\r\nCSeq: {cseq}\r\n"
        if status == 401:
            head += f"WWW-Authenticate: {self.challenge()}\r\n"
        if body:
            head += f"Content-Length: {len(body)}\r\n"
        head += extra + "\r\n"
        self.sock.sendall(head.encode("latin-1") + body)

    def interleaved(self, payload, channel=0, marker=False):
        # Interleaved frame: '$' | channel(1) | length(2 BE) | RTP packet.
        # RTP: V=2 P=0 X=0 CC=0 | M PT | seq(2) | ts(4) | ssrc(4)
        self.rtp_seq += 1
        rtp = struct.pack(">BBHII", 0x80, (0x80 if marker else 0) | (self.pt & 0x7F),
                          self.rtp_seq & 0xFFFF, self.ts, SSRC) + payload
        frame = b"$" + bytes([channel]) + struct.pack(">H", len(rtp)) + rtp
        self.sock.sendall(frame)

    # ---- stream loop (JPEG over RTP, RFC 2435) ----

    def stream_jpeg(self, jpeg: bytes):
        chunk = 320
        seq = 0
        ts = 0
        while self.playing.is_set():
            offset = 0
            i = 0
            while offset < len(jpeg):
                piece = jpeg[offset:offset + chunk]
                offset += len(piece)
                last = offset >= len(jpeg)
                # RTP/JPEG header: spec(1) fragoff(3) type(1) Q(1) w/8(1) h/8(1)
                h = bytes([0, 0, (i >> 8) & 0xFF, i & 0xFF, 0, 0, 64 // 8, 48 // 8])
                h += piece
                i += len(piece)
                self.interleaved(h, marker=last)
                time.sleep(0.001)
            ts += int(90000 * 0.04)
            self.ts = ts
            time.sleep(max(0.035, 0.04 - time.time() % 1))
            # coarse pacing ~25fps

    def stream_hevc(self, nals):
        # Loop the NAL list (VPS/SPS/PPS ride before each IDR, as cameras do).
        # NALs bigger than fu_chunk bytes are sent as RFC 7798 FU-A fragments.
        gop = 0
        while self.playing.is_set():
            t0 = time.time()
            ts_base = gop * int(90000 * 0.04 * 8)
            ts = ts_base
            for i, nal in enumerate(nals):
                if not self.playing.is_set():
                    return
                last_of_list = i == len(nals) - 1
                for pkt, frag_last in self.fragment_hevc(nal):
                    self.ts = ts
                    self.interleaved(pkt, marker=last_of_list and frag_last)
                    ts += 90000 // 25 // 4
                    time.sleep(0.0003)
                ts += 90000 // 25
            gop += 1
            time.sleep(max(0.0, 0.3 - (time.time() - t0)))

    def fragment_hevc(self, nal):
        if len(nal) <= self.fu_chunk:
            yield bytes(nal), True
            return
        # RFC 7798: fixed FU octets — 0x7C on the start fragment, 0x1C on
        # every following fragment. The H.265 NAL type is a 6-bit field at
        # bits [6:1] of the first byte.
        body = nal[1:]
        nalu_type = (nal[0] >> 1) & 0x3F
        i = 0
        n = 0
        while i < len(body):
            piece = body[i:i + self.fu_chunk]
            i += len(piece)
            last = i >= len(body)
            indicator = 0x7C if n == 0 else 0x1C
            fu_header = ((0x80 if n == 0 else 0) | (0x40 if last else 0)) | nalu_type
            yield bytes([indicator, fu_header]) + piece, last
            n += 1

    def run(self):
        self.rtp_seq = 0
        self.ts = 0
        self.pt = 26
        self.fu_chunk = 128
        jpeg = open(self.args.media, "rb").read() if self.args.media else None
        hevc_nals = []
        if self.args.hevc_nals:
            with open(self.args.hevc_nals) as f:
                hevc_nals = [bytes.fromhex(line.strip()) for line in f if line.strip()]
            self.pt = 96
        log(f"client connected; pt={self.pt} hevc_nals={len(hevc_nals)}")
        try:
            with self.sock:
                self._handle(jpeg, hevc_nals)
        finally:
            self._ACTIVE.discard(self)
            self.playing.clear()

    def _handle(self, jpeg, hevc_nals):
        while self.running:
                req = self.read_request()
                if req is None:
                    break
                method, uri, headers, _rest = req
                cseq = int(headers.get("cseq", "0"))
                if not self.authed and self.args.auth != "none":
                    if self.check_auth(method, uri, headers):
                        self.authed = True
                        log(f"auth OK ({self.args.auth})")
                    else:
                        self.respond(401, cseq)
                        continue
                if method == "DESCRIBE":
                    if hevc_nals:
                        sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=FakeCam\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
                               "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n"
                               "a=control:trackID=0\r\n").encode()
                    else:
                        sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=FakeCam\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
                               "m=video 0 RTP/AVP 26\r\na=rtpmap:26 JPEG/90000\r\n"
                               "a=control:trackID=0\r\n").encode()
                    self.respond(200, cseq, "Content-Type: application/sdp\r\n", body=sdp)
                elif method == "SETUP":
                    self.respond(200, cseq, f"Session: {self.session}\r\n")
                elif method == "PLAY":
                    self.playing.set()
                    self.respond(200, cseq)
                    if hevc_nals:
                        self.stream_hevc(hevc_nals)
                    elif jpeg:
                        self.stream_jpeg(jpeg)
                elif method == "TEARDOWN":
                    self.respond(200, cseq)
                    self.playing.clear()
                    self.running = False
                    break
                elif method == "OPTIONS":
                    self.respond(200, cseq,
                                 extra="Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n")
                elif method == "GET_PARAMETER":
                    self.respond(200, cseq)
                else:
                    self.respond(501, cseq)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def shutdown_request(self, request):
        # No-op: the ClientHandler thread owns the socket and closes it itself.
        # The default close races with (and beats) the handler on first use.
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--media", default=None, help="JPEG file to serve")
    p.add_argument("--hevc-nals", default=None,
                   help="file with one HEX-encoded H.265 NAL unit per line; served as an RTP/H265 loop")
    p.add_argument("--auth", default="digest", choices=["none", "basic", "digest"])
    p.add_argument("--user", default="admin")
    p.add_argument("--pass", dest="pass_", default="secret")
    args = p.parse_args()

    srv = Server(("0.0.0.0", args.port), None)
    def make_handler(sock, addr, srv_):
        h = ClientHandler(sock, args)
        h.start()  # ClientHandler IS the thread; socketserver never starts it otherwise
        return h

    srv.RequestHandlerClass = make_handler
    real_port = srv.socket.getsockname()[1]
    log(f"ready 127.0.0.1:{real_port} auth={args.auth}")
    print(f"READY {real_port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

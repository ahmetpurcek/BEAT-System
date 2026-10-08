#!/usr/bin/env python3
"""BEAT kamera testbedi - basit MJPEG-over-HTTP sahte kamera sunucusu.

ffmpeg ile uretilen test deseni MJPEG'e kodlanir ve multipart/x-mixed-replace
olarak HTTP uzerinden yayinlanir. Gercek IP kameralarin /video veya
/stream.mjpg uclarini taklit eder.

Kullanim:
    python3 mjpeg_server.py [PORT] [WxH] [DESEN]
Ornek:
    python3 mjpeg_server.py 8090 640x360 testsrc2
"""
import http.server
import socketserver
import subprocess
import sys

BOUNDARY = b"--boundarydonotcross"


def ffmpeg_cmd(port_unused, size, pattern):
    return [
        "ffmpeg", "-loglevel", "error", "-re",
        "-f", "lavfi", "-i", f"{pattern}=size={size}:rate=12",
        "-c:v", "mjpeg", "-q:v", "7",
        "-f", "mjpeg", "pipe:1",
    ]


class Handler(http.server.BaseHTTPRequestHandler):
    size = "640x360"
    pattern = "testsrc2"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path not in ("/", "/stream.mjpg", "/video", "/mjpg/video.mjpg"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "multipart/x-mixed-replace; boundary=boundarydonotcross",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        proc = subprocess.Popen(
            ffmpeg_cmd(0, self.size, self.pattern),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        buf = b""
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                buf += chunk
                while True:
                    start = buf.find(b"\xff\xd8")
                    if start < 0:
                        buf = b""
                        break
                    end = buf.find(b"\xff\xd9", start + 2)
                    if end < 0:
                        buf = buf[start:]
                        break
                    jpg = buf[start:end + 2]
                    buf = buf[end + 2:]
                    header = (
                        BOUNDARY
                        + b"\r\nContent-Type: image/jpeg\r\nContent-Length: "
                        + str(len(jpg)).encode()
                        + b"\r\n\r\n"
                    )
                    self.wfile.write(header + jpg + b"\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.kill()
            except Exception:
                pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    size = sys.argv[2] if len(sys.argv) > 2 else "640x360"
    pattern = sys.argv[3] if len(sys.argv) > 3 else "testsrc2"

    Handler.size = size
    Handler.pattern = pattern

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        f"[mjpeg] http://0.0.0.0:{port}/stream.mjpg  ({size}, {pattern})",
        flush=True,
    )
    srv.serve_forever()


if __name__ == "__main__":
    main()

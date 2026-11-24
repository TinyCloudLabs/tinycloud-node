#!/usr/bin/env python3
"""TC-4249: no-Docker check of the ingress request-header capacity.

Runs a source-built nginx (SSL and HTTP/2 modules) with `header-buffers.conf`
loaded in the http{} context, as the wrapper image does, in front of a loopback
upstream that records the size of the largest header line it received. A
single header line of 93 KB (a delegation of ~140 keys) and 200 KB must reach
the upstream over HTTP/1.1 (and a 60 KB line over HTTP/2); 280 KB (over the 256 KB buffer) must be refused with 400 before
it reaches the upstream. The server block here is minimal, not the one the pinned
image's entrypoint generates: `test-redacted-logging.sh` covers that one under
Docker in CI.

Usage:
  deploy/ingress/test-header-buffers.py --nginx /path/to/nginx [--conf FILE]
  --conf  the drop-in to test (default: header-buffers.conf next to this file);
          pass a file holding `large_client_header_buffers 4 32k;` to reproduce
          the former limit (the 93 KB and 200 KB cases then fail).
"""
import argparse
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

CASES = ((93_000, 200), (200_000, 200), (280_000, 400))
H2_SIZE = 60_000


def raw_status(ctx, port, size):
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="x") as conn:
        conn.settimeout(20)
        conn.sendall(b"GET /delegate HTTP/1.1\r\nHost: x\r\nX-Large: " + b"a" * size
                     + b"\r\nConnection: close\r\n\r\n")
        try:
            return conn.recv(64).split(b" ")[1].decode()
        except (IndexError, OSError):
            return "none"


def check(label, got, want, reached, failures):
    ok = got == str(want) and reached == (want == 200)
    print(f"{'ok  ' if ok else 'FAIL'} {label}: status {got} (want {want}), reached upstream: {reached}")
    if not ok:
        failures.append(label)


def upstream(sock, seen):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0]
            seen.append(max((len(line) for line in head.split(b"\r\n")), default=0))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--conf", default=str(Path(__file__).with_name("header-buffers.conf")))
    args = parser.parse_args()

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-keyout", str(root / "k.pem"), "-out", str(root / "c.pem")],
            check=True, capture_output=True)
        up = socket.socket()
        up.bind(("127.0.0.1", 0))
        up.listen(16)
        seen = []
        threading.Thread(target=upstream, args=(up, seen), daemon=True).start()
        port = free_port()
        conf = root / "nginx.conf"
        conf.write_text(f"""
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{}}
http {{
    access_log off;
    client_body_temp_path {root}/b; proxy_temp_path {root}/p;
    fastcgi_temp_path {root}/f; uwsgi_temp_path {root}/u; scgi_temp_path {root}/s;
    include {args.conf};
    server {{
        listen 127.0.0.1:{port} ssl http2;
        ssl_certificate {root}/c.pem;
        ssl_certificate_key {root}/k.pem;
        location / {{ proxy_pass http://127.0.0.1:{up.getsockname()[1]}; }}
    }}
}}
""")
        proc = subprocess.Popen([args.nginx, "-p", str(root), "-c", str(conf)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(50):
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        break
                threading.Event().wait(0.1)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # HTTP/1.1 over TLS, written raw: curl cannot send header lines this large.
            for size, want in CASES:
                before = len(seen)
                got = raw_status(ctx, port, size)
                check(f"HTTP/1.1 {size} B header line", got, want, len(seen) > before, failures)
            # HTTP/2 shares the same buffers (nginx >= 1.19.7). curl's nghttp2 caps an
            # outbound header block at 64 KiB, so only a smaller line can be sent.
            header = root / "h"
            header.write_text("X-Large: " + "a" * H2_SIZE)
            before = len(seen)
            got = subprocess.run(
                ["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20",
                 "-H", f"@{header}", f"https://127.0.0.1:{port}/delegate"],
                capture_output=True, text=True).stdout
            check(f"HTTP/2 {H2_SIZE} B header line", got, 200, len(seen) > before, failures)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            up.close()
    if failures:
        print(f"{len(failures)} case(s) failed", file=sys.stderr)
        return 1
    print("PASS: 93 KB and 200 KB header lines reach the upstream; 280 KB gets 400")
    return 0


if __name__ == "__main__":
    sys.exit(main())

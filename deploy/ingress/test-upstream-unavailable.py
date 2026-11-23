#!/usr/bin/env python3
"""TC-3972: exercise the generated ingress against a disposable local upstream.

Default: build/run the wrapper with Docker (Linux host networking, as in CI).
No-Docker check: --nginx /path/to/nginx --entrypoint /path/to/image/entrypoint.sh
The latter uses the supplied entrypoint's actual setup_nginx_conf heredoc.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
BODY = b"Service temporarily unavailable.\n"
stream_release = threading.Event()
received_bodies = []


class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/hooks/events":
            self.send_response(200)
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Content-Length", "12")
            self.end_headers()
            self.wfile.write(b"first\n")
            self.wfile.flush()
            stream_release.wait(5)
            self.wfile.write(b"last!\n")
            return
        if self.path == "/timeout":
            time.sleep(2)
            return
        status = int(self.path[1:]) if self.path[1:].isdigit() else 200
        body = b"ok\n" if status == 200 else f"node response {status}\n".encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 503:
            self.send_header("Retry-After", "17")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        received_bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
        # Receive the whole synthetic write, then lose its response. No replay.
        self.close_connection = True


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx")
    parser.add_argument("--entrypoint", type=Path)
    args = parser.parse_args()
    if bool(args.nginx) != bool(args.entrypoint):
        parser.error("--nginx and --entrypoint must be supplied together")
    port, upstream_port = free_port(), free_port()
    name = "tc3972-" + uuid.uuid4().hex
    image = os.environ.get("IMAGE")
    built_image = not image and not args.nginx
    upstream = process = None
    failures = 0
    marker = uuid.uuid4().hex

    def check(label, condition):
        nonlocal failures
        failures += not condition
        print(f"{label}={'PASS' if condition else 'FAIL'}", flush=True)

    with tempfile.TemporaryDirectory(prefix="tc3972-") as directory:
        root = Path(directory)
        setup = '''
set -eo pipefail
source /scripts/functions.sh
mkdir -p "/etc/letsencrypt/live/$DOMAIN"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$DOMAIN" \\
    -keyout "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \\
    -out "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" 2>/dev/null
PROXY_CMD=proxy
eval "$(sed -n '/^setup_nginx_conf() {/,/^set_alias_record() {/p' /scripts/entrypoint.sh | sed '$d')"
setup_nginx_conf
exec nginx -g 'daemon off;'
'''
        environment = dict(os.environ, DOMAIN="ingress-test.local", PORT=str(port),
                           TARGET_ENDPOINT=f"http://127.0.0.1:{upstream_port}",
                           CLIENT_MAX_BODY_SIZE="95m", PROXY_READ_TIMEOUT="1s")
        try:
            if args.nginx:
                entrypoint = args.entrypoint.read_text()
                function = entrypoint.split("setup_nginx_conf() {", 1)[1].split("set_alias_record() {", 1)[0]
                function = "setup_nginx_conf() {" + function
                function = function.replace("/etc/letsencrypt", str(root / "certs"))
                function = function.replace("/etc/nginx/conf.d/default.conf", str(root / "server.conf"))
                generate = setup.split('eval "$(sed', 1)[0].replace("/etc/letsencrypt", str(root / "certs"))
                generate = generate.replace("source /scripts/functions.sh", 'cert_dir_name() { echo "$1"; }')
                generate += function + "\nsetup_nginx_conf\n"
                run("bash", "-c", generate, env=environment)
                server = (root / "server.conf").read_text().replace(
                    "/etc/nginx/tinycloud-upstream-unavailable.conf", str(HERE / "upstream-unavailable.conf"))
                (root / "server.conf").write_text(server)
                (root / "nginx.conf").write_text(f'''
worker_processes 1;
error_log stderr notice;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    include {HERE}/header-buffers.conf;
    include {HERE}/redacted-logging.conf;
    include {root}/server.conf;
}}
''')
                process = subprocess.Popen([args.nginx, "-p", directory + "/", "-c", str(root / "nginx.conf"),
                                            "-g", "daemon off;"], stdout=(root / "logs").open("wb"),
                                           stderr=subprocess.DEVNULL)
            else:
                if built_image:
                    image = name + ":test"
                    run("docker", "build", "-q", "-t", image, str(HERE))
                command = ["docker", "run", "-d", "--name", name, "--network", "host"]
                for key in ("DOMAIN", "PORT", "TARGET_ENDPOINT", "CLIENT_MAX_BODY_SIZE", "PROXY_READ_TIMEOUT"):
                    command += ["-e", key + "=" + environment[key]]
                run(*command, "--entrypoint", "/bin/bash", image, "-c", setup)

            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("ingress did not start")
                    time.sleep(0.05)

            def request(path, *extra):
                result = subprocess.run(["curl", "-sk", "--max-time", "5", "-D", str(root / "headers"),
                                         "-o", str(root / "body"), "-w", "%{http_code}",
                                         *extra, f"https://127.0.0.1:{port}{path}"],
                                        capture_output=True, check=True)
                headers = (root / "headers").read_text().lower()
                return int(result.stdout), headers, (root / "body").read_bytes()

            status, headers, body = request("/info")
            print(f"upstream_down_status={status}")
            check("upstream_down", status == 503 and "retry-after: 5\n" in headers and body == BODY)
            upstream = http.server.ThreadingHTTPServer(("127.0.0.1", upstream_port), Upstream)
            threading.Thread(target=upstream.serve_forever, daemon=True).start()
            status, headers, body = request("/info")
            print(f"upstream_up_status={status}")
            check("upstream_up", status == 200 and body == b"ok\n" and "retry-after:" not in headers)
            for code in (401, 502, 503, 504):
                status, headers, body = request(f"/{code}")
                check(f"node_{code}_preserved", status == code and body == f"node response {code}\n".encode()
                      and (("retry-after: 17\n" in headers) if code == 503 else "retry-after:" not in headers))
            status, headers, body = request("/timeout")
            print(f"upstream_timeout_status={status}")
            check("upstream_timeout", status == 504 and "retry-after:" not in headers and body != BODY)
            status, headers, body = request("/invoke", "--data-binary", marker)
            print(f"response_lost_status={status}\nreceived_bodies={len(received_bodies)}")
            check("response_lost", status == 502 and body != BODY and "retry-after:" not in headers
                  and received_bodies == [marker.encode()])

            stream = subprocess.Popen(["curl", "-skN", "--max-time", "5",
                                       f"https://127.0.0.1:{port}/hooks/events"], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL)
            try:
                readable, _, _ = select.select([stream.stdout], [], [], 0.75)
                first = os.read(stream.stdout.fileno(), 6) if readable else b""
                stream_release.set()
                rest, _ = stream.communicate(timeout=5)
                check("stream_unbuffered", first == b"first\n" and rest == b"last!\n" and stream.returncode == 0)
            finally:
                stream_release.set()
                if stream.poll() is None:
                    stream.kill()
                    stream.wait()
            upstream.shutdown()
            upstream.server_close()
            upstream = None
            status, headers, body = request("/info")
            check("upstream_stopped", status == 503 and body == BODY and "retry-after: 5\n" in headers)
            logs = ((root / "logs").read_text() if args.nginx else subprocess.check_output(
                ["docker", "logs", name], stderr=subprocess.STDOUT).decode())
            records = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
            check("redacted_proxy_errors", marker not in logs and any(
                r["route"] == "/invoke" and r["status"] == 502 and r["upstream_status"] == "502"
                and r["upstream_connect_time"] != "-" for r in records) and any(
                r["route"] == "/info" and r["status"] == 503 and r["upstream_status"] == "502"
                and r["upstream_connect_time"] == "-" for r in records))
        finally:
            stream_release.set()
            if upstream:
                upstream.shutdown()
                upstream.server_close()
            if process:
                process.terminate()
                process.wait(timeout=5)
            if not args.nginx:
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if built_image:
                    subprocess.run(["docker", "image", "rm", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"failures={failures}")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())

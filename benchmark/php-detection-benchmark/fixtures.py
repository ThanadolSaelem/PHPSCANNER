"""Serve every benchmark case as a canned HTTP response on 127.0.0.1:<port>.

Harmless: it only returns the fixed strings in cases.py. It runs no PHP and
sends no payload anywhere. Bound to loopback only.
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cases import CASES

# loopback by default; a container sets FIXTURE_BIND=0.0.0.0 and the host maps
# the ports to 127.0.0.1 only (see docker-compose.yml)
HOST = os.environ.get("FIXTURE_BIND", "127.0.0.1")


def make_handler(resp):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self):
            body = resp["body"].encode("utf-8")
            self.send_response(resp["status"])
            sent_type = False
            for k, v in resp["headers"].items():
                self.send_header(k, v)
                if k.lower() == "content-type":
                    sent_type = True
            if not sent_type:
                self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            self._send()

        def do_HEAD(self):
            self._send()

        def log_message(self, *a):
            pass
    return H


def main():
    servers = []
    for c in CASES:
        srv = ThreadingHTTPServer((HOST, c["port"]), make_handler(c["response"]))
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append(srv)
    print(f"serving {len(servers)} fixtures on {HOST}:{CASES[0]['port']}-{CASES[-1]['port']}",
          flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    sys.exit(main())

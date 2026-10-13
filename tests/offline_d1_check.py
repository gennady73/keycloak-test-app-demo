"""Offline check of the issuer/hostname incident replay (D1) with a throwaway local server.
The server answers on one port but advertises another one in its discovery document, which is what a
proxy that hides the real port (or a wrong KC_HOSTNAME) does."""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import kc_phase0 as k

ADVERTISED = 18466
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        iss = "http://127.0.0.1:%d/realms/r" % ADVERTISED
        if self.path.endswith("/.well-known/openid-configuration"):
            body = json.dumps({"issuer": iss, "authorization_endpoint": iss + "/auth", "token_endpoint": iss + "/token"}).encode()
            self.send_response(200)
        else:
            body = b"{}"; self.send_response(404)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

def run(advertised):
    global ADVERTISED
    ADVERTISED = advertised
    srv = HTTPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
    if advertised == 0: ADVERTISED = port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    http = k.Http(None, 5) if hasattr(k, "Http") else None
    res = k.audit_route(http, "external", "http://127.0.0.1:%d" % port, "r")
    srv.shutdown()
    return [f["rule"] for f in res["findings"] if f["rule"] == "D1"]

bad = run(18466); good = run(0)
print("mismatched issuer -> D1 findings:", len(bad)); print("matching issuer   -> D1 findings:", len(good))
sys.exit(0 if bad and not good else 1)

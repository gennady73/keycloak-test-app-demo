"""Stand-in SAML service provider for testing the login driver only (no SAML library, no real assertion).
  python tests/fake_saml_sp.py <port> <mock-issuer-url>"""
import base64, json, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
PORT, ISS = int(sys.argv[1]), sys.argv[2]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/start"):
            q = urllib.parse.urlencode({"SAMLRequest": base64.b64encode(("http://127.0.0.1:%d/acs" % PORT).encode()).decode(), "RelayState": "r1"})
            self.send_response(302); self.send_header("Location", "/go?" + q); self.end_headers()   # relative, via an own page
        elif self.path.startswith("/go"):
            self.send_response(302); self.send_header("Location", ISS + "/protocol/saml?" + self.path.split("?", 1)[1]); self.end_headers()
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        f = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        b = json.dumps({"got_saml_response": "SAMLResponse" in f, "relay": f.get("RelayState", [""])[0]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
HTTPServer(("127.0.0.1", PORT), H).serve_forever()

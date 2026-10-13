#!/usr/bin/env python3
"""Control runner: authorization-code flow written with plain HTTP (no OIDC library). Same web contract as the
library runners: GET /start redirects to Keycloak, GET /callback returns the result JSON.
  F1 code flow with client secret, issuer check  F2 refresh_token grant  F4 sid / session_state formats
  RN_CLIENT_SECRET in the environment. Port on the command line."""
import argparse, json, os, secrets, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rn_common import Http, safe_claims, jwt_claims, shape, scrub

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=3100); ap.add_argument("--issuer", required=True)
ap.add_argument("--client-id", default="rn-plain"); ap.add_argument("--ca-bundle")
a = ap.parse_args()
SECRET = os.environ.get("RN_CLIENT_SECRET", "")
RED = "http://127.0.0.1:%d/callback" % a.port
kc = Http(a.ca_bundle)
state = {}


def result(code, st):
    checks, claims = [], {}
    try:
        s, _, raw = kc.post(a.issuer + "/protocol/openid-connect/token",
                            dict(grant_type="authorization_code", code=code, redirect_uri=RED, client_id=a.client_id, client_secret=SECRET))
        body = json.loads(raw)
        if s != 200:
            raise RuntimeError("token endpoint HTTP %s: %s" % (s, body.get("error")))
        idc = jwt_claims(body.get("id_token", ""))
        claims = {"id_token": safe_claims(idc), "access_token": safe_claims(body["access_token"])}
        checks.append(dict(id="F1", status="done", observed=dict(
            http_status=s, token_obtained=True, issuer_matches=idc.get("iss") == a.issuer, audience_ok=a.client_id in ([idc.get("aud")] if isinstance(idc.get("aud"), str) else idc.get("aud", [])),
            nonce_ok=idc.get("nonce") == st["nonce"], refresh_token_issued="refresh_token" in body)))
        checks.append(dict(id="F4", status="done", observed=dict(
            sid_format=shape(idc.get("sid")), session_state_format=shape(body.get("session_state")))))
        s2, _, raw2 = kc.post(a.issuer + "/protocol/openid-connect/token",
                              dict(grant_type="refresh_token", refresh_token=body.get("refresh_token", ""), client_id=a.client_id, client_secret=SECRET))
        checks.append(dict(id="F2", status="done", observed=dict(http_status=s2, refreshed=s2 == 200, new_refresh_token="refresh_token" in json.loads(raw2))))
    except Exception as e:  # noqa: BLE001
        checks.append(dict(id="F1", status="error", observed={}, error=str(e)))
    return dict(runner=dict(id="plain-http-code", language="python", library="(none, stdlib)", version=sys.version.split()[0]),
                checks=checks, claims=claims)


class H(BaseHTTPRequestHandler):
    def log_message(self, *x): pass

    def out(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/start":
            state.update(state=secrets.token_urlsafe(16), nonce=secrets.token_urlsafe(16))
            p = dict(response_type="code", client_id=a.client_id, redirect_uri=RED, scope="openid", state=state["state"], nonce=state["nonce"])
            if q.get("fresh"):
                p["prompt"] = "login"
            return self.out(302, headers=[("Location", a.issuer + "/protocol/openid-connect/auth?" + urllib.parse.urlencode(p))])
        if u.path == "/callback":
            if q.get("state", [""])[0] != state.get("state"):
                return self.out(400, b'{"error":"state mismatch"}')
            r = result(q.get("code", [""])[0], state)
            return self.out(200, json.dumps(scrub(r, [SECRET])).encode(), [("Content-Type", "application/json")])
        self.out(404)


HTTPServer(("127.0.0.1", a.port), H).serve_forever()

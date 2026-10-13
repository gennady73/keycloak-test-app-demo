"""Mock of the Keycloak endpoints the runners use (login form, token, discovery). Test use only.
  python tests/mock_oidc.py <port> <server-version>        e.g. 8470 26.6.4
Behaviour that follows the server version: wrong-password ROPC answers 401 before 26.6.2, 400 from it."""
import base64, json, posixpath, re, secrets, sys, time, uuid, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
PORT, VER = int(sys.argv[1]), sys.argv[2]
ISS = "http://127.0.0.1:%d/realms/fx-runner" % PORT
SECRETS = {"rn-plain": "rn-plain-secret", "rn-node": "rn-node-secret", "rn-flask": "rn-flask-secret", "rn-svc": "rn-svc-secret", "rn-ropc": "rn-ropc-secret"}
NEWER = tuple(int(x) for x in VER.split(".")) >= (26, 6, 2)
V = tuple(int(x) for x in VER.split('.'))
codes, refresh = {}, {}
newid = lambda: secrets.token_urlsafe(18) if NEWER else str(uuid.uuid4())   # 24 chars from 26.6.2


def path_status(p):
    """26.4.4+: '//' and '..' rejected; 26.4.9+: ';' rejected. Older servers normalise silently."""
    if V >= (26, 4, 4) and ('//' in p or '..' in p) or V >= (26, 4, 9) and ';' in p:
        return None
    return posixpath.normpath(re.sub(r';[^/]*', '', p))



def jwt(c):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return b({"alg": "RS256"}) + "." + b(c) + ".c2ln"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def out(self, code, body=b"", ctype="application/json", extra=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        norm = path_status(u.path)
        if norm is None:
            return self.out(400, "bad path", "text/plain")
        u = u._replace(path=norm)
        if u.path == "/realms/fx-runner/.well-known/openid-configuration":
            return self.out(200, {"issuer": ISS, "token_endpoint": ISS + "/protocol/openid-connect/token", "authorization_endpoint": ISS + "/protocol/openid-connect/auth",
                                  "userinfo_endpoint": ISS + "/protocol/openid-connect/userinfo", "jwks_uri": ISS + "/protocol/openid-connect/certs"})
        if u.path == "/realms/fx-runner/protocol/saml":
            k = uuid.uuid4().hex; codes[k] = dict(saml=base64.b64decode(q["SAMLRequest"][0]).decode(), relay=q.get("RelayState", [""])[0])
            act = ISS + "/login-actions/authenticate?session_code=%s&amp;execution=1" % k
            return self.out(200, '<html><form id="kc-form-login" action="%s" method="post"></form></html>' % act, "text/html")
        if u.path.endswith("/protocol/openid-connect/auth"):
            if q["client_id"][0] not in SECRETS:
                return self.out(400, "bad client", "text/plain")
            k = uuid.uuid4().hex; codes[k] = dict(q={a: b[0] for a, b in q.items()})
            act = ISS + "/login-actions/authenticate?session_code=%s&amp;execution=1" % k
            return self.out(200, '<html><form id="kc-form-login" onsubmit="x" action="%s" method="post"></form></html>' % act, "text/html")
        self.out(404, "nf", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); f = {a: b[0] for a, b in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        u = urllib.parse.urlparse(self.path); q = {a: b[0] for a, b in urllib.parse.parse_qs(u.query).items()}
        if u.path.endswith("/login-actions/authenticate"):
            s = codes.get(q.get("session_code"))
            if not s or f.get("username") != "rn-user" or f.get("password") != "rn-user-password":
                return self.out(200, "login failed", "text/html")
            if "saml" in s:
                return self.out(200, '<html><body onload="document.forms[0].submit()"><form method="post" action="%s"><input type="hidden" name="SAMLResponse" value="%s"/><input type="hidden" name="RelayState" value="%s"/></form></body></html>'
                                % (s["saml"], base64.b64encode(b"fake").decode(), s["relay"]), "text/html")
            code = uuid.uuid4().hex; codes[code] = s
            loc = s["q"]["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": s["q"]["state"], "session_state": newid()})
            return self.out(302, extra=[("Location", loc)])
        if not u.path.endswith("/protocol/openid-connect/token"):
            return self.out(404)
        cid, sec = f.get("client_id"), f.get("client_secret")
        if self.headers.get("Authorization", "").startswith("Basic "):
            cid, sec = base64.b64decode(self.headers["Authorization"][6:]).decode().split(":", 1)
            cid, sec = urllib.parse.unquote(cid), urllib.parse.unquote(sec)
        if SECRETS.get(cid) != sec:
            return self.out(401, {"error": "unauthorized_client"})
        g, now = f.get("grant_type"), int(time.time())
        base = {"iss": ISS, "iat": now, "exp": now + 300, "azp": cid}
        if g == "password":
            return self.out(400 if NEWER else 401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
        if g == "client_credentials":
            return self.out(200, {"access_token": jwt(dict(base, typ="Bearer", client_id=cid)), "token_type": "Bearer", "expires_in": 300})
        if g == "authorization_code":
            s = codes.pop(f.get("code"), None)
            if not s:
                return self.out(400, {"error": "invalid_grant"})
            sid = newid(); rt = uuid.uuid4().hex; refresh[rt] = (cid, sid, s["q"].get("nonce"))
            idt = dict(base, aud=cid, typ="ID", sub="u1", sid=sid, preferred_username="rn-user", nonce=s["q"].get("nonce"))
            return self.out(200, {"access_token": jwt(dict(base, aud="account", typ="Bearer", sid=sid, scope="openid")), "id_token": jwt(idt),
                                  "refresh_token": rt, "token_type": "Bearer", "session_state": sid, "expires_in": 300})
        if g == "refresh_token":
            r = refresh.pop(f.get("refresh_token"), None)
            if not r:
                return self.out(400, {"error": "invalid_grant"})
            rt = uuid.uuid4().hex; refresh[rt] = r
            return self.out(200, {"access_token": jwt(dict(base, sid=r[1])), "refresh_token": rt, "token_type": "Bearer"})
        self.out(400, {"error": "unsupported_grant_type"})


HTTPServer(("127.0.0.1", PORT), H).serve_forever()

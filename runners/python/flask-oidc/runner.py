#!/usr/bin/env python3
"""Runner: flask-oidc 2.4.0 (Authlib based).  FIRST DRAFT - written without being able to install the library.
Assumptions to confirm on the first real run (each is a one-line fix if wrong):
  * OIDC_CLIENT_SECRETS takes a path to a Google-style JSON file with a "web" object including "issuer"
  * the extension registers blueprint 'oidc_auth' with the callback at /authorize (the fx-runner realm allows
    http://127.0.0.1:3102/authorize as redirect URI)
  * after login the extension redirects back to the page that required it, and session['oidc_auth_token']
    holds the token response
Web contract: GET /start -> Keycloak (first call) or the result JSON (after login).
Arguments: --port --issuer --client-id ; secret from RN_CLIENT_SECRET ; CA from SSL_CERT_FILE / REQUESTS_CA_BUNDLE."""
import argparse, atexit, json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from rn_common import jwt_claims, safe_claims, shape

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=3102); ap.add_argument("--issuer", required=True)
ap.add_argument("--client-id", default="rn-flask"); ap.add_argument("--ca-bundle")
a = ap.parse_args()
iss, base = a.issuer.rstrip("/"), "http://127.0.0.1:%d" % a.port

from flask import Flask, jsonify, session           # noqa: E402
from flask_oidc import OpenIDConnect                # noqa: E402
import importlib.metadata as md                     # noqa: E402

# The library wants a file; keep it in a private temp dir for the lifetime of the process only.
fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd); os.chmod(path, 0o600)
oidc_url = iss + "/protocol/openid-connect"
json.dump({"web": {"client_id": a.client_id, "client_secret": os.environ.get("RN_CLIENT_SECRET", ""), "issuer": iss,
                   "auth_uri": oidc_url + "/auth", "token_uri": oidc_url + "/token", "userinfo_uri": oidc_url + "/userinfo",
                   "redirect_uris": [base + "/authorize"]}}, open(path, "w"))
atexit.register(lambda: os.path.exists(path) and os.remove(path))

app = Flask(__name__)
app.config.update(SECRET_KEY="runner-only", OIDC_CLIENT_SECRETS=path, OIDC_SCOPES=["openid"], SERVER_NAME=None)
oidc = OpenIDConnect(app)


@app.route("/start")
@oidc.require_login
def start():
    checks, claims = [], {}
    tok = session.get("oidc_auth_token") or {}
    idc = tok.get("userinfo") or jwt_claims(tok.get("id_token", ""))
    claims["id_token"] = safe_claims(idc)
    claims["access_token"] = safe_claims(tok.get("access_token", ""))
    aud = idc.get("aud", [])
    aud = [aud] if isinstance(aud, str) else aud
    checks.append(dict(id="F1", status="done", observed=dict(
        token_obtained=bool(tok.get("access_token")), id_token_present=bool(tok.get("id_token") or tok.get("userinfo")),
        issuer_matches=idc.get("iss") == iss, audience_ok=a.client_id in aud, refresh_token_issued=bool(tok.get("refresh_token")))))
    checks.append(dict(id="F4", status="done", observed=dict(sid_format=shape(idc.get("sid")), session_state_format=shape(tok.get("session_state")))))
    checks.append(dict(id="F2", status="skipped", observed={}, error="first draft: flask-oidc refreshes inside require_login; no explicit refresh call is made yet"))
    return jsonify(runner=dict(id="flask-oidc", language="python", library="flask-oidc", version=md.version("flask-oidc")), checks=checks, claims=claims)


app.run(host="127.0.0.1", port=a.port)

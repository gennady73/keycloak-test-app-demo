#!/usr/bin/env python3
"""Shared helpers for the runner framework. Python 3.8+, standard library only.

Runner contract (what every runner prints / returns as JSON):
  {"runner": {"id","language","library","version"},
   "checks": [{"id": "F1", "status": "done|error|skipped", "observed": {...}, "error": "text"}],
   "claims": {"id_token": {...}, "access_token": {...}, "userinfo": {...}}}      # optional, raw
The orchestrator - not the runner - redacts: only allowlisted claims survive, secrets and JWT-shaped strings
are removed. A runner can therefore not leak by forgetting to filter.
"""
import base64, html, json, re, ssl, urllib.error, urllib.parse, urllib.request
from urllib.parse import urljoin
from http.cookiejar import CookieJar

CLAIM_ALLOWLIST = {"iss", "aud", "azp", "typ", "exp", "iat", "auth_time", "acr", "scope", "client_id", "token_type",
                   "nonce_present", "sid_format", "session_state_format", "has_sub", "preferred_username_present"}
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def vtuple(s):
    out = []
    for p in str(s or "0").replace("-", ".").split(".")[:3]:
        out.append(int(p) if p.isdigit() else 0)
    return tuple(out + [0] * (3 - len(out)))


def jwt_claims(tok):
    """Decode WITHOUT verifying; only used to look at claim shapes."""
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:  # noqa: BLE001
        return {}


def shape(v):
    """Describe the format of an opaque id without keeping it."""
    if v is None:
        return "absent"
    s = str(v)
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s):
        return "uuid"
    if re.fullmatch(r"[0-9a-f]{32}", s):
        return "hex32"
    if re.fullmatch(r"[A-Za-z0-9_-]{24}", s):
        return "base64-24"
    return "other(len=%d)" % len(s)


def safe_claims(tok_or_claims):
    c = jwt_claims(tok_or_claims) if isinstance(tok_or_claims, str) else dict(tok_or_claims or {})
    out = {k: c[k] for k in CLAIM_ALLOWLIST if k in c}
    out["has_sub"] = "sub" in c
    out["preferred_username_present"] = "preferred_username" in c
    if "sid" in c:
        out["sid_format"] = shape(c["sid"])
    if "session_state" in c:
        out["session_state_format"] = shape(c["session_state"])
    if "nonce" in c:
        out["nonce_present"] = True
    return out


def scrub(obj, secrets=()):
    """Remove JWT-shaped strings and known secret values from any JSON-like structure."""
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, secrets) for v in obj]
    if isinstance(obj, str):
        s = JWT_RE.sub("<jwt-removed>", obj)
        for sec in secrets:
            if sec:
                s = s.replace(sec, "<secret-removed>")
        return s
    return obj


class Http:
    """urllib wrapper: optional CA bundle, cookies, no automatic redirects."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    def __init__(self, ca_bundle=None, timeout=15):
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
        self.jar = CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                              urllib.request.HTTPCookieProcessor(self.jar), self._NoRedirect)
        self.timeout = timeout

    def req(self, method, url, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        r = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            resp = self.op.open(r, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp = e
        raw = resp.read()
        return resp.status if hasattr(resp, "status") else resp.code, {k.title(): v for k, v in resp.headers.items()}, raw

    def get(self, url, **k):
        return self.req("GET", url, **k)

    def post(self, url, data=None, **k):
        return self.req("POST", url, data=data, **k)


def drive_login(runner_base, user, password, ca_bundle=None, fresh=True, start_path="/start"):
    """Unattended browser stand-in. Calls <runner>/start (expects a redirect to Keycloak), submits the Keycloak
    login form with the test user, then hands the redirect back to the runner callback and returns its JSON.
    The runner keeps its own session cookie, exactly as a browser would carry it."""
    kc, runner = Http(ca_bundle), Http(None)
    st, hd, _b = runner.get(runner_base + start_path + ("?fresh=1" if fresh else ""))
    for _ in range(5):          # a library may bounce through one of its own pages before it points at Keycloak
        if st in (301, 302, 303, 307) and hd.get("Location") and urljoin(runner_base + "/", hd["Location"]).startswith(runner_base):
            st, hd, _b = runner.get(urljoin(runner_base + "/", hd["Location"]))   # Location may be relative (flask-oidc: /login?next=...)
    if st not in (301, 302, 303, 307) or "Location" not in hd:
        raise RuntimeError("runner /start did not redirect (HTTP %s): %s" % (st, (_b or b"")[:300].decode("utf-8", "replace")))
    url = hd["Location"]
    st, hd, body = kc.get(url)
    if st != 200:
        raise RuntimeError("authorization endpoint answered HTTP %s" % st)
    m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', body.decode("utf-8", "replace")) or \
        re.search(r'<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"', body.decode("utf-8", "replace"))
    if not m:
        raise RuntimeError("login form not found (theme changed, or an existing session / required action?)")
    action = html.unescape(m.group(1))
    st, hd, page = kc.post(action, {"username": user, "password": password, "credentialId": ""})
    if st == 200 and b"SAMLResponse" in page:     # SAML: Keycloak answers with an auto-submitting form, not a redirect
        text = page.decode("utf-8", "replace")
        fm = re.search(r'<form[^>]*action="([^"]+)"', text)
        fields = {n: html.unescape(v) for n, v in re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', text)}
        if not fm or "SAMLResponse" not in fields:
            raise RuntimeError("SAML response form not understood")
        target = html.unescape(fm.group(1))
        if not target.startswith(runner_base):
            raise RuntimeError("SAML response addressed to %s, not to the runner (ACS URL mismatch?)" % target)
        st, hd, body = runner.post(target, fields)
        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeError("runner ACS returned HTTP %s, not JSON" % st)
    if st not in (302, 303) or "Location" not in hd:
        raise RuntimeError("login did not redirect (HTTP %s): wrong credentials or a required action" % st)
    cb = urljoin(action, hd["Location"])
    if not cb.startswith(runner_base):
        raise RuntimeError("redirect went to %s, not to the runner (redirect URI mismatch?)" % cb.split("?")[0])
    st, hd, body = runner.get(cb)
    for _ in range(5):          # some libraries redirect once more (e.g. back to the page that asked for login)
        if st in (301, 302, 303, 307) and hd.get("Location") and urljoin(runner_base + "/", hd["Location"]).startswith(runner_base):
            st, hd, body = runner.get(urljoin(runner_base + "/", hd["Location"]))
    try:
        return json.loads(body)
    except ValueError:
        raise RuntimeError("runner callback returned HTTP %s, not JSON" % st)

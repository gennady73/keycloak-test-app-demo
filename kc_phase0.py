#!/usr/bin/env python3
"""
kc_phase0.py - read-only Keycloak/RHBK consumer-impact discovery (Phase 0).

Python 3.8+ standard library only. Makes only GET requests to the Admin API plus
one client-credentials token request. Never writes to Keycloak.

Sub-commands
  inventory   collect clients, lint them, audit discovery documents, write JSON + HTML
  diff        compare two inventory JSON files (DC-1 vs DC-2, staging vs production, 26.0 vs 26.6)

Secrets: the client secret is read from an environment variable or a file, never from
the command line. Only an allowlist of client fields is kept; secret-like attribute
values are replaced before anything is stored; a final scan refuses to write output
that still contains the secret or anything that looks like a JWT.
"""
import argparse
import base64
import datetime as dt
import html
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1"

# --------------------------------------------------------------------------------------
# Rules. Every rule carries the release that introduced it and the guide section, so a
# finding reads "what, since when, where documented". IDs match the design document §6.2.
# --------------------------------------------------------------------------------------
RULES = {
    "C4a": dict(sev="high", since="26.4.13", doc="UG26.4 §2.2.1; UG26.6 §2.5.1",
                title="Hostname wildcard in a redirect URI no longer works"),
    "C4b": dict(sev="medium", since="26.4.13", doc="UG26.4 §2.2.1; UG26.6 §2.5.1",
                title="'https://host*' is now treated as 'https://host/*'"),
    "C5": dict(sev="high", since="26.6.7", doc="UG26.6 §2.1.2",
               title="OIDC parameter (state/code/session_state) inside a registered redirect URI, or the compatibility attribute is set"),
    "C6": dict(sev="medium", since="26.6.2", doc="UG26.6 §2.6.4",
               title="'http' URL in a field that the secure-client-uris executor requires to be https"),
    "C7": dict(sev="medium", since="26.2", doc="UG26.2 §2.1.4",
               title="JWT client authentication: only a single audience accepted"),
    "C8": dict(sev="medium", since="26.2", doc="UG26.2 §2.1.6; UG26.6 §2.10.39",
               title="Standard token exchange enabled on this client"),
    "C10": dict(sev="medium", since="26.4.12", doc="UG26.4 §2.3.3; UG26.6 §2.6.10",
                title="Per-client compatibility switch (introspection/userinfo) present - deprecated"),
    "C11": dict(sev="medium", since="26.4.12", doc="UG26.4 §2.3.4; UG26.6 §2.6.11",
                title="Client issues lightweight access tokens: UserInfo rejects them (401)"),
    "C12": dict(sev="low", since="26.6.3", doc="UG26.6 §2.9.2",
                title="Web origin is not a plain origin; invalid Origin requests are rejected with 403"),
    "C15": dict(sev="info", since="26.6.2", doc="UG26.6 §2.10.29",
                title="Client authentication method inventory (enforced for newly registered clients)"),
    "C16": dict(sev="low", since="26.6.2", doc="UG26.6 §2.10.38",
                title="Direct access grants (ROPC) enabled: invalid_grant now returns HTTP 400 instead of 401"),
    "P1": dict(sev="info", since="-", doc="design §4",
               title="Public client: outside the confidential-client runner matrix, review manually"),
    "C21": dict(sev="info", since="26.4.12", doc="UG26.4 §2.3.1; UG26.6 §2.6.8",
                title="Identity-provider endpoint URL: the server no longer follows redirects"),
    "R6": dict(sev="info", since="26.6.2", doc="UG26.6 §2.6.4",
               title="secure-client-uris executor is (not) present in realm client policies"),
    "D1": dict(sev="high", since="26.2", doc="UG26.2 §2.1.1",
               title="Discovery document disagrees with the route it was fetched through"),
    "D2": dict(sev="high", since="26.4.2", doc="UG26.4 §2.15.12",
               title="Root /.well-known/oauth-authorization-server path not reachable through this route"),
    "H1": dict(sev="info", since="26.6.2", doc="UG26.6 §2.6.6",
               title="Readiness check result"),
}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Only these client fields are ever kept.
CLIENT_FIELDS = [
    "id", "clientId", "name", "protocol", "enabled", "publicClient", "bearerOnly",
    "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
    "serviceAccountsEnabled", "authorizationServicesEnabled", "frontchannelLogout",
    "clientAuthenticatorType", "rootUrl", "baseUrl", "adminUrl", "redirectUris",
    "webOrigins", "defaultClientScopes", "optionalClientScopes", "description",
]
SECRETISH = re.compile(r"secret|password|passwd|credential|jwks|cert|private|keystore|key$|\.key|token$|assertion",
                       re.I)
SAFE_KEY = re.compile(r"(exchange|lifespan|lifetime|timeout|\.enabled$|max\.age|method|algorithm|\.uris?$)", re.I)
# Keycloak's own clients: kept in the inventory, excluded from lint and totals.
BUILTIN = {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def vtuple(s):
    if not s:
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?", str(s))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------
# HTTP (GET only, plus the token POST)
# --------------------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Http:
    def __init__(self, ca_bundle=None, timeout=20):
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
        self.ctx, self.timeout = ctx, timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())

    def request(self, url, headers=None, data=None):
        """Returns (status, body_text, headers). Network errors -> (0, error text, {})."""
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            return e.code, body, dict(e.headers or {})
        except Exception as e:  # noqa: BLE001 - report, never crash an audit
            return 0, "%s: %s" % (type(e).__name__, e), {}


class Admin:
    def __init__(self, http, base, auth_realm, cid, secret):
        self.http, self.base = http, base.rstrip("/")
        self.auth_realm, self.cid, self.secret = auth_realm, cid, secret
        self.token = None
        self.access = []  # X1: (path, status)

    def login(self):
        url = "%s/realms/%s/protocol/openid-connect/token" % (self.base, self.auth_realm)
        body = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
        basic = base64.b64encode(("%s:%s" % (self.cid, self.secret)).encode()).decode()
        st, txt, _ = self.http.request(url, {"Authorization": "Basic " + basic,
                                              "Content-Type": "application/x-www-form-urlencoded"}, body)
        if st != 200:
            hint = ""
            if st == 401:
                hint = ("\nhint: client '%s' must exist in realm '%s' (--auth-realm) with Client authentication ON, "
                        "Service accounts roles ON, and this exact secret (Credentials tab)." % (self.cid, self.auth_realm))
            raise SystemExit("token request failed: HTTP %s %s%s" % (st, txt[:200].replace(self.secret, "***"), hint))
        self.token = json.loads(txt)["access_token"]

    def get(self, path, params=None, label=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        st, txt, _ = self.http.request(url, {"Authorization": "Bearer " + self.token,
                                             "Accept": "application/json"})
        m = re.match(r"/admin/realms/([^/]+)", path)
        self.access.append({"call": (label or path) + (" [%s]" % m.group(1) if m else ""), "status": st})
        if st != 200:
            return None
        try:
            return json.loads(txt)
        except ValueError:
            return None

    def paged(self, path, label, page=100):
        out, first = [], 0
        while True:
            chunk = self.get(path, {"first": first, "max": page}, label)
            if chunk is None:
                return out if out else None
            out.extend(chunk)
            if len(chunk) < page:
                return out
            first += page


# --------------------------------------------------------------------------------------
# Redaction / extraction
# --------------------------------------------------------------------------------------
def clean_attr(key, val):
    s = "" if val is None else str(val)
    if s.lower() in ("true", "false") or re.fullmatch(r"-?\d{1,9}", s):
        return s
    if SECRETISH.search(key) and not SAFE_KEY.search(key):
        return "[redacted]"
    if len(s) > 400 or JWT_RE.search(s):
        return "[redacted: long/opaque value]"
    return s


def extract_client(c):
    out = {k: c.get(k) for k in CLIENT_FIELDS if k in c}
    for k in ("redirectUris", "webOrigins"):
        if k in out:
            out[k] = [x for x in (out[k] or []) if x and x.strip()]   # console stores [""] for "no value"
    out["builtin"] = c.get("clientId") in BUILTIN or str(c.get("clientId", "")).endswith("-realm")
    attrs = c.get("attributes") or {}
    out["attributes"] = {k: clean_attr(k, v) for k, v in sorted(attrs.items())}
    return out


# --------------------------------------------------------------------------------------
# Lint (L1)
# --------------------------------------------------------------------------------------
def finding(rule, client, detail, evidence=None):
    r = RULES[rule]
    return dict(rule=rule, severity=r["sev"], introduced_in=r["since"], doc=r["doc"],
                title=r["title"], client=client, detail=detail, evidence=evidence)


def split_uris(v):
    return [u for u in re.split(r"##", v or "") if u]


def lint_client(c, secure_uris_executor):
    cid = c.get("clientId")
    f = []
    a = c.get("attributes", {})
    is_oidc = (c.get("protocol") or "openid-connect") == "openid-connect"
    redirects = list(c.get("redirectUris") or [])
    post_logout = split_uris(a.get("post.logout.redirect.uris"))

    for u in redirects + post_logout:
        m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", u)
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/*]+\*$", u):
            # 'https://host*' - wildcard directly after the host, no '/' in between
            f.append(finding("C4b", cid, "wildcard directly after host", u))
        elif m and "*" in m.group(2):
            f.append(finding("C4a", cid, "wildcard in host part", u))
        q = urllib.parse.urlsplit(u.replace("*", "x")).query
        params = {p.split("=")[0] for p in q.split("&") if p}
        hit = params & {"state", "code", "session_state"}
        if hit:
            f.append(finding("C5", cid, "parameter(s) %s in registered URI" % ",".join(sorted(hit)), u))
    if a.get("allow.oidc.params.in.redirect.uris") is not None:
        f.append(finding("C5", cid, "attribute allow.oidc.params.in.redirect.uris=%s (deprecated, removed in 27)"
                         % a["allow.oidc.params.in.redirect.uris"]))

    # C6: only meaningful where the executor is used; report with that qualifier.
    https_fields = [("post.logout.redirect.uris", u) for u in post_logout]
    for k in ("logoUri", "policyUri", "tosUri"):
        if a.get(k):
            https_fields.append((k, a[k]))
    for k, u in https_fields:
        if u.lower().startswith("http://"):
            q = {True: "executor present in realm policies", False: "executor not found in realm policies",
                 None: "executor presence unknown (policies not readable)"}[secure_uris_executor]
            f.append(finding("C6", cid, "%s uses http (%s)" % (k, q), u))

    ca = c.get("clientAuthenticatorType")
    if ca in ("client-jwt", "client-secret-jwt"):
        f.append(finding("C7", cid, "clientAuthenticatorType=%s" % ca))
    for k, v in a.items():
        if re.search(r"token\.exchange", k, re.I) and str(v).lower() == "true":
            extra = " on a PUBLIC client (not supported)" if c.get("publicClient") else ""
            f.append(finding("C8", cid, "%s=true%s" % (k, extra)))
        if re.search(r"(introspection|userinfo).*(compat|lightweight|allow)|(compat).*(introspection|userinfo)", k, re.I):
            f.append(finding("C10", cid, "%s=%s - verify against the guide; attribute name matched by pattern" % (k, v)))

    if str(a.get("client.use.lightweight.access.token.enabled", "")).lower() == "true":
        f.append(finding("C11", cid, "client.use.lightweight.access.token.enabled=true; fine unless a consumer calls UserInfo with this token"))

    for o in c.get("webOrigins") or []:
        if o in ("+", "*"):
            continue
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#*]+", o):
            f.append(finding("C12", cid, "web origin is not scheme://host[:port]", o))

    if is_oidc and c.get("directAccessGrantsEnabled"):
        f.append(finding("C16", cid, "directAccessGrantsEnabled=true"))
    if is_oidc and c.get("publicClient"):
        f.append(finding("P1", cid, "publicClient=true"))
    if is_oidc and not c.get("bearerOnly") and not c.get("publicClient"):
        m = a.get("token.endpoint.auth.method") or ca or "unset"
        f.append(finding("C15", cid, "authentication method: %s" % m))
    return f


def realm_secure_uris(adm, realm):
    """True only if an ENABLED client policy references a profile that contains the executor.
    (Global profiles ship with the executor but are inactive until a policy uses them.)"""
    prof = adm.get("/admin/realms/%s/client-policies/profiles" % realm, {"include-global-profiles": "true"},
                   "client-policies/profiles")
    pol = adm.get("/admin/realms/%s/client-policies/policies" % realm, None, "client-policies/policies")
    if prof is None or pol is None:
        return None
    with_exec = {p.get("name") for p in (prof.get("profiles") or []) + (prof.get("globalProfiles") or [])
                 if "secure-client-uris" in json.dumps(p)}
    return any(x.get("enabled", True) and set(x.get("profiles") or []) & with_exec
               for x in pol.get("policies") or [])


def idp_urls(adm, realm):
    idps = adm.get("/admin/realms/%s/identity-provider/instances" % realm, None, "identity-provider/instances")
    out = []
    for i in idps or []:
        cfg = i.get("config") or {}
        urls = {k: v for k, v in cfg.items()
                if re.search(r"(url|uri|issuer)$", k, re.I) and isinstance(v, str)}
        out.append({"alias": i.get("alias"), "providerId": i.get("providerId"), "urls": urls})
    return out


# --------------------------------------------------------------------------------------
# Discovery audit (D1/D2) and readiness (H1)
# --------------------------------------------------------------------------------------
def hostport(u):
    p = urllib.parse.urlsplit(u)
    port = p.port or {"https": 443, "http": 80}.get(p.scheme)
    return (p.scheme, p.hostname, port)


def audit_route(http, name, base, realm):
    base = base.rstrip("/")
    res = dict(route=name, base=base, realm=realm, findings=[])
    st, txt, _ = http.request("%s/realms/%s/.well-known/openid-configuration" % (base, realm))
    res["discovery_status"] = st
    if st == 200:
        try:
            doc = json.loads(txt)
            res["issuer"] = doc.get("issuer")
            ep = {k: doc.get(k) for k in ("authorization_endpoint", "token_endpoint", "jwks_uri",
                                          "userinfo_endpoint", "end_session_endpoint",
                                          "introspection_endpoint") if doc.get(k)}
            res["endpoints"] = ep
            if hostport(base) != hostport(doc.get("issuer", base)):
                res["findings"].append(finding("D1", name, "issuer %s differs from route %s (scheme/host/port)"
                                               % (doc.get("issuer"), base)))
            iss = hostport(doc.get("issuer", base))
            for k, v in ep.items():
                if hostport(v) != iss:
                    res["findings"].append(finding("D1", name, "%s points to %s:%s, issuer is %s:%s"
                                                   % (k, hostport(v)[1], hostport(v)[2], iss[1], iss[2]), v))
        except ValueError:
            res["findings"].append(finding("D1", name, "discovery document is not JSON"))
    else:
        res["findings"].append(finding("D1", name, "discovery document HTTP %s" % st))
    st2, _, _ = http.request("%s/.well-known/oauth-authorization-server/realms/%s" % (base, realm))
    res["rfc8414_status"] = st2
    if st2 != 200:
        res["findings"].append(finding("D2", name, "HTTP %s on /.well-known/oauth-authorization-server/realms/%s"
                                       % (st2, realm)))
    return res


def probe_ready(http, name, url):
    host = urllib.parse.urlsplit(url)
    port = host.port or (443 if host.scheme == "https" else 80)
    try:
        socket.create_connection((host.hostname, port), timeout=5).close()
        port_open = True
    except OSError:
        port_open = False
    st, _, _ = http.request(url)
    d = "port open: %s; /health/ready HTTP %s" % (port_open, st)
    return dict(route=name, url=url, port_open=port_open, ready_status=st,
                findings=[finding("H1", name, d)] if st != 200 else [],
                detail=d)


# --------------------------------------------------------------------------------------
# inventory command
# --------------------------------------------------------------------------------------
def cmd_inventory(a):
    secret = os.environ.get(a.secret_env, "")
    if a.secret_file:
        secret = open(a.secret_file, encoding="utf-8").read().strip()
    secret = secret.strip()
    if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in "\"'":
        print("note: stripped surrounding quotes from the secret (cmd.exe 'set X=\"v\"' keeps them)")
        secret = secret[1:-1]
    if not secret:
        raise SystemExit("no client secret: set $%s or use --secret-file" % a.secret_env)
    cid = a.client_id or os.environ.get("KC_CLIENT_ID")
    if not cid:
        raise SystemExit("no client id: use --client-id or $KC_CLIENT_ID")
    http = Http(a.ca_bundle)
    adm = Admin(http, a.base_url, a.auth_realm, cid, secret)
    adm.login()

    server_version = a.server_version
    si = adm.get("/admin/serverinfo", None, "serverinfo")
    if not server_version and si:
        server_version = (si.get("systemInfo") or {}).get("version")
    sv = vtuple(server_version)

    realms = a.realm
    if not realms:
        rl = adm.get("/admin/realms", None, "realms")
        realms = [r["realm"] for r in rl or [] if r["realm"] != "master"]
    if not realms:
        seen = [x for x in adm.access if x["call"] == "realms"]
        st = seen[-1]["status"] if seen else "?"
        if st == 403:
            raise SystemExit("cannot list realms: GET /admin/realms returned HTTP 403. The account '%s' has no role that "
                             "allows it. In the Service account roles tab assign view-realm and view-clients from the "
                             "'<realm>-realm' client of each realm to inspect, or pass --realm NAME (repeatable)." % cid)
        raise SystemExit("no realms to inspect: GET /admin/realms returned HTTP %s with %s realm(s) other than master. "
                         "Create a realm, or pass --realm master." % (st, len([r for r in rl or [] if r["realm"] != "master"])))

    inv = dict(tool="kc_phase0 %s" % VERSION, label=a.label, generated=now(), base_url=a.base_url,
               server_version=server_version, realms=[])
    for realm in realms:
        rinfo = adm.get("/admin/realms/%s" % realm, None, "realm")
        raw = adm.paged("/admin/realms/%s/clients" % realm, "clients")
        executor = realm_secure_uris(adm, realm)
        clients = []
        for c in raw or []:
            ec = extract_client(c)
            ec["findings"] = [] if ec["builtin"] else lint_client(ec, executor)
            for fd in ec["findings"]:
                t = vtuple(fd["introduced_in"])
                fd["present_on_server"] = None if (t is None or sv is None) else sv >= t
            clients.append(ec)
        inv["realms"].append(dict(
            realm=realm, readable=raw is not None, secure_client_uris_executor=executor,
            realm_attrs={k: (rinfo or {}).get(k) for k in ("sslRequired", "ssoSessionIdleTimeout",
                                                          "ssoSessionMaxLifespan", "rememberMe",
                                                          "revokeRefreshToken", "refreshTokenMaxReuse")},
            identity_providers=idp_urls(adm, realm), clients=clients))

    routes = {}
    for r in a.route or []:
        n, _, u = r.partition("=")
        routes[n] = u
    inv["discovery"] = [audit_route(http, n, u, realm) for n, u in routes.items() for realm in realms]
    for d in inv["discovery"]:
        for f in d["findings"]:
            t_ = vtuple(f["introduced_in"])
            f["present_on_server"] = None if (t_ is None or sv is None) else sv >= t_
            if f["rule"] == "D2" and f["present_on_server"] is False:
                f["severity"] = "info"
                f["detail"] += " (expected: this path exists from %s)" % f["introduced_in"]
    inv["readiness"] = [probe_ready(http, *h.partition("=")[::2]) for h in (a.health or [])]
    inv["read_access"] = adm.access  # X1
    inv["summary"] = summarize(inv)

    blob = json.dumps(inv)
    if secret in blob or JWT_RE.search(blob):
        raise SystemExit("REFUSING to write: output contains the secret or a JWT-like string. Report this as a bug.")
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.join(a.out, re.sub(r"[^A-Za-z0-9_.-]", "_", a.label))
    with open(stem + ".json", "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=2, ensure_ascii=False)
    with open(stem + ".html", "w", encoding="utf-8") as fh:
        fh.write(render_html(inv))
    s = inv["summary"]
    print("%s: %d of %d clients have findings (%d high, %d medium); discovery findings: %d"
          % (a.label, s["clients_with_findings"], s["clients_total"], s["by_severity"].get("high", 0),
             s["by_severity"].get("medium", 0), s["discovery_findings"]))
    print("wrote %s.json and %s.html" % (stem, stem))
    bad = [x for x in adm.access if x["status"] != 200]
    if bad:
        print("note: %d read calls were not HTTP 200 (see 'read_access'): %s"
              % (len(bad), ", ".join("%s=%s" % (b["call"], b["status"]) for b in bad)))


def summarize(inv):
    tot = with_f = 0
    sev = {}
    for r in inv["realms"]:
        for c in r["clients"]:
            if c.get("builtin"):
                continue
            tot += 1
            actionable = [f for f in c["findings"] if f["severity"] != "info"]
            if actionable:
                with_f += 1
            for f in actionable:
                sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    disc = sum(1 for d in inv.get("discovery", []) for f in d["findings"] if not (f["rule"] == "D2" and f.get("present_on_server") is False)) + \
        sum(len(h["findings"]) for h in inv.get("readiness", []))
    return dict(clients_total=tot, clients_with_findings=with_f, by_severity=sev, discovery_findings=disc)


# --------------------------------------------------------------------------------------
# HTML report (self-contained)
# --------------------------------------------------------------------------------------
def render_html(inv):
    e = html.escape
    s = inv["summary"]
    rows = []
    for r in inv["realms"]:
        for c in r["clients"]:
            fs = sorted(c["findings"], key=lambda x: SEV_ORDER[x["severity"]])
            for f in fs:
                p = {True: "yes", False: "<b>not yet</b>", None: "?"}[f.get("present_on_server")]
                rows.append("<tr class=%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                            "<td>%s</td><td><code>%s</code></td></tr>" % (
                                f["severity"], e(r["realm"]), e(str(c["clientId"])), e(f["severity"]),
                                e(f["rule"]), e(f["introduced_in"]) + " (on server: %s)" % p,
                                e(f["title"]), e(f["detail"] + " [" + f["doc"] + "]"), e(str(f.get("evidence") or ""))))
    disc = []
    for d in inv.get("discovery", []):
        disc.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(d["route"]), e(d["realm"]), e(str(d.get("issuer"))), e(str(d["discovery_status"])),
            e(str(d["rfc8414_status"]))))
        for f in d["findings"]:
            disc.append("<tr class=%s><td colspan=5>%s %s - %s <code>%s</code></td></tr>" % (
                f["severity"], e(f["rule"]), e(f["title"]), e(f["detail"]), e(str(f.get("evidence") or ""))))
    acc = "".join("<tr><td>%s</td><td>%s</td></tr>" % (e(x["call"]), x["status"]) for x in inv["read_access"])
    return """<!doctype html><meta charset=utf-8><title>%(l)s</title>
<style>body{font:14px system-ui,sans-serif;margin:24px}table{border-collapse:collapse;margin:8px 0 24px}
td,th{border:1px solid #bbb;padding:3px 8px;vertical-align:top;text-align:left}
.high{background:#fdd}.medium{background:#ffe9c4}.low{background:#fff7c4}.info{color:#555}</style>
<h1>%(l)s</h1><p>Server %(v)s, generated %(g)s. <b>%(w)d of %(t)d clients have findings</b>
(info-level inventory rows excluded). Discovery/readiness findings: %(d)d.</p>
<h2>Client findings</h2><table><tr><th>Realm<th>Client<th>Sev<th>Rule<th>Since<th>What<th>Detail<th>Evidence</tr>%(rows)s</table>
<h2>Discovery audit (D1/D2)</h2><table><tr><th>Route<th>Realm<th>Issuer<th>OIDC discovery<th>RFC 8414 root</tr>%(disc)s</table>
<h2>Read access of the inventory account (X1)</h2><table><tr><th>Call<th>HTTP</tr>%(acc)s</table>""" % dict(
        l=e(inv["label"]), v=e(str(inv["server_version"])), g=e(inv["generated"]), w=s["clients_with_findings"],
        t=s["clients_total"], d=s["discovery_findings"], rows="".join(rows), disc="".join(disc), acc=acc)


# --------------------------------------------------------------------------------------
# diff command
# --------------------------------------------------------------------------------------
def cmd_diff(a):
    A, B = (json.load(open(p, encoding="utf-8")) for p in (a.left, a.right))

    def idx(inv):
        return {(r["realm"], c["clientId"]): c for r in inv["realms"] for c in r["clients"]}
    ia, ib = idx(A), idx(B)
    print("LEFT  %s (server %s)\nRIGHT %s (server %s)\n" % (A["label"], A["server_version"],
                                                           B["label"], B["server_version"]))
    for k in sorted(set(ia) - set(ib)):
        print("only in LEFT : %s/%s" % k)
    for k in sorted(set(ib) - set(ia)):
        print("only in RIGHT: %s/%s" % k)
    n = 0
    for k in sorted(set(ia) & set(ib)):
        x, y = ia[k], ib[k]
        d = []
        for f in sorted((set(x) | set(y)) - {"findings", "id", "attributes"}):
            if x.get(f) != y.get(f):
                d.append("  %s: %r -> %r" % (f, x.get(f), y.get(f)))
        for f in sorted(set(x["attributes"]) | set(y["attributes"])):
            if x["attributes"].get(f) != y["attributes"].get(f):
                d.append("  attr %s: %r -> %r" % (f, x["attributes"].get(f), y["attributes"].get(f)))
        if d:
            n += 1
            print("%s/%s differs:" % k)
            print("\n".join(d))
    print("\n%d clients differ, %d only left, %d only right" % (n, len(set(ia) - set(ib)), len(set(ib) - set(ia))))


# --------------------------------------------------------------------------------------
# verify command: inventories vs expected results (fixture tests)
# --------------------------------------------------------------------------------------
def verify_inventories(invs, expected):
    """Returns list of (status, realm, client, message). status in PASS/FAIL/WARN."""
    out = []
    byrealm = {r["realm"]: (inv, r) for inv in invs for r in inv["realms"]}
    for realm, spec in expected["realms"].items():
        if realm not in byrealm:
            out.append(("FAIL", realm, "*", "realm missing from inventory (import or read access failed?)"))
            continue
        inv, r = byrealm[realm]
        sv = vtuple(inv.get("server_version"))
        got = {c["clientId"]: c for c in r["clients"] if not c.get("builtin")}
        for cid, rules in spec["clients"].items():
            if cid not in got:
                out.append(("FAIL", realm, cid, "client missing"))
                continue
            have = sorted({f["rule"] for f in got[cid]["findings"]})
            want = sorted(rules)
            msgs = []
            if have != want:
                msgs.append("rules %s != expected %s" % (have, want))
            for f in got[cid]["findings"]:
                t_ = vtuple(RULES[f["rule"]]["since"])
                if sv and t_:
                    exp_present = sv >= t_
                    if f.get("present_on_server") != exp_present:
                        msgs.append("%s present_on_server=%s, expected %s for server %s"
                                    % (f["rule"], f.get("present_on_server"), exp_present, inv["server_version"]))
            out.append(("FAIL" if msgs else "PASS", realm, cid, "; ".join(msgs) or "rules %s" % have))
        for cid in got:
            if cid not in spec["clients"]:
                out.append(("WARN", realm, cid, "client not in expected.json"))
    return out


def cmd_verify(a):
    invs = [json.load(open(p, encoding="utf-8")) for p in a.inventory]
    expected = json.load(open(a.expected, encoding="utf-8"))
    res = verify_inventories(invs, expected)
    for st, realm, cid, msg in res:
        print("%-4s %s/%s: %s" % (st, realm, cid, msg))
    fails = sum(1 for r in res if r[0] == "FAIL")
    print("\n%d passed, %d failed, %d warnings" % (sum(1 for r in res if r[0] == "PASS"), fails,
                                                  sum(1 for r in res if r[0] == "WARN")))
    sys.exit(1 if fails else 0)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("inventory")
    i.add_argument("--base-url", required=True, help="e.g. https://sso-staging.example.org (include /auth only if configured)")
    i.add_argument("--label", required=True, help="e.g. staging-26.6.6-dc1")
    i.add_argument("--realm", action="append", help="repeatable; default: all realms except master")
    i.add_argument("--auth-realm", default="master", help="realm that holds the inventory service account")
    i.add_argument("--client-id")
    i.add_argument("--secret-env", default="KC_CLIENT_SECRET")
    i.add_argument("--secret-file")
    i.add_argument("--ca-bundle", help="PEM file with your internal CA")
    i.add_argument("--server-version", help="override if serverinfo is not readable, e.g. 26.6.6")
    i.add_argument("--route", action="append", help="NAME=BASE_URL consumers use (repeatable) for D1/D2")
    i.add_argument("--health", action="append", help="NAME=URL of /health/ready (repeatable)")
    i.add_argument("--out", default="out")
    i.set_defaults(fn=cmd_inventory)
    d = sub.add_parser("diff")
    d.add_argument("left")
    d.add_argument("right")
    d.set_defaults(fn=cmd_diff)
    v = sub.add_parser("verify", help="compare inventory JSON file(s) with an expected-results file")
    v.add_argument("inventory", nargs="+")
    v.add_argument("--expected", required=True)
    v.set_defaults(fn=cmd_verify)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()

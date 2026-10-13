#!/usr/bin/env python3
"""Runner orchestrator. Starts each catalog runner, drives the login unattended, compares the result with the
expectation for the given server version, redacts, writes JSON + HTML.

  python runners/orchestrate.py --issuer https://192.0.2.10:8466/realms/fx-runner --server-version 26.6.4 \
         --ca-bundle certs/kc.crt --fixture-secrets --out out_runners
Real (non-fixture) secrets: leave --fixture-secrets off and export them per runner, e.g.\n  RN_CLIENT_SECRET__PASSPORT_OAUTH2, RN_CLIENT_SECRET__FLASK_OIDC, RN_SVC_SECRET, RN_ROPC_SECRET (plain RN_CLIENT_SECRET is the fallback)."""
import argparse, html, json, os, socket, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rn_common import vtuple, scrub, drive_login, safe_claims, CLAIM_ALLOWLIST


def rule_for(rules, ver):
    v = vtuple(ver)
    for r in rules:
        if ("min" not in r or v >= vtuple(r["min"])) and ("max" not in r or v <= vtuple(r["max"])):
            return r
    return None


def judge(check, exp, ver):
    """-> (verdict, detail). verdicts: matched | differs | recorded | error"""
    if check["status"] == "skipped":
        return "skipped", check.get("error", "")
    if check["status"] != "done":
        return "error", check.get("error", "no result")
    e = exp.get(check["id"])
    if not e or not e["rules"]:
        return "recorded", "no documented expectation yet"
    r = rule_for(e["rules"], ver)
    if not r:
        return "recorded", "no expectation for server %s" % ver
    obs = check["observed"]
    # a key the runner does not report at all (e.g. better-auth does not expose session_state) is "not observed", not a difference
    bad = ["%s: expected %r, got %r" % (k, v, obs[k]) for k, v in r["expect"].items() if k in obs and obs[k] != v]
    skipped = [k for k in r["expect"] if k not in obs]
    if bad:
        return "differs", "; ".join(bad)
    if skipped and len(skipped) == len(r["expect"]):
        return "recorded", "runner reports none of the expected values: " + ", ".join(skipped)
    return "matched", ("not reported by this runner: " + ", ".join(skipped)) if skipped else ""


def wait_port(port, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close(); return True
        except OSError:
            time.sleep(0.3)
    return False


def run_entry(ent, a, env_extra):
    cmd = [c.replace("{python}", sys.executable) for c in ent["cmd"]]
    if not os.path.isabs(cmd[-1]) and cmd[0] in (sys.executable, "node"):
        cmd[-1] = os.path.join(HERE, cmd[-1])
    env = dict(os.environ, **env_extra)
    if a.ca_bundle:   # each runtime reads its own variable
        ca = os.path.abspath(a.ca_bundle)
        env.update(NODE_EXTRA_CA_CERTS=ca, SSL_CERT_FILE=ca, REQUESTS_CA_BUNDLE=ca, CURL_CA_BUNDLE=ca)
    if ent["kind"] == "probe":
        c = cmd + ["--issuer", a.issuer] + (["--ca-bundle", a.ca_bundle] if a.ca_bundle else [])
        r = subprocess.run(c, env=env, text=True, capture_output=True, cwd=HERE, timeout=120)
        if r.returncode:
            raise RuntimeError("runner exited %s: %s" % (r.returncode, r.stderr.strip()[-300:]))
        return json.loads(r.stdout)
    c = cmd + ["--port", str(ent["port"]), "--issuer", a.issuer, "--client-id", ent["client_id"]] + (["--ca-bundle", a.ca_bundle] if a.ca_bundle else [])
    p = subprocess.Popen(c, env=env, cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        if not wait_port(ent["port"]):
            p.terminate(); raise RuntimeError("runner did not start: %s" % (p.communicate(timeout=5)[1] or "")[-300:])
        return drive_login("http://127.0.0.1:%d" % ent["port"], a.user, env.get("RN_USER_PASSWORD", "rn-user-password"), a.ca_bundle, fresh=not a.no_fresh)
    finally:
        p.terminate()


def prereq_ok(ent):
    if "prereq" not in ent:
        return True
    cmd = [c.replace("{python}", sys.executable) for c in ent["prereq"]]
    try:
        return subprocess.run(cmd, cwd=os.path.join(HERE, ent.get("prereq_cwd", ".")), capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def sanitize(res, secrets):
    """Orchestrator-side redaction: claims reduced to the allowlist again, JWT shapes and secrets removed."""
    res = dict(res)
    res["claims"] = {k: {kk: vv for kk, vv in (v or {}).items() if kk in CLAIM_ALLOWLIST} for k, v in (res.get("claims") or {}).items()}
    return scrub(res, secrets)


ICON = {"matched": "✔ Matches expectation", "differs": "✖ Differs from expectation", "recorded": "▲ Recorded (no expectation yet)", "error": "✖ Could not run", "skipped": "– Not exercised"}
CLS = {"matched": "g", "differs": "r", "recorded": "a", "error": "r", "skipped": "a"}


def report(rows, ver, issuer):
    tr = ""
    for r in rows:
        dep = ("<br><span class=m>Deprecated: %s. %s</span>" % (html.escape(r["deprecation"]["reason"]), html.escape(r["deprecation"]["action"]))) if r.get("deprecation") else ""
        head = "<b>%s</b> %s<br><span class=m>%s &middot; %s &middot; %s</span>%s" % (html.escape(r["id"]), html.escape(r["version"]),
               html.escape(r["language"]), html.escape(r["protocol"]), html.escape(r["status"]), dep)
        if not r["checks"]:
            tr += "<tr><td>%s</td><td colspan=3 class=m>%s</td></tr>" % (head, html.escape(r["state"]))
            continue
        for i, c in enumerate(r["checks"]):
            tr += "<tr><td>%s</td><td><b>%s</b><br><span class=m>%s</span></td><td><span class='c %s'>%s</span><br><span class=m>%s</span></td><td><code>%s</code></td></tr>" % (
                head if i == 0 else "", html.escape(c["id"]), html.escape(c["title"]), CLS[c["verdict"]], ICON[c["verdict"]], html.escape(c["detail"]),
                html.escape(json.dumps(c["observed"])))
    return """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Library runner results</title>
<style>:root{--bg:#f6f7fb;--ink:#1d2433;--m:#5b6577;--l:#dde1ea;--r:#c62828;--a:#b26a00;--g:#17803d}@media(prefers-color-scheme:dark){:root{--bg:#12161f;--ink:#e6e9f2;--m:#9aa4b8;--l:#2b3347;--r:#ff8a80;--a:#ffb74d;--g:#7bd88f}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif}main{max-width:1180px;margin:0 auto;padding:24px 16px}table{border-collapse:collapse;width:100%%}
td,th{border-bottom:1px solid var(--l);padding:6px 8px;text-align:left;vertical-align:top}.m{color:var(--m);font-size:12px}.c{font-weight:700}.c.r{color:var(--r)}.c.a{color:var(--a)}.c.g{color:var(--g)}code{font-size:11px;word-break:break-all}</style>
<main><h1>Library runner results</h1><p class=m>Server %s &middot; %s &middot; %s. “Matches expectation” is about the documented behaviour of this server version, not a statement that the team's application works.</p>
<table><tr><th>Runner</th><th>Check</th><th>Result</th><th>Observed</th></tr>%s</table></main></html>""" % (html.escape(ver), html.escape(issuer), time.strftime("%Y-%m-%d %H:%M"), tr)


def lookup_secrets(ent):
    """Real secrets from the environment. Per-runner name first (RN_CLIENT_SECRET__PASSPORT_OAUTH2), then the plain name."""
    suffix = "__" + ent["id"].upper().replace("-", "_")
    out = {}
    for k in ent.get("env", {}):
        v = os.environ.get(k + suffix) or os.environ.get(k)
        if v:
            out[k] = v
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--issuer", required=True); ap.add_argument("--server-version", required=True)
    ap.add_argument("--ca-bundle"); ap.add_argument("--out", default="out_runners"); ap.add_argument("--user", default="rn-user")
    ap.add_argument("--only", help="comma separated runner ids"); ap.add_argument("--fixture-secrets", action="store_true")
    ap.add_argument("--no-fresh", action="store_true", help="do not send prompt=login")
    ap.add_argument("--catalog", default=os.path.join(HERE, "catalog.json"))
    a = ap.parse_args()
    cat = json.load(open(a.catalog)); exp = json.load(open(os.path.join(HERE, "expectations", "checks.json")))
    only = set(a.only.split(",")) if a.only else None
    rows, secrets = [], []
    for ent in cat["runners"]:
        if only and ent["id"] not in only:
            continue
        row = dict(id=ent["id"], language=ent["language"], library=ent["library"], version=ent["version"], protocol=ent["protocol"],
                   status=ent["status"], deprecation=ent.get("deprecation"), build_state=ent.get("build_state"), checks=[], state="")
        rows.append(row)
        if ent["status"] in ("planned", "blocked") or "kind" not in ent:
            row["state"] = ent.get("note") or ent["status"]; continue
        if not prereq_ok(ent):
            row["state"] = "Not installed here. " + ent.get("install", ""); continue
        envx = dict(ent.get("env", {})) if a.fixture_secrets else lookup_secrets(ent)
        secrets += list(envx.values())
        try:
            res = sanitize(run_entry(ent, a, envx), secrets)
        except Exception as e:  # noqa: BLE001
            row["state"] = "Error: %s" % scrub(str(e), secrets); row["checks"] = [dict(id=c, title=exp.get(c, {}).get("title", ""), verdict="error", detail=row["state"], observed={}) for c in ent["checks"]]
            continue
        for c in res["checks"]:
            v, d = judge(c, exp, a.server_version)
            row["checks"].append(dict(id=c["id"], title=exp.get(c["id"], {}).get("title", ""), doc=exp.get(c["id"], {}).get("doc", ""), verdict=v, detail=d, observed=c["observed"]))
        row["claims"] = res.get("claims", {})
    os.makedirs(a.out, exist_ok=True)
    doc = dict(server_version=a.server_version, issuer=a.issuer, generated=time.strftime("%Y-%m-%dT%H:%M:%S"), runners=rows)
    blob = json.dumps(doc, indent=1)
    for s in secrets:
        assert s not in blob, "secret leaked into output"
    base = os.path.join(a.out, "runners-%s" % a.server_version)
    open(base + ".json", "w", encoding="utf-8").write(blob)
    open(base + ".html", "w", encoding="utf-8").write(report(rows, a.server_version, a.issuer))
    cnt = {}
    for r in rows:
        for c in r["checks"]:
            cnt[c["verdict"]] = cnt.get(c["verdict"], 0) + 1
        print("%-16s %-10s %s" % (r["id"], r["status"], ", ".join("%s=%s" % (c["id"], c["verdict"]) for c in r["checks"]) or r["state"]))
    print("verdicts:", cnt, "->", base + ".html")
    return 1 if cnt.get("differs") or cnt.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())

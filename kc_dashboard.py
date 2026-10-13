#!/usr/bin/env python3
"""Per-client risk dashboard from Phase 0 inventory JSON files. Python 3.8+, stdlib only.

  python kc_dashboard.py out_fixtures/*.json --runners out_runners/runners-*.json --target 26.6.7 --out dashboard.html

Status of a client at a target version (red / amber / green):
  red    a HIGH finding whose rule applies at or before the target version
  amber  a MEDIUM or LOW finding that applies at or before the target
  green  nothing applicable (information-only rows never count)
The 'observed' columns show the status the same client has on each inspected server, so a client that is
green on 26.0.x and red on 26.6.x is a regression caused by the migration.
"""
import argparse, glob, html, json, sys, time

E = html.escape
ORDER = {"green": 0, "amber": 1, "red": 2}
SEV_STATUS = {"high": "red", "medium": "amber", "low": "amber"}


def vtuple(s):
    out = []
    for p in str(s or "").replace("-", "").split(".")[:3]:
        out.append(int(p) if p.isdigit() else 0)
    return tuple(out + [0] * (3 - len(out)))


def status_of(findings, ok):
    st = "green"
    for f in findings:
        s = SEV_STATUS.get(f["severity"])
        if s and ok(f) and ORDER[s] > ORDER[st]:
            st = s
    return st


def load(paths):
    by_ver, order = {}, []
    for p in paths:
        inv = json.load(open(p, encoding="utf-8"))
        v = inv.get("server_version") or inv.get("label") or p
        if v not in by_ver:
            by_ver[v] = []
            order.append(v)
        by_ver[v].append(inv)
    order.sort(key=vtuple)
    return by_ver, order


def build(by_ver, order, target):
    clients = {}   # (realm, clientId) -> dict
    for v in order:
        for inv in by_ver[v]:
            for r in inv["realms"]:
                for c in r["clients"]:
                    if c.get("builtin"):
                        continue
                    k = (r["realm"], c["clientId"])
                    d = clients.setdefault(k, dict(realm=r["realm"], client=c["clientId"], proto=c.get("protocol"),
                                                   public=c.get("publicClient"), bearer=c.get("bearerOnly"),
                                                   findings={}, observed={}))
                    probs = [f for f in c["findings"] if f["severity"] != "info"]
                    d["observed"][v] = status_of(probs, lambda f: f.get("present_on_server") is not False)
                    for f in c["findings"]:
                        if f["severity"] == "info":
                            continue
                        key = (f["rule"], f["detail"], f.get("evidence"))
                        d["findings"].setdefault(key, f)
    for d in clients.values():
        fl = list(d["findings"].values())
        d["at_target"] = status_of(fl, lambda f: vtuple(f["introduced_in"]) <= vtuple(target))
        d["future"] = [f for f in fl if vtuple(f["introduced_in"]) > vtuple(target)]
    return sorted(clients.values(), key=lambda d: (-ORDER[d["at_target"]], d["realm"], d["client"]))


# runner check -> inventory rule it gives live evidence for (a runner result may also carry "rule" itself)
RULE_OF_CHECK = {"C16": "C16", "F4": "C14", "D3": "C3"}
VERDICT = {"matched": ("green", "\u2714 Matches expectation"), "differs": ("red", "\u2716 Differs from expectation"),
           "error": ("red", "\u2716 Could not run"), "recorded": ("grey", "\u25b2 Recorded"), "skipped": ("grey", "\u2013 Not exercised")}
VSHORT = {"matched": "\u2714", "differs": "\u2716", "error": "\u2716", "recorded": "\u25b2", "skipped": "\u2013"}
VORDER = {"differs": 4, "error": 4, "matched": 3, "recorded": 2, "skipped": 1}
LABEL = {"red": "\u2716 Action required", "amber": "\u25b2 Review", "green": "\u2714 No impact found"}
SHORT = {"red": "\u2716 Action", "amber": "\u25b2 Review", "green": "\u2714 OK"}
CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#1d2433;--mut:#5b6577;--line:#dde1ea;--red:#c62828;--redbg:#fde3e3;--amb:#b26a00;--ambbg:#ffeccc;--grn:#17803d;--grnbg:#dff3e5;--acc:#2f4fa8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#12161f;--card:#1a2030;--ink:#e6e9f2;--mut:#9aa4b8;--line:#2b3347;--red:#ff8a80;--redbg:#44201f;--amb:#ffb74d;--ambbg:#40300f;--grn:#7bd88f;--grnbg:#16341f;--acc:#8fa8ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Arial,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px}
.sub{color:var(--mut);margin:0 0 18px}.tiles{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 6px}
.tile{flex:1;min-width:200px;display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 14px;cursor:default}
.tile:hover,.tile:focus{outline:2px solid var(--acc);outline-offset:1px}.tl{display:block;font-weight:700}.ts{display:block;font-size:12px;color:var(--mut)}
.tile b{font-size:26px;line-height:1}.tile.red b{color:var(--red)}.tile.amber b{color:var(--amb)}.tile.green b{color:var(--grn)}
.chip{display:inline-block;border-radius:10px;padding:1px 10px;font-size:12px;font-weight:700;white-space:nowrap}
.chip.red{background:var(--redbg);color:var(--red)}.chip.amber{background:var(--ambbg);color:var(--amb)}.chip.green{background:var(--grnbg);color:var(--grn)}
.row{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}
.row>summary{list-style:none;cursor:pointer;display:flex;gap:12px;align-items:center;padding:10px 14px;flex-wrap:wrap}
.row>summary::-webkit-details-marker{display:none}.name{font-weight:700;min-width:170px}.mut{color:var(--mut)}.grow{flex:1}
.obs{display:flex;gap:6px;align-items:center;font-size:12px;color:var(--mut)}
.body{padding:2px 14px 12px;border-top:1px solid var(--line)}
table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}code{background:var(--bg);padding:0 4px;border-radius:3px;font-size:12px;word-break:break-all}
td code,.ev code{word-break:normal;overflow-wrap:break-word}.chip.grey{background:var(--bg);color:var(--mut);border:1px solid var(--line)}.scroll{overflow-x:auto}td.v{white-space:nowrap}.ev{margin-top:4px;font-size:12px;color:var(--grn)}
.explain{min-height:3.4em;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:6px;padding:8px 14px;margin:0 0 6px;color:var(--mut)}.explain b{color:var(--ink)}
.legend{display:none}@media print{.explain{min-height:0}.legend{display:block;margin:6px 0 12px}.legend p{margin:2px 0}}
.note{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:6px;padding:10px 14px;margin:12px 0;color:var(--mut)}
"""


def load_runners(paths):
    by = {}
    for p in paths:
        d = json.load(open(p, encoding="utf-8"))
        by[d["server_version"]] = d
    return by, sorted(by, key=vtuple)


def runner_rows(by, vers):
    """-> ordered list of runner dicts: meta + per-version {check id: check}"""
    rows, idx = [], {}
    for v in vers:
        for r in by[v]["runners"]:
            if r["id"] not in idx:
                idx[r["id"]] = len(rows)
                rows.append(dict(meta=r, checks={}, order=[], states={}))
            row = rows[idx[r["id"]]]
            row["states"][v] = r.get("state", "")
            for ck in r["checks"]:
                if ck["id"] not in row["order"]:
                    row["order"].append(ck["id"])
                row["checks"].setdefault(v, {})[ck["id"]] = ck
    return rows


def observed_changes(rows, vers):
    """Observed values that differ between server versions: [(check, title, doc, key, {version: value}, [runners])]"""
    found = {}
    for row in rows:
        for cid in row["order"]:
            keys = set()
            for v in vers:
                ck = row["checks"].get(v, {}).get(cid)
                if ck and ck["verdict"] != "error":
                    keys |= set(ck["observed"])
            for k in sorted(keys):
                vals = {v: row["checks"][v][cid]["observed"][k] for v in vers
                        if cid in row["checks"].get(v, {}) and row["checks"][v][cid]["verdict"] != "error" and k in row["checks"][v][cid]["observed"]}
                if len(vals) == len(vers) and len({json.dumps(x) for x in vals.values()}) > 1:
                    ck0 = row["checks"][vers[0]][cid]
                    key = (cid, k, json.dumps([vals[v] for v in vers]))
                    e = found.setdefault(key, [cid, ck0.get("title", ""), ck0.get("doc", ""), k, vals, []])
                    e[5].append(row["meta"]["id"])
    return list(found.values())


def span(vers, vals):
    """'401 on 26.0.8, 26.2.5 -> 400 on 26.6.4' grouping consecutive equal values"""
    groups = []
    for v in vers:
        s = json.dumps(vals[v]).strip('"')
        if groups and groups[-1][0] == s:
            groups[-1][1].append(v)
        else:
            groups.append([s, [v]])
    return " &rarr; ".join("<code>%s</code> on %s" % (E(s), E(", ".join(vs))) for s, vs in groups)


def obs_text(o):
    return ", ".join("%s=%s" % (k, json.dumps(v).strip('"')) for k, v in o.items())


def render_runners(rows, vers, changes):
    if not rows:
        return ""
    tot = {}
    for row in rows:
        for v in vers:
            for ck in row["checks"].get(v, {}).values():
                tot[ck["verdict"]] = tot.get(ck["verdict"], 0) + 1
    ran = [r for r in rows if r["checks"]]
    words = {"matched": "match", "differs": "differ", "error": "could not run", "recorded": "recorded", "skipped": "not exercised"}
    summ = ", ".join("%d %s" % (n, words[k]) for k, n in sorted(tot.items(), key=lambda kv: -VORDER[kv[0]]))
    out = "<h2>Libraries on each server version</h2><p class=sub>%d libraries ran against %s. Checks: %s.</p>" % (len(ran), E(", ".join(vers)), E(summ))
    for row in rows:
        m = row["meta"]
        if not row["checks"]:
            dep = ""
            if m.get("deprecation"):
                dep = " <span class='chip red'>deprecated</span> %s. %s" % (E(m["deprecation"]["reason"]), E(m["deprecation"]["action"]))
            out += "<div class=row><div class=body style='border:0'><b>%s %s</b> <span class=mut>%s &middot; %s &middot; %s</span>%s<br><span class=mut>%s</span></div></div>" % (
                E(m["id"]), E(m["version"]), E(m["language"]), E(m["protocol"]), E(m["status"]), dep,
                E(next((s for s in row["states"].values() if s), "")))
            continue
        chips = ""
        for v in vers:
            cks = list(row["checks"].get(v, {}).values())
            if not cks:
                chips += '<span class=obs>%s <span class="chip grey">not run</span></span>' % E(v)
                continue
            worst = max((c["verdict"] for c in cks), key=lambda x: VORDER[x])
            cls = VERDICT[worst][0] if worst in ("differs", "error", "matched") else "grey"
            n_ok = sum(1 for c in cks if c["verdict"] == "matched")
            txt = ("\u2714 %d/%d match" % (n_ok, len(cks))) if worst == "matched" else ("\u2716 %d differ" % sum(1 for c in cks if c["verdict"] in ("differs", "error")))
            chips += '<span class=obs>%s <span class="chip %s">%s</span></span>' % (E(v), cls, E(txt))
        tr = ""
        for cid in row["order"]:
            first = next(row["checks"][v][cid] for v in vers if cid in row["checks"].get(v, {}))
            tds = ""
            for v in vers:
                ck = row["checks"].get(v, {}).get(cid)
                if not ck:
                    tds += "<td class=mut>&ndash;</td>"
                    continue
                cls = VERDICT[ck["verdict"]][0]
                tds += "<td><span class='chip %s'>%s</span><br><code>%s</code>%s</td>" % (
                    cls, E(VSHORT[ck["verdict"]] + " " + ck["verdict"]), E(obs_text(ck["observed"])),
                    ("<br><span class=mut>%s</span>" % E(ck["detail"])) if ck.get("detail") else "")
            tr += "<tr><td><b>%s</b><br><span class=mut>%s<br>%s</span></td>%s</tr>" % (E(cid), E(first.get("title", "")), E(first.get("doc", "")), tds)
        note = ("<p class=mut>%s</p>" % E(m["note"])) if m.get("note") else ""
        sub = "%s &middot; %s &middot; %s" % (E(m["language"]), E(m["protocol"]), E(m["version"]) if m["version"] != "-" else "no library")
        out += ("<details class=row><summary><span class=name>%s<br><span class=mut>%s</span></span><span class=grow></span>%s</summary>"
                "<div class=body>%s<div class=scroll><table><tr><th>Check</th>%s</tr>%s</table></div></div></details>") % (
            E(m["id"]), sub, chips, note, "".join("<th>%s</th>" % E(v) for v in vers), tr)
    if changes:
        tr = "".join("<tr><td><b>%s</b><br><span class=mut>%s</span></td><td>%s</td><td>%s</td><td class=mut>%s</td><td>%s</td></tr>" % (
            E(cid), E(title), E(k), span(vers, vals), E(", ".join(rs)), E(doc)) for cid, title, doc, k, vals, rs in sorted(changes, key=lambda e: (e[0], e[3])))
        out += ("<h2>What the servers do differently, seen on real runs</h2><p class=sub>Observed values that change between the inspected servers. "
                "Libraries that agree are listed together.</p><div class=scroll><table><tr><th>Check</th><th>Value</th><th>Observed</th><th>Seen by</th><th>Official document</th></tr>%s</table></div>") % tr
    else:
        out += "<h2>What the servers do differently, seen on real runs</h2><p class=mut>No observed value changes between the inspected servers.</p>"
    return out


def evidence_for(changes, vers):
    """inventory rule -> html lines of live evidence"""
    ev = {}
    for cid, title, doc, k, vals, rs in changes:
        rule = RULE_OF_CHECK.get(cid)
        if rule:
            ev.setdefault(rule, []).append("%s: %s (seen by %s)" % (E(k), span(vers, vals), E(", ".join(rs))))
    return ev


TXT = {
    "red": "A high-severity documented change applies to this client at or before the target version. Fix before the upgrade.",
    "amber": "A medium or low-severity documented change applies. Check whether the client is affected.",
    "green": "No documented configuration change touches this client. This does not prove the application works: runtime behaviour such as tokens, sessions and proxies is not covered.",
}


def render(clients, order, target, title, sources, runner_html="", evidence=None):
    evidence = evidence or {}
    n = {s: sum(1 for c in clients if c["at_target"] == s) for s in ORDER}
    rows = ""
    for c in clients:
        obs = "".join('<span class="obs">%s <span class="chip %s">%s</span></span>' % (E(v), c["observed"].get(v, "green"),
                                                                                         SHORT[c["observed"].get(v, "green")]) for v in order)
        typ = "public" if c["public"] else ("bearer-only" if c["bearer"] else c["proto"])
        fr = ""
        for f in sorted(c["findings"].values(), key=lambda f: (ORDER[SEV_STATUS.get(f["severity"], "green")] * -1, f["rule"])):
            applies = [v for v in order if vtuple(v) >= vtuple(f["introduced_in"])]
            when = "applies from %s" % E(f["introduced_in"]) + (" (active on %s)" % E(", ".join(applies)) if applies else " (not yet on any inspected server)")
            live = "".join("<div class=ev>\u2714 Confirmed on real servers - %s</div>" % e for e in evidence.get(f["rule"], []))
            fr += "<tr><td><span class='chip %s'>%s</span></td><td><b>%s</b><br><span class=mut>%s</span></td><td>%s%s%s</td><td>%s</td></tr>" % (
                SEV_STATUS.get(f["severity"], "green"), E(f["rule"]), E(f["title"]), when, E(f["detail"]),
                ("<br><code>%s</code>" % E(str(f["evidence"]))) if f.get("evidence") else "", live, E(f["doc"]))
        body = ("<table><tr><th>Rule</th><th>What changes</th><th>Found</th><th>Official document (UG = Upgrading Guide)</th></tr>%s</table>" % fr) if fr else \
            "<p class=mut>No documented breaking change touches this client's configuration.</p>"
        rows += ("<details class=row%s><summary><span class=name>%s<br><span class=mut>%s &middot; %s</span></span>"
                 "<span class='chip %s'>%s</span><span class=grow></span>%s</summary><div class=body>%s</div></details>") % (
            " open" if c["at_target"] == "red" else "", E(c["client"]), E(c["realm"]), E(str(typ)), c["at_target"],
            LABEL[c["at_target"]], obs, body)
    reg = []
    for c in clients:
        seq = [(v, c["observed"].get(v)) for v in order if v in c["observed"]]
        for (v1, s1), (v2, s2) in zip(seq, seq[1:]):
            if ORDER[s2] > ORDER[s1]:
                reg.append("<tr><td><b>%s</b><br><span class=mut>%s</span></td><td>%s &rarr; %s</td><td><span class='chip %s'>%s</span> &rarr; <span class='chip %s'>%s</span></td></tr>" % (
                    E(c["client"]), E(c["realm"]), E(v1), E(v2), s1, SHORT[s1], s2, SHORT[s2]))
    regt = ("<table><tr><th>Client</th><th>Move</th><th>Status</th></tr>%s</table>" % "".join(reg)) if reg else \
        "<p class=mut>No client gets worse between the inspected servers.</p>"
    return """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>%(t)s</title><style>%(css)s</style></head><body><main>
<h1>%(t)s</h1><p class=sub>Status per client for target version <b>%(tg)s</b>. Servers inspected: %(vs)s. Generated %(g)s.</p>
<div class=tiles>
<div class="tile red" tabindex=0 data-t=t-red aria-describedby=t-red><b>%(r)d</b><span><span class=tl>\u2716 Action required</span><span class=ts>Fix before the upgrade</span></span></div>
<div class="tile amber" tabindex=0 data-t=t-amber aria-describedby=t-amber><b>%(a)d</b><span><span class=tl>\u25b2 Review</span><span class=ts>Check if affected</span></span></div>
<div class="tile green" tabindex=0 data-t=t-green aria-describedby=t-green><b>%(gr)d</b><span><span class=tl>\u2714 No impact found</span><span class=ts>Nothing documented</span></span></div></div>
<div class=explain id=explain>%(dflt)s</div>
<div class=legend><p id=t-red><b>\u2716 Action required:</b> %(t_red)s</p><p id=t-amber><b>\u25b2 Review:</b> %(t_amber)s</p><p id=t-green><b>\u2714 No impact found:</b> %(t_green)s</p></div>
<script>(function(){var ex=document.getElementById('explain'),d=ex.innerHTML;document.querySelectorAll('.tile[data-t]').forEach(function(t){
var h=document.getElementById(t.getAttribute('data-t')).innerHTML;function on(){ex.innerHTML=h}function off(){ex.innerHTML=d}
t.addEventListener('mouseenter',on);t.addEventListener('mouseleave',off);t.addEventListener('focus',on);t.addEventListener('blur',off)})})();</script>
<h2>Clients</h2>%(rows)s
<h2>What gets worse between the inspected servers</h2>%(reg)s
%(runners)s
<p class=mut style="margin-top:28px">Sources: %(src)s. Rules cite the Red Hat build of Keycloak Upgrading Guides (UG).</p>
</main></body></html>""" % dict(t=E(title), css=CSS, tg=E(target), vs=E(", ".join(order)), g=E(time.strftime("%Y-%m-%d %H:%M")),
                                 r=n["red"], a=n["amber"], gr=n["green"], rows=rows, reg=regt, runners=runner_html,
                                 dflt=("Rules cite the Red Hat build of Keycloak Upgrading Guides (UG). <b>For example:</b> <code>UG26.6 \u00a72.10.38</code> in the "
                                       "\u201cOfficial document\u201d column means Upgrading Guide 26.6, section 2.10.38. Statuses are judged for target version %s. "
                                       "<i>Hover a count to see what it means.</i>") % E(target),
                                 t_red=E(TXT["red"]), t_amber=E(TXT["amber"]), t_green=E(TXT["green"]), src=E(", ".join(sources)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inventories", nargs="+")
    ap.add_argument("--runners", nargs="*", default=[], help="runner result files (out_runners/runners-<version>.json) to add live evidence")
    ap.add_argument("--target", help="version to judge against; default = newest version any rule mentions")
    ap.add_argument("--title", default="Client impact dashboard")
    ap.add_argument("--out", default="dashboard.html")
    a = ap.parse_args(argv)
    expand = lambda ps: [f for p in ps for f in (sorted(glob.glob(p)) or [p])]   # cmd.exe does not expand wildcards
    a.inventories, a.runners = expand(a.inventories), expand(a.runners)
    by_ver, order = load(a.inventories)
    tg = a.target
    if not tg:
        all_f = [f["introduced_in"] for invs in by_ver.values() for inv in invs for r in inv["realms"]
                 for c in r["clients"] for f in c["findings"] if f["introduced_in"] not in ("-", "")]
        tg = max(all_f, key=vtuple) if all_f else order[-1]
    clients = build(by_ver, order, tg)
    runner_html, evidence = "", {}
    if a.runners:
        rby, rvers = load_runners(a.runners)
        rrows = runner_rows(rby, rvers)
        changes = observed_changes(rrows, rvers)
        runner_html, evidence = render_runners(rrows, rvers, changes), evidence_for(changes, rvers)
    open(a.out, "w", encoding="utf-8").write(render(clients, order, tg, a.title, [p.split("/")[-1].split("\\")[-1] for p in a.inventories + a.runners], runner_html, evidence))
    n = {s: sum(1 for c in clients if c["at_target"] == s) for s in ORDER}
    print("%d clients at target %s: %d red, %d amber, %d green -> %s" % (len(clients), tg, n["red"], n["amber"], n["green"], a.out))


if __name__ == "__main__":
    sys.exit(main())

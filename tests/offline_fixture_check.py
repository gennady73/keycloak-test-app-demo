"""Offline self-test: lint the fixture realms WITHOUT a Keycloak and verify against expected.json.
Proves the fixtures and the expectations agree with the tool's own rules. It does not prove that Keycloak
imports the fixtures as written: that is what the container run is for."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kc_phase0 as k
base = os.path.join(os.path.dirname(__file__), "..", "fixtures")
exp = json.load(open(os.path.join(base, "expected.json")))
for ver in ("26.0.8", "26.6.4"):
    invs = []
    for realm in exp["realms"]:
        d = json.load(open(os.path.join(base, "realms", "%s-realm.json" % realm)))
        sv = k.vtuple(ver)
        cl = []
        for c in d["clients"]:
            ec = k.extract_client(c); ec["findings"] = [] if ec["builtin"] else k.lint_client(ec, None)
            for f in ec["findings"]:
                t = k.vtuple(f["introduced_in"]); f["present_on_server"] = None if t is None else sv >= t
            cl.append(ec)
        invs.append({"server_version": ver, "realms": [{"realm": realm, "clients": cl}]})
    res = k.verify_inventories(invs, exp)
    bad = [r for r in res if r[0] != "PASS"]
    print("server %s: %d checks, %d not passing" % (ver, len(res), len(bad)))
    for r in bad: print("  ", r)

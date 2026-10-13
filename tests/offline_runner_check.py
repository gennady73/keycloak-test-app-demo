#!/usr/bin/env python3
"""Offline regression for the runner framework: starts tests/mock_oidc.py as an older and a newer server and
checks the verdicts the orchestrator produces. No Keycloak, no libraries needed. Exit 1 on failure."""
import json, os, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
fails = []


def run(mock_ver, declared_ver, port):
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_oidc.py"), str(port), mock_ver]); time.sleep(1)
    try:
        out = tempfile.mkdtemp()
        subprocess.run([sys.executable, os.path.join(ROOT, "runners", "orchestrate.py"), "--issuer", "http://127.0.0.1:%d/realms/fx-runner" % port,
                        "--server-version", declared_ver, "--fixture-secrets", "--only", "http-probe,plain-http-code", "--out", out],
                       capture_output=True, text=True)
        d = json.load(open(os.path.join(out, "runners-%s.json" % declared_ver)))
        blob = open(os.path.join(out, "runners-%s.json" % declared_ver)).read()
        assert "rn-svc-secret" not in blob and "eyJ" not in blob, "secret or token in output"
        return {(r["id"], c["id"]): c["verdict"] for r in d["runners"] for c in r["checks"]}
    finally:
        p.terminate()


def expect(res, key, want, label):
    if res.get(key) != want:
        fails.append("%s %s: expected %s got %s" % (label, key, want, res.get(key)))


for mv, dv, port in (("26.0.8", "26.0.8", 8472), ("26.6.4", "26.6.4", 8473), ("26.0.8", "26.6.4", 8474)):
    r = run(mv, dv, port); lab = "mock %s declared %s" % (mv, dv)
    for k in (("http-probe", "F5"), ("plain-http-code", "F1"), ("plain-http-code", "F2")):
        expect(r, k, "matched", lab)
    expect(r, ("http-probe", "C16"), "matched" if mv == dv else "differs", lab)
    expect(r, ("http-probe", "D3"), "matched" if mv == dv else "differs", lab)
    expect(r, ("plain-http-code", "F4"), "matched" if mv == dv else "differs", lab)
print("FAIL\n" + "\n".join(fails) if fails else "PASS runner framework (3 scenarios)")
sys.exit(1 if fails else 0)

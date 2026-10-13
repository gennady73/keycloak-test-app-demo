#!/usr/bin/env python3
"""Run the inventory against each fixture realm, then verify against fixtures/expected.json.
Usage: python run_fixture_tests.py --base-url https://localhost:8443 --ca-bundle certs/kc.crt --label fx-26.6.4
The fixture realms must already be imported (see README). Exit code 1 if any check fails."""
import argparse, glob, json, os, ssl, subprocess, sys, time, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--base-url", required=True)
ap.add_argument("--ca-bundle")
ap.add_argument("--label", required=True)
ap.add_argument("--out", default=os.path.join(HERE, "out_fixtures"))
ap.add_argument("--wait", type=int, default=0, help="seconds to wait for the server and the imported realms")
a = ap.parse_args()
def wait_ready(base, ca, seconds):
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    url = base.rstrip("/") + "/realms/fx-legacy/.well-known/openid-configuration"
    end = time.time() + seconds
    while True:
        try:
            if urllib.request.urlopen(url, timeout=5, context=ctx).status == 200:
                return
        except Exception as e:  # noqa: BLE001
            last = e
        if time.time() > end:
            sys.exit("server not ready after %ss (%s). Check: docker compose logs" % (seconds, last))
        time.sleep(3)


if a.wait:
    wait_ready(a.base_url, a.ca_bundle, a.wait)
exp = json.load(open(os.path.join(HERE, "fixtures", "expected.json")))
env = dict(os.environ, KC_CLIENT_SECRET="fx-inventory-secret")   # fixture secret, test data only
files = []
for realm in exp["realms"]:
    label = "%s-%s" % (a.label, realm)
    cmd = [sys.executable, os.path.join(HERE, "kc_phase0.py"), "inventory", "--base-url", a.base_url,
           "--label", label, "--client-id", "kc-inventory", "--auth-realm", realm, "--realm", realm, "--out", a.out,
           "--route", "external=" + a.base_url]
    if a.ca_bundle:
        cmd += ["--ca-bundle", a.ca_bundle]
    r = subprocess.run(cmd, env=env, text=True, capture_output=True)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode:
        sys.exit("inventory failed for %s" % realm)
    files.append(os.path.join(a.out, label + ".json"))
sys.exit(subprocess.call([sys.executable, os.path.join(HERE, "kc_phase0.py"), "verify", *files,
                          "--expected", os.path.join(HERE, "fixtures", "expected.json")]))

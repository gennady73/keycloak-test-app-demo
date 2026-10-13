#!/usr/bin/env python3
"""Create (or recreate) the fx-runner realm through the Admin API. Test servers only.
Kept out of the startup import folder on purpose: the inventory fixtures stay exactly as verified.
  KC_ADMIN_PASSWORD=... python runners/bootstrap_realm.py --base-url https://192.0.2.10:8466 --ca-bundle certs/kc.crt
Admin credentials come from the environment, never from the command line."""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rn_common import Http
HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--base-url", required=True); ap.add_argument("--ca-bundle")
ap.add_argument("--admin-user", default="admin"); ap.add_argument("--recreate", action="store_true")
a = ap.parse_args()
pw = os.environ.get("KC_ADMIN_PASSWORD") or sys.exit("set KC_ADMIN_PASSWORD")
h = Http(a.ca_bundle); b = a.base_url.rstrip("/")
st, _, raw = h.post(b + "/realms/master/protocol/openid-connect/token",
                    {"grant_type": "password", "client_id": "admin-cli", "username": a.admin_user, "password": pw})
if st != 200:
    sys.exit("admin login failed (HTTP %s)" % st)
auth = {"Authorization": "Bearer " + json.loads(raw)["access_token"]}
realm = json.load(open(os.path.join(HERE, "..", "fixtures", "runner", "fx-runner-realm.json")))
st, _, _ = h.get(b + "/admin/realms/fx-runner", headers=auth)
if st == 200:
    if not a.recreate:
        sys.exit("realm fx-runner exists; use --recreate to replace it")
    h.req("DELETE", b + "/admin/realms/fx-runner", headers=auth)
st, _, raw = h.post(b + "/admin/realms", data=json.dumps(realm).encode(), headers=dict(auth, **{"Content-Type": "application/json"}))
print("created fx-runner" if st == 201 else "failed: HTTP %s %s" % (st, raw[:200]))
sys.exit(0 if st == 201 else 1)

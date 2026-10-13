#!/usr/bin/env python3
"""Library-free runner: raw HTTP checks that need no browser. Prints the runner-contract JSON.
  D3   path probes ('//', '..', ';') against the realm base URL        (observation, no documented expectation)
  C16  Direct-access-grant with a wrong password: HTTP status          (UG26.6 §2.10.38)
  F5   client-credentials token: status, token type, claim shapes      (UG26.2 §2.9.7)
Secrets only through the environment: RN_SVC_SECRET, RN_ROPC_SECRET, RN_ROPC_PASSWORD (wrong value is fixed here)."""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rn_common import Http, safe_claims, scrub

ap = argparse.ArgumentParser()
ap.add_argument("--issuer", required=True, help="https://host:port/realms/<realm>")
ap.add_argument("--ca-bundle"); ap.add_argument("--svc-client", default="rn-svc"); ap.add_argument("--ropc-client", default="rn-ropc")
ap.add_argument("--user", default="rn-user")
a = ap.parse_args()
h, iss = Http(a.ca_bundle), a.issuer.rstrip("/")
checks = []


def add(i, status="done", observed=None, error=None):
    checks.append(dict(id=i, status=status, observed=observed or {}, **({"error": error} if error else {})))


try:   # D3
    realm = iss.rsplit("/", 1)[1]
    root = iss.rsplit("/realms/", 1)[0]
    tail = "/.well-known/openid-configuration"
    probes = {"plain": iss + tail, "double_slash": iss + "/" + tail, "dot_dot": root + "/realms/x/../" + realm + tail,
              "semicolon": iss + ";a=b" + tail, "encoded_slash": iss + "%2F" + tail}
    obs = {}
    for k, u in probes.items():
        st, _, _ = h.get(u)
        obs[k] = st
    add("D3", observed=obs)
except Exception as e:  # noqa: BLE001
    add("D3", "error", error=str(e))

tok = iss + "/protocol/openid-connect/token"
try:   # C16
    st, _, raw = h.post(tok, {"grant_type": "password", "client_id": a.ropc_client, "client_secret": os.environ.get("RN_ROPC_SECRET", ""),
                              "username": a.user, "password": "definitely-wrong"})
    err = json.loads(raw).get("error") if raw[:1] == b"{" else None
    add("C16", observed={"http_status": st, "error": err})
except Exception as e:  # noqa: BLE001
    add("C16", "error", error=str(e))

claims = {}
try:   # F5
    st, _, raw = h.post(tok, {"grant_type": "client_credentials", "client_id": a.svc_client, "client_secret": os.environ.get("RN_SVC_SECRET", "")})
    body = json.loads(raw) if raw[:1] == b"{" else {}
    ob = {"http_status": st, "token_type": body.get("token_type"), "refresh_token_issued": "refresh_token" in body}
    if st == 200:
        c = safe_claims(body["access_token"])
        claims["access_token"] = c
        ob.update(client_id_claim=c.get("client_id"), azp=c.get("azp"), issuer_matches=c.get("iss") == iss)
    add("F5", observed=ob)
except Exception as e:  # noqa: BLE001
    add("F5", "error", error=str(e))

res = dict(runner=dict(id="http-probe", language="python", library="(none, stdlib)", version=sys.version.split()[0]), checks=checks, claims=claims)
print(json.dumps(scrub(res, [os.environ.get("RN_SVC_SECRET"), os.environ.get("RN_ROPC_SECRET")])))

#!/usr/bin/env python3
"""Offline check of the login driver's SAML path: Keycloak-style auto-submitting form, relative redirect in /start."""
import os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(os.path.dirname(HERE), "runners"))
from rn_common import drive_login
ps = [subprocess.Popen([sys.executable, os.path.join(HERE, "mock_oidc.py"), "8475", "26.6.4"]),
      subprocess.Popen([sys.executable, os.path.join(HERE, "fake_saml_sp.py"), "8476", "http://127.0.0.1:8475/realms/fx-runner"])]
time.sleep(1)
try:
    r = drive_login("http://127.0.0.1:8476", "rn-user", "rn-user-password")
    ok = r == {"got_saml_response": True, "relay": "r1"}
    print(("PASS" if ok else "FAIL"), "SAML driver path", r)
    sys.exit(0 if ok else 1)
finally:
    for p in ps: p.terminate()

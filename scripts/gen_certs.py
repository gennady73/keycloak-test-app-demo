#!/usr/bin/env python3
"""Create a self-signed test certificate (certs/kc.crt, certs/kc.key) for the local Keycloak containers.
Needs the openssl command (1.1.1 or later). Test use only; the key is git-ignored.
  python scripts/gen_certs.py [HOST_IP]      (default: HOST_IP from .env)"""
import os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ip = sys.argv[1] if len(sys.argv) > 1 else None
if not ip:
    for fn in (os.path.join(ROOT, ".env"), os.path.join(ROOT, "local", ".env")):   # later file wins
        for line in open(fn) if os.path.exists(fn) else []:
            if line.startswith("HOST_IP="):
                ip = line.split("=", 1)[1].strip()
ip = ip or "127.0.0.1"
d = os.path.join(ROOT, "certs"); os.makedirs(d, exist_ok=True)
san = "subjectAltName=DNS:localhost,IP:127.0.0.1" + ("" if ip == "127.0.0.1" else ",IP:" + ip)
r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj", "/CN=kc-test",
                    "-addext", san, "-keyout", os.path.join(d, "kc.key"), "-out", os.path.join(d, "kc.crt")])
if r.returncode:
    sys.exit("openssl failed. Install openssl, or place your own kc.crt/kc.key (with %s in the SAN) in certs/" % ip)
os.chmod(os.path.join(d, "kc.key"), 0o644)   # the container user must be able to read the bind-mounted key
print("created certs/kc.crt and certs/kc.key  (SAN: %s)" % san)

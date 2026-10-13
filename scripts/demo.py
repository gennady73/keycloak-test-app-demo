#!/usr/bin/env python3
"""One entry point for the local test environment and the demo. Works on Windows, Linux and macOS (Python 3.8+).

  python scripts/demo.py certs        create the test certificate
  python scripts/demo.py up           start the three Keycloak versions (docker compose / podman compose)
  python scripts/demo.py bootstrap    create the fx-runner realm on each version (needs KC_ADMIN_PASSWORD in .env)
  python scripts/demo.py fixtures     inventory + verify against fixtures on each version
  python scripts/demo.py runners      run all library runners on each version
  python scripts/demo.py dashboard    build out_fixtures/dashboard.html from both result sets
  python scripts/demo.py d1           issuer/hostname incident replay
  python scripts/demo.py all          up, bootstrap, fixtures, runners, dashboard
  python scripts/demo.py down         remove the containers
Settings are read from .env, then local/.env (git-ignored, real values). Copy .env.example to start."""
import os, re, shutil, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
PY = sys.executable
ENV_FILES = [f for f in (".env", os.path.join("local", ".env")) if os.path.exists(f)]   # local/.env (git-ignored) wins
def load_env():
    e = {}
    for fn in ENV_FILES:
        for l in open(fn):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); e[k.strip()] = v.strip().strip('"').strip("'")
    return e
ENV = load_env()
IP = ENV.get("HOST_IP", "127.0.0.1")
CA = os.path.join(ROOT, "certs", "kc.crt")
def ver(tag): return re.sub(r"-\d+$", "", tag)
VERSIONS = [(ver(ENV.get("KC_TAG_2608", "26.0.8-1")), 8460), (ver(ENV.get("KC_TAG_262", "26.2.5-0")), 8462), (ver(ENV.get("KC_TAG_266", "26.6.4-1")), 8466)]
def run(cmd, env=None, check=True):
    print("\n> " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, env=dict(os.environ, **(env or {})))
    if check and r.returncode:
        sys.exit("failed (exit %s): %s" % (r.returncode, " ".join(cmd)))
    return r.returncode
def compose():
    for c in (["docker", "compose"], ["docker-compose"], ["podman", "compose"], ["podman-compose"]):
        if shutil.which(c[0]) and (len(c) == 1 or subprocess.run(c + ["version"], capture_output=True).returncode == 0):
            return c
    sys.exit("no docker compose / podman compose found")
def env_file_args():
    # compose reads only ./.env by itself; hand it the local/.env when that is where the real settings live
    return ["--env-file", os.path.join("local", ".env")] if os.path.exists(os.path.join("local", ".env")) else []
def need_env():
    if not ENV_FILES: sys.exit("copy .env.example to local/.env (or .env) and edit it first")
    if not os.path.exists(CA): sys.exit("no certs/kc.crt: run  python scripts/demo.py certs")
def cmd_certs(): run([PY, "scripts/gen_certs.py"])
def cmd_up(profile=None):
    need_env(); run(compose() + env_file_args() + (["--profile", profile] if profile else []) + ["up", "-d"] + (["kc-266-d1"] if profile else []))
    print("\nThe first start imports the realms; fixtures wait for it (--wait 120).")
def cmd_down(): run(compose() + env_file_args() + ["--profile", "d1", "down"])
def cmd_bootstrap():
    need_env()
    pw = ENV.get("KC_ADMIN_PASSWORD") or os.environ.get("KC_ADMIN_PASSWORD") or sys.exit("KC_ADMIN_PASSWORD missing in .env")
    for v, p in VERSIONS:
        run([PY, "runners/bootstrap_realm.py", "--base-url", "https://%s:%d" % (IP, p), "--ca-bundle", CA, "--recreate"], {"KC_ADMIN_PASSWORD": pw})
def cmd_fixtures():
    need_env(); rc = 0
    for v, p in VERSIONS:
        rc |= run([PY, "run_fixture_tests.py", "--base-url", "https://%s:%d" % (IP, p), "--ca-bundle", CA, "--label", "fx-" + v, "--wait", "120"], check=False)
    return rc
def cmd_runners():
    need_env()
    for v, p in VERSIONS:
        run([PY, "runners/orchestrate.py", "--issuer", "https://%s:%d/realms/fx-runner" % (IP, p), "--server-version", v, "--ca-bundle", CA, "--fixture-secrets", "--out", "out_runners"])
def cmd_dashboard():
    import glob
    fx = sorted(glob.glob("out_fixtures/fx-*.json")); rn = sorted(glob.glob("out_runners/runners-*.json"))
    if not fx: sys.exit("no fixture results: run  fixtures  first")
    cmd = [PY, "kc_dashboard.py", *fx]
    if rn: cmd += ["--runners", *rn]
    run(cmd + ["--target", "26.6.7", "--title", "Keycloak 26.0 to 26.6: client impact", "--out", "out_fixtures/dashboard.html"])
    print("\nOpen out_fixtures/dashboard.html in a browser.")
def cmd_d1():
    need_env(); cmd_up("d1")
    run([PY, "kc_phase0.py", "inventory", "--base-url", "https://%s:8467" % IP, "--ca-bundle", CA, "--label", "d1-replay", "--client-id", "kc-inventory",
         "--auth-realm", "fx-baseline", "--realm", "fx-baseline", "--server-version", "26.6.4", "--route", "external=https://%s:8467" % IP, "--out", "out_d1"],
        {"KC_CLIENT_SECRET": "fx-inventory-secret"}, check=False)
    print("\nExpected: findings above 0 (rule D1: issuer :8466 differs from the route :8467).")
CMDS = {"certs": cmd_certs, "up": cmd_up, "down": cmd_down, "bootstrap": cmd_bootstrap, "fixtures": cmd_fixtures,
        "runners": cmd_runners, "dashboard": cmd_dashboard, "d1": cmd_d1}
if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else ""
    if a == "all":
        cmd_up(); cmd_bootstrap(); cmd_fixtures(); cmd_runners(); cmd_dashboard()
    elif a in CMDS:
        sys.exit(CMDS[a]() or 0)
    else:
        print(__doc__)

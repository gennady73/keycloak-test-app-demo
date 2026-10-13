#!/usr/bin/env python3
"""Pre-publish check: fails when files that would be committed contain something that should stay local.
  python scripts/check_public.py
Checks (files git would track: tracked + untracked-not-ignored; without git, everything outside ignored folders):
  * private IPv4 addresses (10.x, 172.16-31.x, 192.168.x); documentation addresses 192.0.2.x and 127.x are fine
  * e-mail addresses (except noreply and example.*)
  * private key blocks, other than the allowed test key (runners/node/samlify/sp-test-key.pem)
  * every non-empty line of local/forbidden.txt (your own list: real IPs, host names, company names)
  * a tracked .env, certificate key or zip
PDF files are searched through pdftotext when it is installed."""
import os, re, shutil, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
ALLOWED_KEYS = {"runners/node/samlify/sp-test-key.pem"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "local", "certs", "_to_delete"}
def files():
    if shutil.which("git") and os.path.isdir(".git"):
        out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True).stdout.split("\n")
        return [f for f in out if f and os.path.exists(f)]
    import fnmatch      # no git: approximate .gitignore (name or folder patterns only)
    pats = [l.strip().rstrip("/") for l in open(".gitignore", encoding="utf-8") if l.strip() and not l.startswith(("#", "!"))] if os.path.exists(".gitignore") else []
    ign = lambda n: any(fnmatch.fnmatch(n, p.lstrip("/")) for p in pats)
    res = []
    for r, d, fs in os.walk("."):
        d[:] = [x for x in d if x not in SKIP_DIRS and not ign(x)]
        res += [os.path.relpath(os.path.join(r, f)).replace(os.sep, "/") for f in fs if not ign(f)]
    return res
def text_of(f):
    if f.lower().endswith(".pdf"):
        if not shutil.which("pdftotext"): return ""
        return subprocess.run(["pdftotext", f, "-"], capture_output=True, text=True).stdout
    try: return open(f, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError): return ""
forbidden = []
if os.path.exists("local/forbidden.txt"):
    forbidden = [l.strip() for l in open("local/forbidden.txt", encoding="utf-8") if l.strip() and not l.startswith("#")]
PRIV = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
MAIL = re.compile(r"[\w.+-]+@[A-Za-z][\w-]*(?:\.[A-Za-z][\w-]*)*\.[A-Za-z]{2,}\b")
bad = []
for f in files():
    base = os.path.basename(f)
    if base == ".env" or f.endswith((".zip", "kc.key")) or f.startswith(("local/", "certs/kc")):
        bad.append((f, "must not be published")); continue
    t = text_of(f)
    if re.search(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY", t) and f not in ALLOWED_KEYS:
        bad.append((f, "private key"))
    for m in PRIV.finditer(t): bad.append((f, "private IP " + m.group(0)))
    for m in MAIL.finditer(t):
        a = m.group(0).lower()
        if not (a.startswith("noreply") or "@example." in a or a.endswith(("@users.noreply.github.com",))) and not re.search(r"\.(png|jpg|js|css)$", a):
            bad.append((f, "e-mail " + m.group(0)))
    low = t.lower()
    for w in forbidden:
        if w.lower() in low: bad.append((f, "forbidden string from local/forbidden.txt: " + w))
if bad:
    for f, why in sorted(set(bad)): print("FOUND  %-55s %s" % (f, why))
    sys.exit("\n%d problem(s). Fix them or move the content to local/." % len(set(bad)))
print("OK: nothing private found in %d files%s." % (len(files()), "" if forbidden else " (no local/forbidden.txt yet: add your real IPs and names there)"))

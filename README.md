# Keycloak / RHBK consumer-impact validation

Shows, **per client application and per client library**, what changes for the application when Keycloak / RHBK is upgraded from 26.0.x to 26.6.x, with evidence, so the problems are visible during staging and not on the first morning in production. Built for an air-gapped environment.

| Part | What it does |
|---|---|
| `kc_phase0.py` | Read-only inventory over the Admin API (GET only). Compares each client's configuration with documented breaking changes. Each rule cites an Upgrading Guide paragraph. Also checks issuer/hostname per route (D1). |
| `runners/` | Library runners: a tiny app per library logs in to Keycloak; an orchestrator plays the browser, compares with expectations per server version, redacts, writes JSON + HTML. 7 runners (Node and Python, OIDC and SAML). |
| `kc_dashboard.py` | One HTML page: status per client (Action required / Review / No impact found), library matrix per server version, observed changes between versions. |
| `fixtures/`, `tests/` | Test realms with known mistakes, expected results, offline tests (no Keycloak needed). |
| `docker-compose.yml`, `Dockerfile` | Three Keycloak versions side by side for the lab (26.0.8, 26.2.5, 26.6.4). |

## Quick start (lab, 10 minutes after the images are present)
```
cp .env.example .env            # edit HOST_IP, KC_ADMIN_PASSWORD, KC_IMAGE, KC_TAG_*
python scripts/demo.py certs
python scripts/demo.py all      # up, bootstrap, fixtures, runners, dashboard
```
Open `out_fixtures/dashboard.html`. Library runners need their packages first (see `docs/INSTALL-CHECKLIST.md`); without them the row says "Not installed", not "failed".
No Keycloak at hand? Open `docs/sample-output/dashboard.html` (real results from the lab) and run `python tests/offline_runner_check.py` (self-test).

## Documents
- `docs/Consumer-Impact-Briefing.pdf`: presentation of the approach and the results (27 pages).
- `docs/INSTALL-CHECKLIST.md`: air-gapped install, and how to connect to the real staging.
- `docs/DEMO-SCRIPT.md`: 15-minute demo, timings, likely questions.
- `docs/AI-PROMPT.md`: paste into Claude or another AI to continue on site (add libraries, rules, expectations).
- `docs/INVENTORY-TOOL.md`: reference for the inventory tool.
- `runners/README.md`: the runner framework.

The design discussion (v0.2, v0.3), the findings and the status notes live in the Claude project "Keycloak Deployment Test Application" and are not part of this archive.

## Keeping real settings out of the repository
Everything specific to your environment (real IPs, host names, admin password, staging commands, real results) goes in `local/`, which is git-ignored; see `local.example/README.md`. `scripts/demo.py` reads `local/.env` first. Before every push run `python scripts/check_public.py`: it fails on private IPs, e-mail addresses, private keys, tracked `.env` or zip files, and on anything you list in `local/forbidden.txt`.

## Safety
- Inventory is read-only. Outputs hold no tokens or secrets; the tools refuse to write output that contains a known secret or a JWT-looking string.
- **Test-only material is committed on purpose:** the fixture secrets (`rn-*-secret`, `fx-inventory-secret`), the test user password, and the SAML key pair in `runners/node/samlify/`. Never use them, or `--fixture-secrets`, against a real realm. Generated certificates and `.env` are git-ignored.
- Lab servers are upstream Keycloak images, not RHBK. Not yet run on 26.4, 26.6.6/26.6.7, staging or production.

## Requirements
Python 3.8+ (standard library only for the tools), Node 20.19+ or 22 for better-auth (18 is enough for the rest), openssl, Docker or Podman with compose (lab only). This project is MIT-licensed (`LICENCE`); see `LICENSE-NOTICE.md` for third-party libraries.

# On-site install checklist (air-gapped host)

Assumes: npm and PyPI mirrors work on the host, Keycloak images are in the local registry. Time: about 30 minutes plus first image start.

## A. Host prerequisites  ☐
- ☐ Python 3.8+ (`python3 --version`). Everything except the library runners uses the standard library only.
- ☐ Node 20.19+ or 22 (`node --version`). Node 18 runs all runners except better-auth (its dependencies declare 20.19+).
- ☐ `openssl` (certificate for the test containers), Docker or Podman with compose.
- ☐ Mirrors answer: `npm view samlify@2.13.1 version`, `npm view better-auth@1.7.1 version`, `pip download python3-saml==1.16.0 --no-deps -d /tmp/x`.
- ☐ RHEL 9 only, for python3-saml: if pip has no `xmlsec` wheel, install `gcc xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel pkgconf-pkg-config`.

## B. Install  ☐
1. ☐ Unpack the zip (or `git clone`) and `cd` into it.
2. ☐ `cp .env.example .env` and edit: `HOST_IP` (address the containers publish on), `KC_ADMIN_PASSWORD`, `KC_IMAGE` (your registry path, e.g. `registry.local:5000/keycloak/keycloak` or the RHBK image), `KC_TAG_*` (the tags you hold).
3. ☐ `python3 scripts/demo.py certs` (self-signed test certificate with `HOST_IP` in its SAN).
4. ☐ Libraries: `cd runners/node/passport-oauth2 && npm install`, same in `samlify` and `better-auth`; then `pip install -r runners/python/flask-oidc/requirements.txt -r runners/python/python3-saml/requirements.txt`.
5. ☐ Self-test without Keycloak: `python3 tests/offline_runner_check.py` and `python3 tests/offline_fixture_check.py` must print PASS / "0 not passing".
6. ☐ Everything locally: `python3 scripts/demo.py all` (starts three versions, creates the runner realm, runs fixtures and runners, builds `out_fixtures/dashboard.html`). A runner whose library is missing shows "Not installed" with the command; it is not a failure.

If an image is built from a registry that is not Docker Hub, the `Dockerfile` takes `KEYCLOAK_IMAGE` and `KEYCLOAK_VERSION` build arguments (set through `.env`). An image already tagged `kc-local:<tag>` is used as is.

## C. Connect to the real staging (read-only first)  ☐
**Staging only. Never production, never `--fixture-secrets` on a real realm.**

1. ☐ **Inventory account** (Keycloak team, once): confidential client `kc-inventory`, Service accounts on, other flows off, service-account roles `view-clients` and `view-realm` only (no `manage-*`).
2. ☐ Secret into the environment, not the command line: `export KC_CLIENT_SECRET=...`.
3. ☐ Run per datacenter, one `--route` for **every base URL consumers really use** (external, internal service name):
   `python3 kc_phase0.py inventory --base-url https://sso-staging-dc1... --label staging-26.6.x-dc1 --client-id kc-inventory --ca-bundle <internal-ca.pem> --server-version 26.6.x --route external=https://... --route internal=https://... --out out`
   Pass `--server-version` when the read-only account cannot read it. Check the `read_access` table in the report: a non-200 means a role is missing.
4. ☐ Compare datacenters: `python3 kc_phase0.py diff out/staging-...-dc1.json out/staging-...-dc2.json`.
5. ☐ Dashboard for the team leads: `python3 kc_dashboard.py out/staging-*.json --target 26.6.7 --out out/dashboard.html`. Skim the HTML before sharing.
6. ☐ **Runners on staging** (needs a realm with a test user and test clients; this needs admin rights, so decide who):
   - Option 1: Keycloak team imports `fixtures/runner/fx-runner-realm.json`. Before import, replace the `rn-*-secret` values and the `rn-user` password in a copy.
   - Option 2: use `runners/bootstrap_realm.py` with `KC_ADMIN_PASSWORD` set, on a staging that allows it.
   - Redirect URIs point to `127.0.0.1:3100-3105`; run the runners on a host that can reach staging and trusts its CA (`--ca-bundle`).
   - Secrets per runner: `RN_CLIENT_SECRET__PASSPORT_OAUTH2`, `RN_CLIENT_SECRET__FLASK_OIDC`, `RN_CLIENT_SECRET__BETTER_AUTH`, `RN_CLIENT_SECRET__PLAIN_HTTP_CODE`, `RN_SVC_SECRET`, `RN_ROPC_SECRET` (or plain `RN_CLIENT_SECRET`).
   - `python3 runners/orchestrate.py --issuer https://<staging>/realms/fx-runner --server-version 26.6.x --ca-bundle <ca.pem> --out out_runners`, then rebuild the dashboard with `--runners out_runners/runners-*.json`.
7. ☐ Delete the test realm when done. Results contain no tokens or secrets (the tool refuses to write them), but review before sending out.
8. ☐ Weekly use: schedule steps 3 and 5 (cron or an OpenShift CronJob with the secret mounted from an OpenShift Secret) and publish `dashboard.html` on an internal page.

## D. Known limits to say out loud
Lab servers were upstream Keycloak, not RHBK. Not yet run on 26.4, 26.6.6/26.6.7, staging, or a real client export. Test SAML key pair in the repo is **test-only**.

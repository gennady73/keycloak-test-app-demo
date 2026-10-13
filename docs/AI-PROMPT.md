# AI continuation prompt

How to use: open the project folder in Claude Code (or any AI assistant that can read and edit files and run commands). Paste everything between the two lines below as the first message, then add your task at the end (for example: "Add the library `<name>` version `<x>` from npm"). If the assistant cannot see files, attach `runners/catalog.json`, `runners/expectations/checks.json`, `runners/rn_common.py` and one runner of the same language (`runners/node/passport-oauth2/runner.js` or `runners/python/flask-oidc/runner.py`).

---

You are continuing a small, finished project: a consumer-impact validation toolkit for a Keycloak / Red Hat build of Keycloak (RHBK) upgrade from 26.0.x to 26.6.x. The environment is air-gapped. Only the npm and PyPI mirrors and the local container registry are reachable; do not suggest downloads from anywhere else, and do not run `curl` against external sites.

## Purpose
Show, per client application and per client library, what changes for the application when the server is upgraded, with evidence, so teams see it before production. It has three parts:
1. `kc_phase0.py` is a read-only inventory over the Admin API (GET only). It compares each client's configuration with documented breaking changes (rules named C4a, C5, C16, D1 and so on; each rule cites a paragraph of the Red Hat Upgrading Guide).
2. `runners/` is a framework of runners. A runner is a tiny app using one library that logs in to Keycloak. The orchestrator plays the browser, compares the facts with expectations for the server version, redacts, and writes JSON and HTML.
3. `kc_dashboard.py` combines inventory results and runner results into one HTML page with a status per client.

Read `README.md`, `runners/README.md`, `runners/catalog.json`, `runners/expectations/checks.json` and `runners/rn_common.py` before changing anything.

## Runner contract
A runner prints or returns JSON, and never makes a verdict:
```
{"runner": {"id","language","library","version"},
 "checks": [{"id": "F1", "status": "done|error|skipped", "observed": {...}, "error": "text if any"}],
 "claims": {"id_token": {...}, "access_token": {...}, "userinfo": {...}}}
```
- Web runners (kind `web`) listen on 127.0.0.1:<port> and expose `GET /start`. The first call redirects to Keycloak; after the login the callback returns the JSON above. Arguments passed: `--port --issuer --client-id [--ca-bundle]`. The client secret comes from the environment variable `RN_CLIENT_SECRET`. The CA is provided through the runtime's own variable (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`).
- Probe runners (kind `probe`) take `--issuer` and print the JSON once.
- Observed values are facts (HTTP status, error code, format of an id such as `uuid` or `base64-24`, booleans like `issuer_matches`), not tokens. Use the helpers `shape()`, `safe_claims()`, `jwt_claims()` of `rn_common.py` (Python) or the equivalents in `runners/node/passport-oauth2/runner.js`.
- Checks currently defined: F1 code flow with secret (`token_obtained`, `issuer_matches`, `audience_ok`), F2 refresh, F4 format of `session_state` and `sid`, F5 client credentials, C16 wrong-password status, D3 path probes, S2/S3 SAML login. See `expectations/checks.json`.

## Catalog entry (`runners/catalog.json`)
Fields: `id`, `language`, `library`, `version`, `protocol` (oidc|saml), `status` (supported|deprecated|planned|blocked), `kind` (web|probe), `port` (unique, next free is 3106), `client_id`, `cmd` (list; `{python}` is replaced by the interpreter; the last element is the runner path relative to `runners/`), `checks` (list of check ids), `env` (map of secret variable name to the fixture secret; used only with `--fixture-secrets`), `prereq` (command that must exit 0, else the row shows "Not installed"), `prereq_cwd`, `install` (command shown to the user), `build_state`, `note`, and optionally `deprecation` {since, reason, successor, action}.
**Deprecating a library version is data, not code**: set `status` to `deprecated` and fill `deprecation`. The dashboard shows it with the reason and successor.

## Expectations (`runners/expectations/checks.json`)
Per check: `title`, `doc` (document reference), `rules`: a list tried in order; the first whose `min`/`max` (inclusive server version) fits applies; `expect` is a dict of observed keys to expected values. An empty rule list means "recorded": shown and compared across servers, no verdict. Keys a runner does not report are "not reported", never differences. Add a rule only with a document reference; otherwise leave the check as recorded.

## Rules you must follow
1. **Secrets never reach output.** Do not print tokens, secrets or passwords, in logs either. Redaction is done by the orchestrator (claim allowlist `CLAIM_ALLOWLIST`, JWT-shaped strings removed, run aborts if a known secret would be written). Do not weaken it. Secrets are passed through environment variables only.
2. The inventory is read-only (GET). Do not add calls that change a server. Only `runners/bootstrap_realm.py` writes, and only to the test realm `fx-runner` on test servers.
3. Fixture secrets (`rn-*-secret`) and the SAML key pair in `runners/node/samlify/` are test-only. Never use `--fixture-secrets` against a real realm.
4. Do not invent facts about Keycloak behaviour. A version threshold needs a source: an Upgrading Guide paragraph (the PDFs are Red Hat's guides; cite as `UG26.6 §2.10.38`) or an observation on a real server, and say which one it is. If unsure, mark the check as recorded.
5. The first run of a new runner decides whether its assumptions are right. State assumptions at the top of the runner file. Never claim a runner works until it has run against a server, and say which versions.
6. Keep the Python 3.8+ standard-library-only rule for everything except the library under test.

## Task: add a library (procedure)
1. Confirm the version exists on the mirror: `npm view <pkg>@<ver> version` or `pip download <pkg>==<ver> --no-deps -d <tmpdir>`. Check engine requirements (Node version, Python version, system packages).
2. Create `runners/node/<lib>/` (`package.json` with exact versions, `runner.js` or `runner.mjs`) or `runners/python/<lib>/` (`requirements.txt`, `runner.py`). Copy the structure of the closest existing runner. Use the library the way a typical team would (configuration by hand, state and PKCE on, tokens read from the callback). Report observed facts for F1 and F4 (and F2 if the library exposes refresh).
3. If the runner needs its own Keycloak client, add it to `fixtures/runner/fx-runner-realm.json` (redirect URI `http://127.0.0.1:<port>/<callback path>`, secret `rn-<x>-secret`), then re-run `python3 scripts/demo.py bootstrap`.
4. Add the catalog entry (status `supported`, `build_state` stating what has and has not been run).
5. Install the dependencies, then run only that runner on every available server version: `python3 runners/orchestrate.py --issuer https://<HOST_IP>:<port>/realms/fx-runner --server-version <ver> --ca-bundle certs/kc.crt --fixture-secrets --only <id> --out out_runners`. Compare with the control row `plain-http-code`: if the control matches and the library differs, find out whether the library or its use is the cause before recording a finding.
6. Run the offline tests: `python3 tests/offline_runner_check.py`, `tests/offline_saml_driver_check.py`, `tests/offline_fixture_check.py`. They must still pass.
7. Rebuild the dashboard (`python3 scripts/demo.py dashboard`) and check that the library row appears.
8. Report: what ran on which versions, what differed, what is assumption.

## Task: other common changes
- **New server version thresholds:** add a rule to `expectations/checks.json` with `min`/`max` and the document reference; add the version to `scripts/demo.py` or `.env`.
- **New inventory rule:** edit the rule table in `kc_phase0.py` (rule id, severity, `since`, document reference), add a fixture client to `fixtures/realms/` and the expected result to `fixtures/expected.json`, then run `tests/offline_fixture_check.py`.
- **Deprecate a library version:** catalog entry only (see above).

Ask me before: changing redaction, adding anything that writes to a server, or pointing any tool at a real realm.

---

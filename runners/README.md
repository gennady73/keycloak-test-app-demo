# Runner framework (Phase 2, first batch)

A runner is a small program that logs in to Keycloak the way a team's application does, with one library, and
prints a result. The orchestrator starts it, plays the browser (submits the login form with the test user),
compares the observations with the **expectation for the server version**, redacts, and writes JSON + HTML.

| File | Purpose |
|---|---|
| `catalog.json` | The catalog: language, library, version, protocol, status (`supported` / `deprecated` / `planned` / `blocked`), checks, install hint. Deprecation is a field, not code. |
| `expectations/checks.json` | Expected result per check and server version, with the document reference. Empty rule list = "recorded" (shown, no verdict). |
| `orchestrate.py` | Runs the catalog, writes `out_runners/runners-<version>.json/.html`. |
| `rn_common.py` | Result contract, claim allowlist, secret/JWT scrubbing, the unattended login driver. |
| `bootstrap_realm.py` | Creates realm `fx-runner` through the Admin API (kept out of the startup import). |
| `http_probe.py` | No library: D3 path probes, C16 wrong-password status, F5 client credentials. |
| `plain_code_runner.py` | No library: the authorization-code flow written by hand. This is the **control**. |
| `node/passport-oauth2/` | passport-oauth2 1.8.0 (ran on 26.0.8, 26.2.5 and 26.6.4). |
| `python/flask-oidc/` | flask-oidc 2.4.0 (ran on 26.0.8, 26.2.5 and 26.6.4). |
| `node/samlify/` | samlify 2.13.1, SAML service provider (ran on three versions). |
| `python/python3-saml/` | python3-saml 1.16.0, SAML service provider (ran on 26.0.8, 26.2.5, 26.6.4). |
| `node/better-auth/` | better-auth 1.7.1, generic OAuth plugin, in-memory storage (ran on three versions). |

## Run
1. `python scripts/demo.py up`, then `python scripts/demo.py bootstrap` (admin password from `.env`).
2. `python scripts/demo.py runners`. The two probes run with nothing to install.
3. Libraries: `cd runners\node\passport-oauth2 && npm install`, and `pip install -r runners\python\flask-oidc\requirements.txt`.
   SAML: `cd runners\node\samlify && npm install`, and `pip install -r runners\python\python3-saml\requirements.txt`. Rerun `python scripts/demo.py bootstrap` once (it adds the two SAML clients), then step 2; the library rows now run instead of showing "Not installed".

## Reading a result
- **Matches expectation**: the server behaved as documented for this version.
- **Differs from expectation**: either the server changed behaviour (a finding), or the library does something unexpected. Compare with the control row (`plain-http-code`): if the control matches and the library differs, the library or its use is the cause.
- **Recorded**: a value shown without a verdict, because no documented expectation exists yet. Compared across servers it still shows changes.
- **Not exercised / Not installed**: not a failure.

## Safety
Secrets are passed only through environment variables of the child process. Claims are reduced to an allowlist in the
orchestrator; JWT-shaped strings and secret values are removed; the run aborts if a known secret would reach the output.
`--fixture-secrets` uses the fixed test values of the fx-runner realm; never use it against a real realm.

## What is verified and what is not
Verified offline (tests/offline_runner_check.py, against tests/mock_oidc.py): orchestrator, expectations, login
driver, probes, control runner, redaction. **Run for real** on upstream Keycloak 26.0.8, 26.2.5 and 26.6.4 (see `docs/sample-output`). **Not verified:** staging/production, RHBK images, 26.4, 26.6.6/26.6.7. Each runner's assumptions are listed at the top of its file.

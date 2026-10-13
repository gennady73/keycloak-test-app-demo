> Reference for `kc_phase0.py` (the read-only inventory). The `.bat` files mentioned below were replaced by `python scripts/demo.py <step>`; see the top-level README. Paths such as `192.0.2.10` are examples from the lab.

# Phase 0 - read-only consumer-impact discovery

One file, `kc_phase0.py`, Python 3.8+ standard library only (your Python 3.10.9 is fine). No pip, nothing to mirror.
It sends only GET requests to the Admin API (plus one client-credentials token request). It never changes Keycloak.

## 1. Prepare the read-only account (once per realm that holds it, e.g. master)
Create a confidential client with **Service accounts enabled**, Standard/Direct flows OFF.
Give its service account only `view-clients` and `view-realm`. Where those roles live depends on where the client is:
- Client in **master**: on the *Service account roles* tab choose *Assign role -> Filter by clients* and pick `view-clients` and `view-realm` of the `<realm>-realm` client (e.g. `corp-realm`) for each realm to inspect. (`admin` realm role also works but is far too broad.)
- Client in the **inspected realm itself**: pick them from `realm-management`. Then use `--auth-realm <that realm>` and `--realm <that realm>`; this reads one realm only.
- Windows cmd: `set KC_CLIENT_SECRET=value` with **no quotes** (cmd keeps them); PowerShell: `$env:KC_CLIENT_SECRET='value'`.
`view-system`/server info may be restricted on 26.6.6, so pass `--server-version` if the version is not readable.

## 2. Run (staging 26.6.6 first, then repeat per DC)
    export KC_CLIENT_SECRET='...'            # or use --secret-file
    python3 kc_phase0.py inventory \
      --base-url https://sso-staging-dc1.example.org --label staging-26.6.6-dc1 \
      --client-id kc-inventory --ca-bundle /path/internal-ca.pem \
      --route external=https://sso-staging-dc1.example.org \
      --route internal=https://keycloak.keycloak.svc:8443 \
      --health mgmt=https://keycloak.keycloak.svc:9000/health/ready \
      --out out

Add `--realm NAME` (repeatable) to limit realms; without it all realms except `master` are read.
`--route` is repeatable: list **every base URL consumers really use** (external, internal service name, per DC).
It fetches the discovery document through each, compares issuer/endpoint host and port with the route (D1, the issuer incident),
and checks the root `/.well-known/oauth-authorization-server/realms/{realm}` path (D2).

## 3. Read the result
`out/<label>.html` is the report: "N of M clients have findings", each row with rule, introduced-in release, whether the server already has that change, and guide section.
`out/<label>.json` is the same data for diffing:

    python3 kc_phase0.py diff out/staging-26.6.6-dc1.json out/staging-26.6.6-dc2.json

The **`read_access`** table (X1) shows which Admin API calls the account was allowed; non-200 means a role is missing.

## 4. What may be shared
Only clientId, URIs, flags, and non-secret attributes are kept. Secret-like attribute values show `[redacted]`.
The tool refuses to write output if it contains your secret or a JWT-looking string. Still skim the HTML before sending it out.

## Known limits (be honest about them)
- Attribute names for C8 (token exchange) and C10 (introspection/userinfo compatibility) are matched by pattern, not an exact list: confirm against a real client in your 26.0.17 console. The first run on the SSO team's own client is the check.
- C19 (legacy account linking) is not visible through the client list; it needs events or ingress logs.
- C6 is meaningful only where the `secure-client-uris` executor is used; the report says whether the realm has it.
- C5 shows "on server: not yet" on 26.6.6; it is a next-patch risk.
- Not covered in Phase 0: runners, UI, events, headless login. The tool was tested only against a mock server here, not a real RHBK.

## Local Keycloak in a container (for testing the tool)
Requires Docker 20.10 or later; no BuildKit features are used.

    docker build -t kc-local:26.6.4 --build-arg KEYCLOAK_VERSION=26.6.4-1 .
    docker run -d --name kc-local -p 8080:8080 -p 9000:9000 \
      -e KC_BOOTSTRAP_ADMIN_PASSWORD='choose-one' kc-local:26.6.4

- Admin Console: http://localhost:8080 (user `admin`). Readiness: http://localhost:9000/health/ready
- Data is in the container only (`dev-file` database); `docker rm -f kc-local` resets it. Add `-v kcdata:/opt/keycloak/data` to keep it.
- Create the read-only inventory client (section 1), then run the tool with `--base-url http://localhost:8080` and `--health local=http://localhost:9000/health/ready`.
- Reproducing the hostname incident: change `-e KC_HOSTNAME=...` or put a proxy in front and set `KC_PROXY_HEADERS=xforwarded`; then `--route` the proxy URL and the direct URL and watch D1.

## Fixture tests: import known realms, compare with expected results
Files: `fixtures/realms/fx-legacy-realm.json`, `fixtures/realms/fx-baseline-realm.json`, `fixtures/expected.json`, `run_fixture_tests.py`.
Each realm carries its own `kc-inventory` client (secret `fx-inventory-secret`, test data only) with a service account holding `view-clients` and `view-realm`.

1. Check the fixtures against the tool's own rules, no Keycloak needed: `python tests/offline_fixture_check.py` (expect 0 not passing for both versions).
2. Start a container that imports them (PowerShell). This is the command that worked for the setup with the container on a LAN address (192.0.2.10 in the example): the ports are published on that IP, `KC_HOSTNAME` uses the same IP, and the certificate has that IP in its subject alternative names. On a plain `localhost` setup the IP parts are optional: drop the `192.0.2.10:` prefixes and use `https://localhost:8443`.

       docker run -d --name kc-fx -p 192.0.2.10:8443:8443 -p 192.0.2.10:9000:9000 `
         -v "${PWD}\certs:/opt/keycloak/certs:ro" `
         -v "${PWD}\fixtures\realms:/opt/keycloak/data/import:ro" `
         -e KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/certs/kc.crt -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/certs/kc.key `
         -e KC_HOSTNAME=https://192.0.2.10:8443 -e KC_BOOTSTRAP_ADMIN_PASSWORD='choose-one' `
         kc-local:26.6.4 start --optimized --import-realm

   Mount only `fixtures\realms`: Keycloak tries to import every JSON file in the import folder as a realm, and `expected.json` is not one.

3. Run: `python run_fixture_tests.py --base-url https://192.0.2.10:8443 --ca-bundle certs\kc.crt --label fx-26.6.4` (or use `fixtures-test.bat`)
4. Repeat on a 26.0.x container (build with `--build-arg KEYCLOAK_VERSION=<26.0.x tag>`, other port). The rule sets must be identical; the `present_on_server` flags must differ, and `verify` checks both.

Things to check first (not verified here): the realm import creates the service-account role mapping; the import keeps every attribute as written; the Admin Console shows the attributes the way the fixtures set them. Attribute names for C10 and the legacy params attribute are not in the fixtures until you export a real client once.

## Several versions at once with Docker Compose
`docker-compose.yml` + `.env` define three services that share the same `certs` and `fixtures\realms` folders (read-only bind mounts, so nothing is copied and the containers can run alone or together):

| Service | Image tag (in .env) | Host ports (HTTPS / management) |
|---|---|---|
| kc-2608 | 26.0.8-1 | 8460 / 9060 |
| kc-262 | 26.2.5-0 | 8462 / 9062 |
| kc-266 | 26.6.4-1 | 8466 / 9066 |

    docker compose up -d kc-266      # one version (docker-compose up -d kc-266 with the older standalone tool)
    docker compose up -d             # all three
    docker compose down              # remove the containers: the next start imports the fixtures into a fresh database
    fixtures-test-all.bat            # runs the fixture tests on every version (waits for the import to finish)

Edit `.env` for `HOST_IP` (must be in the certificate's subject alternative names) and the tags. If an image `kc-local:<tag>` already exists it is used as is; otherwise compose builds it from the Dockerfile.
Old-version note: a finding about something that does not exist yet on the server (for example the root `/.well-known/` path before 26.4.2) is shown as informational and not counted in the headline.

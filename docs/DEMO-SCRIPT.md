# Demo script (about 15 minutes)

Setup done the day before (see INSTALL-CHECKLIST.md B): images present, `python3 scripts/demo.py all` finished once, so results and `out_fixtures/dashboard.html` exist. Before the room fills: `python3 scripts/demo.py up` (containers take 30-60 s), open the dashboard in a browser, keep a terminal in the project folder.

**Fallback if Docker misbehaves:** open `docs/sample-output/dashboard.html`. It is the same page built from real runs, so the whole story works without any server.

| Min | Do | Say |
|---|---|---|
| 0:00 | Slide 1 of the PDF | "A Keycloak upgrade can succeed while applications break. Today we learn that on day one of production. This shows impact per client before then." |
| 1:00 | Dashboard top. Hover the three tiles | "Three states, each with its explanation. 3 need action, 7 need a look, 7 have nothing documented. The line below also says what 'UG26.6 §2.10.38' means: a paragraph of the Red Hat Upgrading Guide." |
| 3:00 | Scroll to `fx-multi` | "One client, four findings, each with the rule, the version it starts in, and the document. No team had to test anything; this comes from the client's configuration." |
| 5:00 | Scroll to "What the servers do differently" | "These are not only read from guides. Three real servers, same login, different answers: **wrong password 401 → 400**, **session id UUID → 24 characters**, **paths with `//` `..` `;` 200 → 400**. An application that parses the id as a UUID, or checks for 401, breaks." |
| 7:00 | Library section | "Seven libraries, three servers. The control row is the same flow written without a library: if it passes and a library fails, the library is the cause. The grey `samlify <2.10.0` row is deprecated by data (CVE-2025-47949), no code. That is the soft push to upgrade." |
| 9:00 | Terminal, live: `python3 runners/orchestrate.py --issuer https://<HOST_IP>:8466/realms/fx-runner --server-version 26.6.4 --ca-bundle certs/kc.crt --fixture-secrets --only passport-oauth2 --out out_demo` | "One library, one real login, about 10 seconds. The orchestrator plays the browser and removes tokens and secrets from the output." |
| 11:00 | Terminal, live: `python3 scripts/demo.py d1` | "The hostname incident: the server answers on one port and advertises another. Check D1 flags the issuer mismatch." (Expect findings above 0.) |
| 13:00 | Slide "Proposed on-site step" | "Three outcomes: you like it, we point it at staging read-only. You don't, nothing else depends on it. You want more libraries, we add NPM or Python ones on site, one file and one catalog entry each. Which one?" |

## Likely questions
- **Does this replace team testing?** No. It finds known, documented changes early and per client; behaviour specific to an application still needs its team.
- **Is it safe on staging?** The inventory only reads. Runners need a test realm, which is separate and removable. Output never holds tokens or secrets.
- **Why not RHBK in the lab?** Upstream images were available; behaviour matches closely, patch numbers differ. First run on staging is the real check.
- **Go, Java, .NET?** Deferred until we know which libraries the teams actually use.

After the demo: `python3 scripts/demo.py down`.

# local/ (not in this repository)

Create a folder `local/` next to this one. It is listed in `.gitignore`, so nothing in it is ever committed or published.
Put here everything that describes your real environment:

| File | Content |
|---|---|
| `local/.env` | Real `HOST_IP`, admin password, `KC_IMAGE`, tags. Overrides `.env`; `scripts/demo.py` reads it and passes it to compose. |
| `local/forbidden.txt` | One string per line that must never appear in published files: real IPs, host names, company or project names, team names. `python scripts/check_public.py` fails if any is found. |
| `local/staging.cmd` / `staging.sh` | Your real staging commands (routes, realm names, CA path). Secrets stay in environment variables or a secret store, not in this file. |
| `local/notes/` | Real inventory exports, client lists, screenshots, meeting notes. |

Before every push: `python scripts/check_public.py`.

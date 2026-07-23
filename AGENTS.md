# AGENTS.md — FlawedToken

Intentionally vulnerable OAuth 2.0 lab. Every misconfiguration is deliberate. **Do not accidentally fix the flaws** unless explicitly toggling the relevant environment variable.

---

## Services

| Service | Directory | Port |
|---|---|---|
| Auth Server | `auth-server/` | 8001 |
| Client App | `client-app/` | 8000 |

Each has its own `requirements.txt` and `Dockerfile`. No monorepo tooling. The two services are independent.

---

## Key Commands

```bash
# Environment setup (required before first run)
cp .env.example .env

# Start both services (canonical)
docker compose up

# Force image rebuild
docker compose up --build

# Stop
docker compose down

# Restart after .env changes (flaw toggles are read at import time — restart required)
docker compose down && docker compose up

# Run integration tests (services must be STOPPED first — harness spawns them itself)
python tests/validation_harness.py

# Run auth-server locally without Docker
SC_SERVICE=auth-server python auth-server/app.py

# Run client-app locally without Docker
SC_SERVICE=client-app python client-app/app.py
```

No lint, format, typecheck, or build steps are configured.

---

## Testing

- **No pytest.** The harness (`tests/validation_harness.py`) is a standalone script using plain `assert`.
- **Stop Docker before running the harness.** It binds ports 8001 and 8000 itself; a running `docker compose up` will conflict.
- **`tests/acceptance_fixture.json` is auto-generated golden output.** Do not hand-edit it; re-run the harness to regenerate.
- **The harness checks that `auth-server/sc_events.py` and `client-app/sc_events.py` are byte-identical as its first assertion.** If you edit `sc_events.py`, you must update both copies.

### Known bug
Running `python auth-server/sc_events.py` (or the client-app copy) directly raises `AssertionError` — the smoke test asserts `schema_version == "1.0"` but `SCHEMA_VERSION = "1.1"`. The integration harness is unaffected.

---

## sc_events.py — The Instrumentation System

Both services emit structured JSON-line events to stdout. This file **must be byte-identical** in both `auth-server/` and `client-app/`.

- **Forbidden key names** in event `data` (never use raw values): `code`, `authorization_code`, `auth_code`, `token`, `access_token`, `refresh_token`, `bearer`, `client_secret`, `secret`, `password`, `passwd`, `pwd`. Use `code_fp` / `token_fp` (fingerprints) instead.
- **Strict mode** (`SC_STRICT=on`, used by harness): raises `ValueError` on forbidden keys instead of silently scrubbing.
- **`SC_SERVICE`** is set per-container in `docker-compose.yml`, **not** in `.env`. Adding it to `.env` would make both containers use the same service name, breaking event attribution.

---

## Environment Variables

| Variable | Default | Notes |
|---|---|---|
| `FLAW_CODE_INTERCEPTION` | `on` | `on` = PKCE disabled (exploitable). `off` = PKCE enforced. |
| `FLAW_REDIRECT_URI_VALIDATION` | `on` | `on` = any redirect_uri accepted. `off` = strict allowlist. |
| `AUTH_SERVER_URL` | `http://auth-server:8001` | Docker-internal URL (service-to-service). |
| `AUTH_SERVER_BROWSER_URL` | `http://localhost:8001` | Browser-facing URL (used in redirects). |
| `CLIENT_APP_URL` | `http://localhost:8000` | Used by auth-server to build the redirect URI allowlist at startup. Change port here too if you change the client port. |
| `SC_SERVICE` | (per container) | Set in `docker-compose.yml`, not `.env`. |

Flaw toggles are evaluated **once at module import time** — changing `.env` requires a full restart.

---

## Architecture Notes

- **No database.** `auth_codes` and `access_tokens` are plain Python dicts in-process memory. Any restart clears all state.
- **Dual URL config for auth server:** `AUTH_SERVER_URL` (Docker DNS, for server-to-server calls) vs `AUTH_SERVER_BROWSER_URL` (localhost, for browser redirects). Docker containers cannot resolve `localhost:8001` to the host.
- **`auth-server/users.json`** is loaded fresh on every `POST /authorize` — not cached.
- **`index.html` hardcodes flaw status as "ON"** regardless of actual env vars. Cosmetic only.
- **`requirements.txt` pins** (`flask==3.0.3`, `requests==2.32.3`) may differ from the local `.venv` (which has newer versions). Dockerfiles install exactly what `requirements.txt` specifies.

---

## Test Users

| Username | Password |
|---|---|
| `alice` | `password` |
| `bob` | `password` |

Stored and compared in plaintext — intentional for the lab.

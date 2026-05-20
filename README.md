# FlawedToken

A purpose-built vulnerable OAuth 2.0 environment for security researchers,
red teamers, and anyone learning auth attack techniques.

FlawedToken is intentionally broken. Every misconfiguration is deliberate,
documented, and toggleable. Use it to practice OAuth attack flows in a safe,
controlled environment before running them against authorized targets.

---

## What's Inside

FlawedToken ships two services:

- **auth-server** — a minimal OAuth 2.0 Authorization Server with toggleable flaws
- **client-app** — a relying party client application that trusts it incorrectly

Both services run together via Docker Compose. One command and the full
environment is up.

---
<img width="452" height="493" alt="FlawedToken" src="https://github.com/user-attachments/assets/4bc5165d-8843-4e72-9a90-50c4de6dc2fb" />

---

## Quickstart

```bash
git clone https://github.com/tstacy/flawedtoken.git
cd flawedtoken
cp .env.example .env
docker compose up
```

- Auth Server: `http://localhost:8001`
- Client App: `http://localhost:8000`

---

## Active Flaws (Phase 2)

Each flaw is toggled via environment variable in your `.env` file.

| Flaw | Variable | Default | Description |
|---|---|---|---|
| Auth Code Interception | `FLAW_CODE_INTERCEPTION` | `on` | Authorization server does not bind auth codes to client state, enabling interception and replay. |
| Redirect URI Validation | `FLAW_REDIRECT_URI_VALIDATION` | `on` | Redirect URI allow-list validation is disabled. Any URI is accepted, including open redirects and subdomain variants. |

Set a variable to `off` to enable the correct, secure behavior. This lets you
compare the broken and fixed state side by side.

```env
# .env.example
FLAW_CODE_INTERCEPTION=on
FLAW_REDIRECT_URI_VALIDATION=on
```

---

## Attack Flows

Step-by-step walkthroughs for each flaw live in `/docs`:

- [Flaw 01 — Auth Code Interception](docs/flaw-01-auth-code-interception.md)
- [Flaw 02 — Redirect URI Manipulation](docs/flaw-02-redirect-uri-manipulation.md)

Each doc covers:
- What the misconfiguration is
- Why it exists in real applications
- How to reproduce the attack against FlawedToken
- What the fixed behavior looks like
- Detection guidance for defenders

---

## Pairing with ShroudCloud

FlawedToken is the demo target for [ShroudCloud](https://shroudcloud.com) —
purpose-built OAuth attack infrastructure for authorized red team operations.

The `docs/` walkthroughs show the manual attack path. ShroudCloud automates
the same flows against any authorized target, with configurable IdP and RP
components and full session capture.

ShroudCloud is currently in private beta. [Join the waitlist](https://shroudcloud.com/#access).

---

## Roadmap

FlawedToken ships in phases alongside ShroudCloud.

| Phase | Flaws |
|---|---|
| Phase 2 (current) | Auth code interception, redirect URI manipulation |
| Phase 3 | Token relay, PKCE downgrade, SAML assertion replay |
| Phase 4+ | MFA bypass scenarios, refresh token abuse, cross-tenant OIDC |

---

## Who This Is For

- **Red teamers and pentesters** practicing OAuth attack flows before an engagement
- **Security engineers** understanding what misconfigurations look like from the
  attacker's perspective
- **Detection engineers** building rules against OAuth attack patterns
- **Cert prep** (OSCP, BSCP) covering auth exploitation labs

---

## Rules of Engagement

FlawedToken is for use in authorized testing environments only.

- Do not point FlawedToken at production systems
- Do not use the attack flows documented here against targets you do not have
  explicit written authorization to test
- The misconfigurations here are real. Treat the techniques accordingly.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Related

- [ShroudCloud](https://shroudcloud.com) — OAuth attack infrastructure for authorized red team operations
- [cctbp.com](https://cctbp.com) — Security research blog covering auth attack techniques in depth

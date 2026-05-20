# Flaw 01 — Authorization Code Interception

**Variable:** `FLAW_CODE_INTERCEPTION`
**Default:** `on` (misconfiguration active)

---

## What This Flaw Is

When a user authenticates via OAuth 2.0, the authorization server issues a
short-lived authorization code and redirects the user's browser to the client
application's redirect URI with the code as a query parameter.

The client application is supposed to exchange that code for an access token
in a back-channel server-to-server request that includes the client secret.

This flaw disables state parameter binding on the authorization code. The
authorization server does not verify that the state value in the token exchange
request matches the state value issued at the start of the flow. This allows
an attacker who can intercept the authorization code to exchange it themselves
before the legitimate client does.

---

## Why This Exists in Real Applications

- State parameter validation is often treated as optional CSRF protection rather
  than a core integrity control
- Developers copy OAuth flow examples that omit state validation
- Third-party OAuth libraries sometimes implement state as optional
- Legacy integrations predate state parameter guidance in RFC 6749

---

## Reproducing the Attack Against FlawedToken

### Prerequisites

- FlawedToken running locally (`docker compose up`)
- `FLAW_CODE_INTERCEPTION=on` in your `.env`
- A tool for intercepting HTTP redirects (Burp Suite, mitmproxy, or curl)

### Steps

1. Open the client app at `http://localhost:8000` and click **Login**

2. The client app redirects you to the auth server's authorization endpoint:
   ```
   http://localhost:8001/authorize?response_type=code&client_id=flawedtoken-client&redirect_uri=http://localhost:8000/callback&state=SOMESTATE
   ```

3. Approve the authorization request

4. The auth server redirects back with the authorization code:
   ```
   http://localhost:8000/callback?code=AUTH_CODE_HERE&state=SOMESTATE
   ```

5. Intercept this redirect before it reaches the client app callback

6. Exchange the intercepted code yourself from a separate session:
   ```bash
   curl -X POST http://localhost:8001/token \
     -d "grant_type=authorization_code" \
     -d "code=AUTH_CODE_HERE" \
     -d "redirect_uri=http://localhost:8000/callback" \
     -d "client_id=flawedtoken-client" \
     -d "client_secret=flawedtoken-secret"
   ```

7. The auth server issues an access token to your request. The legitimate
   client's subsequent exchange attempt will fail — the code has already been used.

---

## Fixed Behavior

Set `FLAW_CODE_INTERCEPTION=off` and restart:

```bash
docker compose down && docker compose up
```

With the flaw disabled, the authorization server cryptographically binds the
authorization code to the PKCE code challenge (or state value) provided at
the start of the flow. The token exchange request must include the matching
verifier. An intercepted code without the verifier cannot be exchanged.

---

## Detection Guidance

Signs of authorization code interception in your logs:

- Token exchange requests arriving from a different IP than the authorization request
- Failed token exchanges following a short window after a successful one (legitimate
  client arriving after the attacker)
- Authorization codes appearing in server-side logs or Referer headers
- Unusual user-agent strings on token exchange requests vs authorization requests

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

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 — PKCE for OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- cctbp.com — *OAuth Relay Attacks: How Authorization Codes Get Stolen* (link when published)

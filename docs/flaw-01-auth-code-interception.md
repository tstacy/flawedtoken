# Flaw 01 — Authorization Code Interception

**Variable:** `FLAW_CODE_INTERCEPTION`
**Default:** `on` (misconfiguration active)

---

## What This Flaw Is

When a user authenticates via OAuth 2.0, the authorization server issues a
short-lived authorization code and redirects the user's browser to the client
application's redirect URI with the code as a query parameter.

For a public client (a single-page app, a mobile app, or any client that cannot
keep a secret), there is no client secret to prove that the party redeeming the
code is the same party that started the flow. PKCE (Proof Key for Code Exchange,
RFC 7636) fills that gap: the client generates a random `code_verifier` at the
start of the flow, sends only its hash (`code_challenge`) to the authorization
server, and presents the `code_verifier` itself at the token exchange. The
authorization server issues a token only if the verifier hashes to the
challenge it stored.

This flaw disables PKCE verification at the token endpoint. The authorization
server ignores the `code_verifier` and issues a token to anyone presenting a
valid code. An attacker who intercepts the authorization code can redeem it
directly, because the proof-of-possession check that would stop them is turned
off.

---

## Why This Exists in Real Applications

- PKCE was optional under RFC 6749 and only became mandatory for public clients
  in the OAuth 2.1 draft and current security BCP
- Older SDKs and copied flow examples omit PKCE entirely
- Some servers accept a `code_challenge` at authorize time but never enforce the
  `code_verifier` at token time, which is functionally identical to no PKCE
- Confidential-client assumptions get carried over to public clients that cannot
  actually protect a secret

---

## Reproducing the Attack Against FlawedToken

### Prerequisites

- FlawedToken running locally (`docker compose up`)
- `FLAW_CODE_INTERCEPTION=on` in your `.env`
- A tool for intercepting HTTP redirects (Burp Suite, mitmproxy, or curl)

### Steps

1. Open the client app at `http://localhost:8000` and click **Login**. The
   client generates a `code_verifier`, derives the `code_challenge`, and sends
   the challenge on the authorize request.

2. The client app redirects you to the authorization endpoint (note the PKCE
   parameters):
   ```
   http://localhost:8001/authorize?response_type=code&client_id=flawedtoken-client&redirect_uri=http://localhost:8000/callback&state=SOMESTATE&code_challenge=CHALLENGE&code_challenge_method=S256
   ```

3. Approve the authorization request.

4. The auth server redirects back with the authorization code:
   ```
   http://localhost:8000/callback?code=AUTH_CODE_HERE&state=SOMESTATE
   ```

5. Intercept this redirect before it reaches the client app callback.

6. Redeem the intercepted code yourself, presenting the public `client_id` and
   the code but no `code_verifier` (you never had it, it stayed in the victim's
   client):
   ```
   curl -X POST http://localhost:8001/token \
     -d grant_type=authorization_code \
     -d code=AUTH_CODE_HERE \
     -d redirect_uri=http://localhost:8000/callback \
     -d client_id=flawedtoken-client
   ```
   With the flaw on, the token endpoint skips PKCE verification and returns an
   access token.

### Confirming the fix

Set `FLAW_CODE_INTERCEPTION=off` and repeat step 6. The token endpoint now
rejects the request with `invalid_grant` / `pkce verification failed`, because
the presented request has no verifier that hashes to the stored challenge. The
legitimate client still succeeds, because it holds the matching `code_verifier`.

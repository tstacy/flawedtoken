"""
FlawedToken — Authorization Server
Minimal OAuth 2.0 AS with toggleable misconfigurations.

Flaw toggles (via environment variables):
  FLAW_CODE_INTERCEPTION=on      — disables PKCE verification at the token
                                    endpoint. An intercepted authorization code
                                    can be redeemed without the code_verifier.
  FLAW_REDIRECT_URI_VALIDATION=on — disables strict redirect_uri allow-list check

Set any flag to 'off' to enable correct, secure behavior.

Client model: flawedtoken-client is a PUBLIC client (no client_secret). The
token endpoint is protected by PKCE (RFC 7636), not a shared secret, so code
interception is defended by proof-of-possession rather than confidentiality.
"""

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, render_template_string, request

import sc_events

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

FLAW_CODE_INTERCEPTION = os.environ.get("FLAW_CODE_INTERCEPTION", "on").lower() == "on"
FLAW_REDIRECT_URI_VALIDATION = os.environ.get("FLAW_REDIRECT_URI_VALIDATION", "on").lower() == "on"

AUTH_CODE_TTL = int(os.environ.get("AUTH_CODE_TTL", 60))
CLIENT_APP_URL = os.environ.get("CLIENT_APP_URL", "http://localhost:8000")

REGISTERED_CLIENTS = {
    "flawedtoken-client": {
        "token_endpoint_auth_method": "none",
        "redirect_uris": [
            f"{CLIENT_APP_URL}/callback",
        ],
        "scopes": ["openid", "profile", "email"],
    }
}

USERS_FILE = Path(__file__).parent / "users.json"


def _b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_pkce(code_verifier, code_challenge, method="S256"):
    """RFC 7636 verification. Returns (ok, reason). ok is True only when a
    verifier is present and matches the stored challenge."""
    if not code_challenge:
        return False, "no_challenge_bound"
    if not code_verifier:
        return False, "verifier_missing"
    if method == "plain":
        computed = code_verifier
    else:
        computed = _b64url_sha256(code_verifier)
    if secrets.compare_digest(computed, code_challenge):
        return True, "match"
    return False, "verifier_mismatch"

def load_users():
    if not USERS_FILE.exists():
        return {}
    with open(USERS_FILE) as f:
        users = json.load(f)
    return {u["username"]: u for u in users}

auth_codes: dict = {}
access_tokens: dict = {}

def _in_allowlist(client_id: str, redirect_uri: str) -> bool:
    client = REGISTERED_CLIENTS.get(client_id)
    return bool(client) and redirect_uri in client["redirect_uris"]


def validate_redirect_uri(client_id: str, redirect_uri: str, phase: str = "unknown") -> bool:
    in_allow = _in_allowlist(client_id, redirect_uri)
    accepted = True if FLAW_REDIRECT_URI_VALIDATION else in_allow
    sc_events.emit(
        "authz.redirect_uri.validated",
        client_id=client_id,
        redirect_uri=redirect_uri,
        flaw_active=FLAW_REDIRECT_URI_VALIDATION,
        in_allowlist=in_allow,
        accepted=accepted,
        phase=phase,
    )
    return accepted

def issue_auth_code(client_id, redirect_uri, state, user, code_challenge=None, code_challenge_method="S256"):
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "user": user,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "issued_at": time.time(),
    }
    sc_events.emit(
        "authz.code.issued",
        code_fp=sc_events.fp(code),
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        username=user.get("username"),
        code_challenge_present=bool(code_challenge),
        code_challenge_method=code_challenge_method if code_challenge else None,
        ttl_seconds=AUTH_CODE_TTL,
    )
    return code

def issue_access_token(client_id, user, scope):
    token = secrets.token_urlsafe(48)
    access_tokens[token] = {
        "client_id": client_id,
        "user": user,
        "scope": scope,
        "issued_at": time.time(),
    }
    return token

@app.route("/.well-known/oauth-authorization-server")
def metadata():
    base = request.host_url.rstrip("/")
    return jsonify({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
        "flawedtoken_active_flaws": {
            "FLAW_CODE_INTERCEPTION": FLAW_CODE_INTERCEPTION,
            "FLAW_REDIRECT_URI_VALIDATION": FLAW_REDIRECT_URI_VALIDATION,
        },
    })

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FlawedToken — Authorize</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { min-height: 100vh; display: flex; align-items: center; justify-content: center;
           background: #0d0d0f; font-family: 'Courier New', monospace; color: #e2e2e2; }
    .card { width: 380px; border: 1px solid #2a2a2e; background: #111114; padding: 2rem; }
    .logo { font-size: 0.7rem; letter-spacing: 0.2em; color: #e05c2a; text-transform: uppercase; margin-bottom: 1.5rem; }
    h1 { font-size: 1.1rem; font-weight: 400; margin-bottom: 0.4rem; }
    .client-id { font-size: 0.75rem; color: #888; margin-bottom: 1.8rem; }
    label { display: block; font-size: 0.7rem; letter-spacing: 0.1em; color: #888;
            text-transform: uppercase; margin-bottom: 0.4rem; }
    input { width: 100%; padding: 0.6rem 0.8rem; background: #0d0d0f; border: 1px solid #2a2a2e;
            color: #e2e2e2; font-family: inherit; font-size: 0.9rem; margin-bottom: 1rem; outline: none; }
    input:focus { border-color: #e05c2a; }
    button { width: 100%; padding: 0.7rem; background: #e05c2a; border: none; color: #fff;
             font-family: inherit; font-size: 0.85rem; letter-spacing: 0.05em; cursor: pointer; text-transform: uppercase; }
    button:hover { background: #c94e20; }
    .error { font-size: 0.75rem; color: #e05c2a; margin-bottom: 1rem; padding: 0.5rem; border: 1px solid #e05c2a33; }
    .flaw-badge { margin-top: 1.5rem; padding: 0.5rem 0.6rem; font-size: 0.65rem;
                  letter-spacing: 0.08em; border: 1px solid #2a2a2e; color: #555; }
    .flaw-badge span { color: #e05c2a; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">FlawedToken · Auth Server</div>
    <h1>Authorize Application</h1>
    <p class="client-id">client_id: {{ client_id }}</p>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
      <input type="hidden" name="client_id" value="{{ client_id }}">
      <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
      <input type="hidden" name="state" value="{{ state }}">
      <input type="hidden" name="response_type" value="{{ response_type }}">
      <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
      <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
      <div>
        <label>Username</label>
        <input type="text" name="username" autofocus autocomplete="off">
      </div>
      <div>
        <label>Password</label>
        <input type="password" name="password">
      </div>
      <button type="submit">Approve &amp; Authorize</button>
    </form>
    <div class="flaw-badge">
      active flaws:
      <span>FLAW_CODE_INTERCEPTION={{ 'ON' if flaw_code else 'off' }}</span>
      &nbsp;
      <span>FLAW_REDIRECT_URI={{ 'ON' if flaw_redirect else 'off' }}</span>
    </div>
  </div>
</body>
</html>
"""

@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    users = load_users()

    if request.method == "GET":
        client_id = request.args.get("client_id", "")
        redirect_uri = request.args.get("redirect_uri", "")
        state = request.args.get("state", "")
        response_type = request.args.get("response_type", "code")
        code_challenge = request.args.get("code_challenge", "")
        code_challenge_method = request.args.get("code_challenge_method", "S256")

        sc_events.emit(
            "authz.request.received",
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            response_type=response_type,
            client_recognized=client_id in REGISTERED_CLIENTS,
            response_type_supported=response_type == "code",
            code_challenge_present=bool(code_challenge),
            code_challenge_method=code_challenge_method if code_challenge else None,
        )

        if response_type != "code":
            return jsonify({"error": "unsupported_response_type"}), 400
        if client_id not in REGISTERED_CLIENTS:
            return jsonify({"error": "unauthorized_client"}), 400
        if not validate_redirect_uri(client_id, redirect_uri, phase="authorize_get"):
            return jsonify({"error": "invalid_redirect_uri", "detail": "redirect_uri not in registered allow-list", "flaw_active": False}), 400

        return render_template_string(LOGIN_TEMPLATE,
            client_id=client_id, redirect_uri=redirect_uri, state=state,
            response_type=response_type, error=None,
            code_challenge=code_challenge, code_challenge_method=code_challenge_method,
            flaw_code=FLAW_CODE_INTERCEPTION, flaw_redirect=FLAW_REDIRECT_URI_VALIDATION)

    client_id = request.form.get("client_id", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    response_type = request.form.get("response_type", "code")
    code_challenge = request.form.get("code_challenge", "")
    code_challenge_method = request.form.get("code_challenge_method", "S256")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = users.get(username)
    if not user or user.get("password") != password:
        sc_events.emit(
            "authz.login.failed",
            username=username,
            client_id=client_id,
            reason="invalid_credentials",
        )
        return render_template_string(LOGIN_TEMPLATE,
            client_id=client_id, redirect_uri=redirect_uri, state=state,
            response_type=response_type, error="Invalid credentials.",
            code_challenge=code_challenge, code_challenge_method=code_challenge_method,
            flaw_code=FLAW_CODE_INTERCEPTION, flaw_redirect=FLAW_REDIRECT_URI_VALIDATION)

    sc_events.emit(
        "authz.login.succeeded",
        username=username,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
    )

    if not validate_redirect_uri(client_id, redirect_uri, phase="authorize_post"):
        return jsonify({"error": "invalid_redirect_uri"}), 400

    code = issue_auth_code(client_id, redirect_uri, state, user,
                           code_challenge=code_challenge or None,
                           code_challenge_method=code_challenge_method)

    if FLAW_REDIRECT_URI_VALIDATION and not _in_allowlist(client_id, redirect_uri):
        sc_events.emit(
            "finding.flaw02.redirect_uri_manipulation",
            severity="high",
            unregistered_redirect_uri=redirect_uri,
            registered_allowlist=REGISTERED_CLIENTS.get(client_id, {}).get("redirect_uris", []),
            code_fp=sc_events.fp(code),
            explanation="Any redirect_uri is accepted. Open redirect to attacker-controlled URI is possible.",
        )

    params = {"code": code, "state": state}
    return redirect(f"{redirect_uri}?{urlencode(params)}")

@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    code_verifier = request.form.get("code_verifier")

    code_fp = sc_events.fp(code)
    sc_events.emit(
        "token.request.received",
        grant_type=grant_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_fp=code_fp,
        code_verifier_present=bool(code_verifier),
        code_known=code in auth_codes,
    )

    if grant_type != "authorization_code":
        sc_events.emit("token.rejected", error="unsupported_grant_type",
                       detail="", code_fp=code_fp, client_id_presented=client_id)
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        sc_events.emit("token.rejected", error="invalid_client",
                       detail="unknown client", code_fp=code_fp, client_id_presented=client_id)
        return jsonify({"error": "invalid_client"}), 401

    code_data = auth_codes.get(code)
    if not code_data:
        sc_events.emit("token.rejected", error="invalid_grant",
                       detail="unknown code", code_fp=code_fp, client_id_presented=client_id)
        return jsonify({"error": "invalid_grant", "detail": "unknown code"}), 400

    if time.time() - code_data["issued_at"] > AUTH_CODE_TTL:
        del auth_codes[code]
        sc_events.emit("token.rejected", error="invalid_grant",
                       detail="code expired", code_fp=code_fp, client_id_presented=client_id)
        return jsonify({"error": "invalid_grant", "detail": "code expired"}), 400

    if code_data["redirect_uri"] != redirect_uri:
        sc_events.emit("token.rejected", error="invalid_grant",
                       detail="redirect_uri mismatch", code_fp=code_fp, client_id_presented=client_id)
        return jsonify({"error": "invalid_grant", "detail": "redirect_uri mismatch"}), 400

    pkce_ok, pkce_reason = verify_pkce(
        code_verifier,
        code_data.get("code_challenge"),
        code_data.get("code_challenge_method", "S256"),
    )
    sc_events.emit(
        "token.pkce.verified",
        flaw_active=FLAW_CODE_INTERCEPTION,
        code_fp=code_fp,
        challenge_present=bool(code_data.get("code_challenge")),
        verifier_present=bool(code_verifier),
        method=code_data.get("code_challenge_method", "S256"),
        match=pkce_ok,
        reason=pkce_reason,
        enforced=not FLAW_CODE_INTERCEPTION,
    )

    if not FLAW_CODE_INTERCEPTION:
        if not pkce_ok:
            sc_events.emit("token.rejected", error="invalid_grant",
                           detail=f"pkce verification failed: {pkce_reason}", code_fp=code_fp,
                           client_id_presented=client_id)
            return jsonify({"error": "invalid_grant", "detail": "pkce verification failed"}), 400

    user = code_data["user"]
    del auth_codes[code]

    access_token = issue_access_token(client_id, user, "openid profile email")
    token_fp = sc_events.fp(access_token)
    sc_events.emit(
        "token.issued",
        token_fp=token_fp,
        client_id=client_id,
        username=user.get("username"),
        scope="openid profile email",
        from_code_fp=code_fp,
    )

    if FLAW_CODE_INTERCEPTION and not pkce_ok:
        sc_events.emit(
            "finding.flaw01.code_interception_replay",
            severity="high",
            code_fp=code_fp,
            token_fp=token_fp,
            pkce_reason=pkce_reason,
            explanation="PKCE verification is disabled. An intercepted authorization code was redeemed without a valid code_verifier.",
        )

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email",
    })

@app.route("/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401
    token = auth_header[7:]
    token_data = access_tokens.get(token)
    if not token_data:
        return jsonify({"error": "invalid_token"}), 401
    user = token_data["user"]
    sc_events.emit(
        "userinfo.served",
        token_fp=sc_events.fp(token),
        username=user.get("username"),
        claims_returned=["sub", "name", "email", "username"],
    )
    return jsonify({
        "sub": user.get("username"),
        "name": user.get("name", user.get("username")),
        "email": user.get("email", ""),
        "username": user.get("username"),
    })

@app.route("/debug/flaws")
def debug_flaws():
    return jsonify({
        "FLAW_CODE_INTERCEPTION": {
            "active": FLAW_CODE_INTERCEPTION,
            "effect": "PKCE verification is disabled. An intercepted authorization code can be redeemed without the code_verifier."
                      if FLAW_CODE_INTERCEPTION
                      else "PKCE (S256) is enforced. An intercepted code cannot be exchanged without the matching code_verifier.",
        },
        "FLAW_REDIRECT_URI_VALIDATION": {
            "active": FLAW_REDIRECT_URI_VALIDATION,
            "effect": "Any redirect_uri is accepted. Open redirect to attacker-controlled URI is possible."
                      if FLAW_REDIRECT_URI_VALIDATION
                      else "Strict exact-match validation against registered allow-list.",
        },
        "pending_codes": len(auth_codes),
        "active_tokens": len(access_tokens),
        "warning": "This endpoint is for lab use only. It must not exist on a production authorization server.",
    })

if __name__ == "__main__":
    port = int(os.environ.get("AUTH_SERVER_PORT", 8001))
    app.run(host="0.0.0.0", port=port, debug=False)

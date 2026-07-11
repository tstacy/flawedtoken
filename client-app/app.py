"""
FlawedToken — Client Application (Relying Party)
A minimal OAuth 2.0 client that trusts the auth server incorrectly.
"""

import base64
import hashlib
import os
import secrets

import requests
from flask import Flask, redirect, render_template, request, session, url_for

import sc_events

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://auth-server:8001")
CLIENT_APP_URL = os.environ.get("CLIENT_APP_URL", "http://localhost:8000")

CLIENT_ID = "flawedtoken-client"
REDIRECT_URI = f"{CLIENT_APP_URL}/callback"
SCOPES = "openid profile email"


def _make_pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

AUTH_SERVER_BROWSER_URL = os.environ.get("AUTH_SERVER_BROWSER_URL", "http://localhost:8001")
AUTHORIZE_URL = f"{AUTH_SERVER_BROWSER_URL}/authorize"
TOKEN_URL = f"{AUTH_SERVER_URL}/token"
USERINFO_URL = f"{AUTH_SERVER_URL}/userinfo"

@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login")
def login():
    state = secrets.token_urlsafe(16)
    verifier, challenge = _make_pkce()
    session["oauth_state"] = state
    session["code_verifier"] = verifier
    from urllib.parse import urlencode
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    sc_events.emit(
        "oauth.login.initiated",
        state=state,
        redirect_uri=REDIRECT_URI,
        client_id=CLIENT_ID,
        scopes=SCOPES,
        code_challenge_method="S256",
    )
    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    expected_state = session.get("oauth_state")
    state_match = bool(state) and state == expected_state
    sc_events.emit(
        "oauth.callback.received",
        has_code=bool(code),
        has_error=bool(error),
        error=error,
        returned_state=state,
        expected_state=expected_state,
        state_match=state_match,
        code_fp=sc_events.fp(code),
    )
    if code and not state_match:
        sc_events.emit(
            "finding.state_mismatch",
            severity="medium",
            returned_state=state,
            expected_state=expected_state,
            code_fp=sc_events.fp(code),
            explanation="Callback state did not match the value issued at login initiation, consistent with interception or CSRF.",
        )

    if error:
        return render_template("error.html", error=error, detail=request.args.get("error_description", ""))
    if not code:
        return render_template("error.html", error="missing_code", detail="No authorization code in callback.")

    sc_events.emit(
        "oauth.token.requested",
        code_fp=sc_events.fp(code),
        redirect_uri=REDIRECT_URI,
        client_id=CLIENT_ID,
    )
    try:
        resp = requests.post(TOKEN_URL, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": session.get("code_verifier", ""),
        }, timeout=10)
    except requests.RequestException as e:
        sc_events.emit("oauth.token.failed", error="token_request_failed", detail=str(e), status_code=0)
        return render_template("error.html", error="token_request_failed", detail=str(e))

    if resp.status_code != 200:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        sc_events.emit(
            "oauth.token.failed",
            error=body.get("error", "token_error"),
            detail=body.get("detail", ""),
            status_code=resp.status_code,
        )
        return render_template("error.html",
                               error=body.get("error", "token_error"),
                               detail=body.get("detail", resp.text))

    token_data = resp.json()
    access_token = token_data.get("access_token")

    if not access_token:
        sc_events.emit("oauth.token.failed", error="no_access_token",
                       detail="Token response missing access_token.", status_code=resp.status_code)
        return render_template("error.html", error="no_access_token", detail="Token response missing access_token.")

    sc_events.emit(
        "oauth.token.received",
        token_fp=sc_events.fp(access_token),
        token_type=token_data.get("token_type", ""),
        expires_in=token_data.get("expires_in", 0),
        scope=token_data.get("scope", ""),
    )

    try:
        ui_resp = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
        user_info = ui_resp.json() if ui_resp.status_code == 200 else {}
    except requests.RequestException:
        user_info = {}

    session["user"] = user_info
    session["access_token"] = access_token
    sc_events.emit(
        "oauth.session.established",
        username=user_info.get("username"),
        token_fp=sc_events.fp(access_token),
    )
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    access_token = session.get("access_token", "")
    return render_template("dashboard.html", user=user, access_token=access_token)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    port = int(os.environ.get("CLIENT_APP_PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)

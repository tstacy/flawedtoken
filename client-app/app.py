"""
FlawedToken — Client Application (Relying Party)
A minimal OAuth 2.0 client that trusts the auth server incorrectly.
"""

import os
import secrets

import requests
from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://auth-server:8001")
CLIENT_APP_URL = os.environ.get("CLIENT_APP_URL", "http://localhost:8000")

CLIENT_ID = "flawedtoken-client"
CLIENT_SECRET = "flawedtoken-secret"
REDIRECT_URI = f"{CLIENT_APP_URL}/callback"
SCOPES = "openid profile email"

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
    session["oauth_state"] = state
    from urllib.parse import urlencode
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
    }
    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return render_template("error.html", error=error, detail=request.args.get("error_description", ""))
    if not code:
        return render_template("error.html", error="missing_code", detail="No authorization code in callback.")

    try:
        resp = requests.post(TOKEN_URL, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }, timeout=10)
    except requests.RequestException as e:
        return render_template("error.html", error="token_request_failed", detail=str(e))

    if resp.status_code != 200:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        return render_template("error.html",
                               error=body.get("error", "token_error"),
                               detail=body.get("detail", resp.text))

    token_data = resp.json()
    access_token = token_data.get("access_token")

    if not access_token:
        return render_template("error.html", error="no_access_token", detail="Token response missing access_token.")

    try:
        ui_resp = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
        user_info = ui_resp.json() if ui_resp.status_code == 200 else {}
    except requests.RequestException:
        user_info = {}

    session["user"] = user_info
    session["access_token"] = access_token
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

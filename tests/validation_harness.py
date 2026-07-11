"""
Workstream A validation harness — ShroudCloud / FlawedToken.

The Definition-of-Done gate for the event instrumentation. Runs the real
services, drives each flaw-toggle combination plus a false-positive control, and
asserts:

  1. sc_events.py is byte-identical across both service dirs (Option 1 drift guard)
  2. every event carries a complete v1.1 envelope
  3. seq is strictly increasing per service, starting at 1
  4. no raw code / token / verifier ever appears in the stream (fingerprints only)
  5. the expected base events are present for each scenario
  6. the correct findings fire — and NONE fire when they shouldn't

Emitting processes run with SC_STRICT=on, so any forbidden-key leak raises inside
the app rather than passing silently. On success, writes acceptance_fixture.json
(the golden event sequences) for the backend and result-view workstreams.

Run:  python tests/validation_harness.py
Exit: 0 if all checks pass, 1 otherwise.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests

ROOT = Path(__file__).resolve().parent.parent
AUTH_DIR = ROOT / "auth-server"
CLIENT_DIR = ROOT / "client-app"
AS = "http://localhost:8001"
CLIENT = "http://localhost:8000"
REG = "http://localhost:8000/callback"
SCHEMA_VERSION = "1.1"
ENVELOPE_KEYS = {"schema_version", "event", "event_id", "seq", "ts",
                 "service", "sc_session_id", "sc_instance_id", "data"}
VALID_SERVICES = {"auth-server", "client-app"}
SECRETISH = re.compile(r"[A-Za-z0-9_-]{20,}")  # token_urlsafe-shaped strings

RESULTS = []


def check(cond, label):
    RESULTS.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    return bool(cond)


def pkce():
    v = "verifier-" + hashlib.sha256(os.urandom(16)).hexdigest()
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    return v, c


def _env(service, flaw_code, flaw_redirect):
    return dict(os.environ, SC_SERVICE=service, SC_SESSION_ID="sess_harness",
                SC_INSTANCE_ID="ft-h", SC_STRICT="on",
                FLAW_CODE_INTERCEPTION=flaw_code, FLAW_REDIRECT_URI_VALIDATION=flaw_redirect,
                CLIENT_APP_URL="http://localhost:8000",
                AUTH_SERVER_URL="http://localhost:8001",
                AUTH_SERVER_BROWSER_URL="http://localhost:8001")


def start(cwd, service, port_env, port, fc, fr):
    env = _env(service, fc, fr); env[port_env] = str(port)
    p = subprocess.Popen([sys.executable, "app.py"], cwd=str(cwd), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return p


def wait_up(url):
    for _ in range(60):
        try:
            requests.get(url, timeout=0.5); return True
        except Exception:
            time.sleep(0.1)
    return False


def drain(proc):
    proc.terminate()
    try:
        out = proc.stdout.read()
    except Exception:
        out = ""
    return [json.loads(l) for l in out.splitlines() if l.strip().startswith("{")]


# --- scenario drivers -------------------------------------------------------

def scn_clean_direct(fc="off", fr="off"):
    """Auth-only happy path; we know code + verifier + token for exact no-leak."""
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, fc, fr)
    wait_up(AS + "/debug/flaws")
    v, c = pkce()
    s = requests.Session()
    s.get(f"{AS}/authorize", params={"response_type": "code", "client_id": "flawedtoken-client",
          "redirect_uri": REG, "state": "S1", "code_challenge": c, "code_challenge_method": "S256"})
    r = s.post(f"{AS}/authorize", data={"client_id": "flawedtoken-client", "redirect_uri": REG,
        "state": "S1", "response_type": "code", "code_challenge": c, "code_challenge_method": "S256",
        "username": "alice", "password": "password"}, allow_redirects=False)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    tok = s.post(f"{AS}/token", data={"grant_type": "authorization_code", "code": code,
        "redirect_uri": REG, "client_id": "flawedtoken-client", "code_verifier": v}).json()
    token = tok["access_token"]
    s.get(f"{AS}/userinfo", headers={"Authorization": f"Bearer {token}"})
    return drain(a), {code, token, v}


def scn_flaw02():
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, "off", "on")
    wait_up(AS + "/debug/flaws")
    v, c = pkce()
    s = requests.Session()
    s.get(f"{AS}/authorize", params={"response_type": "code", "client_id": "flawedtoken-client",
          "redirect_uri": "https://evil.example/steal", "state": "S1", "code_challenge": c,
          "code_challenge_method": "S256"})
    r = s.post(f"{AS}/authorize", data={"client_id": "flawedtoken-client",
        "redirect_uri": "https://evil.example/steal", "state": "S1", "response_type": "code",
        "code_challenge": c, "code_challenge_method": "S256", "username": "alice", "password": "password"},
        allow_redirects=False)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    return drain(a), {code, v}


def scn_flaw01():
    """Attacker intercepts code, redeems with NO verifier. Flaw on -> token + F2."""
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, "on", "off")
    wait_up(AS + "/debug/flaws")
    v, c = pkce()
    s = requests.Session()
    s.get(f"{AS}/authorize", params={"response_type": "code", "client_id": "flawedtoken-client",
          "redirect_uri": REG, "state": "S1", "code_challenge": c, "code_challenge_method": "S256"})
    r = s.post(f"{AS}/authorize", data={"client_id": "flawedtoken-client", "redirect_uri": REG,
        "state": "S1", "response_type": "code", "code_challenge": c, "code_challenge_method": "S256",
        "username": "alice", "password": "password"}, allow_redirects=False)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    tok = requests.post(f"{AS}/token", data={"grant_type": "authorization_code", "code": code,
        "redirect_uri": REG, "client_id": "flawedtoken-client"}).json()  # no verifier
    return drain(a), {code, tok.get("access_token", "x"), v}


def scn_secure_control():
    """Same attack, flaw OFF -> token.rejected, NO finding (false-positive guard)."""
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, "off", "off")
    wait_up(AS + "/debug/flaws")
    v, c = pkce()
    s = requests.Session()
    s.get(f"{AS}/authorize", params={"response_type": "code", "client_id": "flawedtoken-client",
          "redirect_uri": REG, "state": "S1", "code_challenge": c, "code_challenge_method": "S256"})
    r = s.post(f"{AS}/authorize", data={"client_id": "flawedtoken-client", "redirect_uri": REG,
        "state": "S1", "response_type": "code", "code_challenge": c, "code_challenge_method": "S256",
        "username": "alice", "password": "password"}, allow_redirects=False)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    requests.post(f"{AS}/token", data={"grant_type": "authorization_code", "code": code,
        "redirect_uri": REG, "client_id": "flawedtoken-client"})  # no verifier
    return drain(a), {code, v}


def scn_clean_e2e():
    """Full two-service login; validates all client events + cross-service correlation."""
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, "off", "off")
    cl = start(CLIENT_DIR, "client-app", "CLIENT_APP_PORT", 8000, "off", "off")
    wait_up(AS + "/debug/flaws"); wait_up(CLIENT + "/")
    s = requests.Session()
    r = s.get(CLIENT + "/login", allow_redirects=False)
    p = {k: val[0] for k, val in parse_qs(urlparse(r.headers["Location"]).query).items()}
    s.get(r.headers["Location"])
    r2 = s.post(f"{AS}/authorize", data={"client_id": p["client_id"], "redirect_uri": p["redirect_uri"],
        "state": p["state"], "response_type": p["response_type"], "code_challenge": p["code_challenge"],
        "code_challenge_method": p["code_challenge_method"], "username": "alice", "password": "password"},
        allow_redirects=False)
    s.get(r2.headers["Location"], allow_redirects=False)  # client callback exchanges token
    ev_a = drain(a); ev_c = drain(cl)
    return ev_a + ev_c, set()


def scn_client_token_failure():
    """Client callback receives a bogus code -> server rejects -> oauth.token.failed."""
    a = start(AUTH_DIR, "auth-server", "AUTH_SERVER_PORT", 8001, "off", "off")
    cl = start(CLIENT_DIR, "client-app", "CLIENT_APP_PORT", 8000, "off", "off")
    wait_up(AS + "/debug/flaws"); wait_up(CLIENT + "/")
    s = requests.Session()
    r = s.get(CLIENT + "/login", allow_redirects=False)
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    s.get(f"{CLIENT}/callback?code=BOGUSCODE&state={state}", allow_redirects=False)
    drain(a)
    return drain(cl), set()


# --- assertions -------------------------------------------------------------

def assert_common(events, scenario, secrets):
    for e in events:
        check(set(e.keys()) == ENVELOPE_KEYS, f"{scenario}: envelope keys complete ({e.get('event')})")
        check(e["schema_version"] == SCHEMA_VERSION, f"{scenario}: schema_version {SCHEMA_VERSION} ({e['event']})")
        check(e["service"] in VALID_SERVICES, f"{scenario}: valid service ({e['event']})")
    for svc in {e["service"] for e in events}:
        seqs = [e["seq"] for e in events if e["service"] == svc]
        check(seqs == list(range(1, len(seqs) + 1)), f"{scenario}: seq 1..n monotonic for {svc} ({seqs})")
    blob = json.dumps([e["data"] for e in events])
    leaked = [sec for sec in secrets if sec and len(sec) > 8 and sec in blob]
    check(not leaked, f"{scenario}: no raw secret in stream" + (f" LEAKED={leaked}" if leaked else ""))
    # heuristic: any secretish string in data must be a fingerprint (contains ':')
    for e in events:
        for k, val in e["data"].items():
            if isinstance(val, str) and k.endswith("_fp"):
                check(":" in val, f"{scenario}: {k} is a fingerprint not raw ({e['event']})")


def names(events, service=None):
    return [e["event"] for e in events if service is None or e["service"] == service]


def run(label, driver, expected_events, expected_findings, secrets_from_driver=True):
    print(f"\n=== {label} ===")
    events, secrets = driver()
    assert_common(events, label, secrets)
    present = set(names(events))
    for ev in expected_events:
        check(ev in present, f"{label}: emits {ev}")
    findings = {e["event"] for e in events if e["event"].startswith("finding.")}
    check(findings == set(expected_findings),
          f"{label}: findings == {sorted(expected_findings)} (got {sorted(findings)})")
    return events


# --- main -------------------------------------------------------------------

def main():
    print("Workstream A validation harness (schema v%s)\n" % SCHEMA_VERSION)

    print("=== pre-flight: sc_events.py drift guard ===")
    a_bytes = (AUTH_DIR / "sc_events.py").read_bytes()
    c_bytes = (CLIENT_DIR / "sc_events.py").read_bytes()
    check(a_bytes == c_bytes, "sc_events.py byte-identical across auth-server and client-app")

    fixture = {}

    ev = run("CLEAN (both off, direct)", scn_clean_direct,
             ["authz.request.received", "authz.redirect_uri.validated", "authz.login.succeeded",
              "authz.code.issued", "token.request.received", "token.pkce.verified",
              "token.issued", "userinfo.served"], [])
    fixture["clean_direct"] = golden(ev)

    ev = run("FLAW-02 redirect URI manipulation", scn_flaw02,
             ["authz.redirect_uri.validated", "authz.code.issued"],
             ["finding.flaw02.redirect_uri_manipulation"])
    fixture["flaw02"] = golden(ev)

    ev = run("FLAW-01 interception (PKCE disabled)", scn_flaw01,
             ["token.pkce.verified", "token.issued"],
             ["finding.flaw01.code_interception_replay"])
    fixture["flaw01"] = golden(ev)

    ev = run("SECURE CONTROL (PKCE enforced, no verifier)", scn_secure_control,
             ["token.pkce.verified", "token.rejected"], [])
    fixture["secure_control"] = golden(ev)

    ev = run("CLEAN e2e (both services)", scn_clean_e2e,
             ["oauth.login.initiated", "oauth.callback.received", "oauth.token.requested",
              "oauth.token.received", "oauth.session.established",
              "authz.code.issued", "token.issued"], [])
    check("oauth.login.initiated" in names(ev, "client-app"), "e2e: client-app events present")
    check("authz.code.issued" in names(ev, "auth-server"), "e2e: auth-server events present")
    check(len({e["sc_session_id"] for e in ev}) == 1, "e2e: single sc_session_id across both services")
    fixture["clean_e2e"] = golden(ev)

    ev = run("CLIENT token failure", scn_client_token_failure,
             ["oauth.callback.received", "oauth.token.requested", "oauth.token.failed"], [])
    fixture["client_token_failure"] = golden(ev)

    out = Path(__file__).parent / "acceptance_fixture.json"
    out.write_text(json.dumps(fixture, indent=2))
    print(f"\nwrote acceptance fixture -> {out}")

    passed = sum(1 for ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{'='*50}\n{passed}/{total} checks passed")
    fails = [lbl for ok, lbl in RESULTS if not ok]
    if fails:
        print("FAILURES:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED — Workstream A DoD gate green")
    return 0


def golden(events):
    """Stable projection for the acceptance fixture: names + service + stable
    decision flags only (drop volatile event_id / ts / seq / fingerprints)."""
    stable_keys = {"flaw_active", "in_allowlist", "accepted", "match", "reason",
                   "enforced", "severity", "state_match", "phase", "code_challenge_present"}
    proj = []
    for e in events:
        d = {k: v for k, v in e["data"].items() if k in stable_keys}
        proj.append({"service": e["service"], "event": e["event"], "data": d})
    return proj


if __name__ == "__main__":
    sys.exit(main())

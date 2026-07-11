"""
sc_events.py — ShroudCloud Workstream A event emitter for FlawedToken.

Implements the v1.0 session-tagged event schema. This module is baked into
BOTH the auth-server and client-app images (copy into each build context, or a
shared dir COPYd into both).

Design (see workstream-a-event-schema-v1.md):
  - Session identity comes from the environment, stamped per pooled instance:
        SC_SESSION_ID, SC_INSTANCE_ID, SC_SERVICE
  - Events are JSON lines on stdout, collected via the Docker log driver.
  - Secrets are never emitted raw: use fp() for codes/tokens; a redaction
    guard scrubs (or, in strict mode, rejects) forbidden key names.
  - Instrumentation must never crash the app: emit() swallows its own errors
    unless strict mode is on (used by the validation harness).

Env:
  SC_SESSION_ID   session tag for the pooled instance (default 'sess_unset')
  SC_INSTANCE_ID  which pool instance (default 'inst_unset')
  SC_SERVICE      'auth-server' | 'client-app' (default 'unknown')
  SC_STRICT       'on' to raise on redaction violations / emit errors (harness)
"""

import hashlib
import json
import os
import sys
import threading
import time
import uuid

SCHEMA_VERSION = "1.1"

_VALID_SERVICES = {"auth-server", "client-app"}

# Key names that must never carry raw secret material (spec 3.2). Guarded on
# every emit. Correct call sites pass fingerprints (code_fp, token_fp) or
# presence booleans (client_secret_present) instead.
_FORBIDDEN_KEYS = {
    "code", "authorization_code", "auth_code",
    "token", "access_token", "refresh_token", "bearer",
    "client_secret", "secret",
    "password", "passwd", "pwd",
}


def _env_bool(name, default=False):
    return os.environ.get(name, "on" if default else "off").lower() == "on"


class EventEmitter:
    """One emitter per service process. The module exposes a default instance
    configured from the environment; tests/harness may construct their own with
    an explicit service, identity, and output stream."""

    def __init__(self, service=None, session_id=None, instance_id=None,
                 strict=None, out=None):
        self.service = service if service is not None else os.environ.get("SC_SERVICE", "unknown")
        self.session_id = session_id if session_id is not None else os.environ.get("SC_SESSION_ID", "sess_unset")
        self.instance_id = instance_id if instance_id is not None else os.environ.get("SC_INSTANCE_ID", "inst_unset")
        self.strict = strict if strict is not None else _env_bool("SC_STRICT", False)
        self.out = out if out is not None else sys.stdout
        self._seq = 0
        self._lock = threading.Lock()

    def _next_seq(self):
        with self._lock:
            self._seq += 1
            return self._seq

    def fp(self, secret):
        """Fingerprint a secret per spec 3.1, salted with this emitter's
        session id: '<12 hex>:<len>'. None-safe (returns None for falsy input)
        so nullable fields like code_fp fall through cleanly."""
        if not secret:
            return None
        digest = hashlib.sha256(f"{self.session_id}|{secret}".encode()).hexdigest()
        return f"{digest[:12]}:{len(secret)}"

    def _guard(self, data):
        """Enforce the redaction rule. Returns a cleaned copy. Strict mode
        raises on any forbidden key; otherwise the value is scrubbed and a
        warning is written to stderr."""
        if not data:
            return {}
        cleaned = {}
        for key, value in data.items():
            if key in _FORBIDDEN_KEYS:
                msg = f"forbidden raw-secret key '{key}' in event data"
                if self.strict:
                    raise ValueError(f"sc_events: {msg}")
                sys.stderr.write(f"[sc_events][WARN] {msg}; scrubbed\n")
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = value
        return cleaned

    def emit(self, event, **data):
        """Emit one schema-v1.0 event as a JSON line. Returns the record dict
        (handy for tests); returns None if a non-strict error was swallowed."""
        try:
            record = {
                "schema_version": SCHEMA_VERSION,
                "event": event,
                "event_id": str(uuid.uuid4()),
                "seq": self._next_seq(),
                "ts": int(time.time() * 1000),
                "service": self.service,
                "sc_session_id": self.session_id,
                "sc_instance_id": self.instance_id,
                "data": self._guard(data),
            }
            self.out.write(json.dumps(record, separators=(",", ":")) + "\n")
            self.out.flush()
            return record
        except Exception as exc:
            if self.strict:
                raise
            sys.stderr.write(f"[sc_events][ERROR] emit failed for '{event}': {exc}\n")
            return None


# --- Module-level default emitter (configured from env) ---------------------

_default = EventEmitter()


def emit(event, **data):
    """Emit via the default env-configured emitter. Primary call-site API."""
    return _default.emit(event, **data)


def fp(secret):
    """Fingerprint via the default emitter's session id."""
    return _default.fp(secret)


def configure(service=None, session_id=None, instance_id=None, strict=None, out=None):
    """Reconfigure the default emitter in place (rarely needed; env is
    preferred). Useful in a single-process harness."""
    if service is not None:
        _default.service = service
    if session_id is not None:
        _default.session_id = session_id
    if instance_id is not None:
        _default.instance_id = instance_id
    if strict is not None:
        _default.strict = strict
    if out is not None:
        _default.out = out


def _startup_check():
    if _default.service not in _VALID_SERVICES:
        sys.stderr.write(
            f"[sc_events][WARN] SC_SERVICE='{_default.service}' is not one of {sorted(_VALID_SERVICES)}\n")
    if _default.session_id == "sess_unset":
        sys.stderr.write(
            "[sc_events][WARN] SC_SESSION_ID unset; events will not correlate to a session\n")


_startup_check()


# --- Smoke test -------------------------------------------------------------
# Run `python sc_events.py` to self-verify envelope shape, seq monotonicity,
# fingerprint stability, and the redaction guard. Not the full Workstream A
# validation harness (that replays the OAuth flow); this checks the module.

if __name__ == "__main__":
    import io

    buf = io.StringIO()
    em = EventEmitter(service="auth-server", session_id="sess_test",
                      instance_id="ft-03", strict=True, out=buf)

    code = "abc123-a-real-looking-authorization-code-value"
    code_fp = em.fp(code)

    em.emit("authz.request.received", client_id="flawedtoken-client",
            redirect_uri="http://localhost:8000/callback", state="S1",
            response_type="code", client_recognized=True,
            response_type_supported=True)
    em.emit("authz.redirect_uri.validated", client_id="flawedtoken-client",
            redirect_uri="http://localhost:8000/callback", flaw_active=False,
            in_allowlist=True, accepted=True, phase="authorize_get")
    em.emit("authz.code.issued", code_fp=code_fp, client_id="flawedtoken-client",
            redirect_uri="http://localhost:8000/callback", state="S1",
            username="alice", ttl_seconds=60)

    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    records = [json.loads(l) for l in lines]

    envelope_keys = {"schema_version", "event", "event_id", "seq", "ts",
                     "service", "sc_session_id", "sc_instance_id", "data"}

    # 1. Envelope completeness
    for r in records:
        assert set(r.keys()) == envelope_keys, f"bad envelope keys: {set(r.keys())}"
        assert r["schema_version"] == "1.0"
        assert r["service"] == "auth-server"
        assert r["sc_session_id"] == "sess_test"

    # 2. seq strictly increasing from 1
    seqs = [r["seq"] for r in records]
    assert seqs == [1, 2, 3], f"seq not monotonic: {seqs}"

    # 3. Fingerprint stability and no raw secret leakage
    assert em.fp(code) == code_fp, "fingerprint not stable"
    assert code not in buf.getvalue(), "raw code leaked into output"
    assert records[2]["data"]["code_fp"] == code_fp

    # 4. Salting: different session id -> different fingerprint
    other = EventEmitter(service="auth-server", session_id="sess_other")
    assert other.fp(code) != code_fp, "fingerprint not salted by session"

    # 5. Redaction guard: strict mode rejects a raw-secret key
    raised = False
    try:
        em.emit("token.issued", access_token=code)  # forbidden key
    except ValueError:
        raised = True
    assert raised, "strict guard did not reject forbidden key 'access_token'"

    # 6. Non-strict guard scrubs instead of raising
    scrub_buf = io.StringIO()
    lax = EventEmitter(service="client-app", session_id="s", strict=False, out=scrub_buf)
    rec = lax.emit("oauth.token.received", password="hunter2")
    assert rec["data"]["password"] == "[REDACTED]", "non-strict guard did not scrub"
    assert "hunter2" not in scrub_buf.getvalue()

    print("sc_events.py smoke test: all checks passed")
    print(f"  emitted {len(records)} events, seq={seqs}, code_fp={code_fp}")

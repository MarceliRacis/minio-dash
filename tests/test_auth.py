"""JWT issuing/verification, the CSRF double-submit check, and the guards that
sit in front of every endpoint."""

import time

import jwt as pyjwt
import pytest


# ─── tokens ──────────────────────────────────────────────────────────────────

def test_token_roundtrip_carries_identity_and_creds(server):
    token = server.create_token("alice", is_admin=True, ak="AK", sk="SK")
    claims = server.decode_token(token)
    assert claims["sub"] == "alice"
    assert claims["admin"] is True
    assert server.decrypt_creds(claims["creds"]) == {"ak": "AK", "sk": "SK"}


def test_creds_are_encrypted_not_just_encoded(server):
    """The JWT payload is base64, not secret — the creds inside it must be
    sealed separately or anyone holding the cookie reads the S3 keys."""
    token = server.create_token("alice", is_admin=False, ak="AK", sk="SUPERSECRET")
    assert "SUPERSECRET" not in token
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert "SUPERSECRET" not in str(claims)


def test_token_without_creds_has_no_creds_claim(server):
    claims = server.decode_token(server.create_token("alice", is_admin=False))
    assert "creds" not in claims


def test_signature_from_another_secret_is_rejected(server):
    forged = pyjwt.encode({"sub": "root", "admin": True,
                           "exp": int(time.time()) + 3600},
                          "attacker-key-" + "x" * 32, algorithm="HS256")
    assert server.decode_token(forged) is None


def test_expired_token_is_rejected(server):
    stale = pyjwt.encode({"sub": "alice", "admin": False,
                          "iat": int(time.time()) - 7200,
                          "exp": int(time.time()) - 60},
                         server.SECRET_KEY, algorithm="HS256")
    assert server.decode_token(stale) is None


def test_alg_none_token_is_rejected(server):
    """Classic JWT downgrade: unsigned token claiming admin."""
    forged = pyjwt.encode({"sub": "root", "admin": True,
                           "exp": int(time.time()) + 3600},
                          key="", algorithm="none")
    assert server.decode_token(forged) is None


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "Bearer x"])
def test_malformed_tokens_return_none(server, token):
    assert server.decode_token(token) is None


# ─── CSRF double-submit ──────────────────────────────────────────────────────

@pytest.mark.parametrize("cookie,header,expected", [
    ("tok", "tok", True),
    ("tok", "different", False),
    ("", "tok", False),
    ("tok", "", False),
    ("", "", False),
])
def test_csrf_double_submit(server, cookie, header, expected):
    headers = {}
    if cookie:
        headers["Cookie"] = f"csrf_token={cookie}"
    if header:
        headers["X-CSRF-Token"] = header
    with server.app.test_request_context("/", headers=headers):
        assert server._csrf_ok() is expected


def test_login_issues_both_cookies(server, client, monkeypatch):
    monkeypatch.setattr(server, "make_client", lambda ak, sk: _FakeMinio())
    monkeypatch.setattr(server, "_HAS_MINIOADMIN", False)
    monkeypatch.setattr(server, "admin_request",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no admin")))

    resp = client.post("/api/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200

    cookies = resp.headers.getlist("Set-Cookie")
    token_cookie = next(c for c in cookies if c.startswith("token="))
    csrf_cookie = next(c for c in cookies if c.startswith("csrf_token="))
    # The session token must be unreadable by JS; the CSRF token must be readable.
    assert "HttpOnly" in token_cookie
    assert "HttpOnly" not in csrf_cookie
    assert "SameSite=Lax" in token_cookie


class _FakeMinio:
    def list_buckets(self):
        return []


# ─── endpoint guards ─────────────────────────────────────────────────────────

PROTECTED_GETS = ["/api/me", "/api/stats", "/api/buckets", "/api/users",
                  "/api/policies", "/api/permission-matrix"]


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_protected_get_requires_a_token(client, path):
    assert client.get(path).status_code == 401


def test_mutating_request_without_csrf_is_403_not_401(auth_client):
    """CSRF is checked before auth, so a valid session still can't POST without
    the header."""
    resp = auth_client.post("/api/logout")
    assert resp.status_code == 403
    assert "CSRF" in resp.get_json()["error"]


def test_mutating_request_with_csrf_passes_the_csrf_gate(auth_client):
    resp = auth_client.post("/api/logout", headers=auth_client.csrf_headers)
    assert resp.status_code == 200


def test_token_without_creds_is_rejected_as_expired(server, csrf_client):
    """A JWT that survived a SESSION_BACKEND switch carries no creds — the
    request must not proceed with an unauthenticated MinIO client."""
    csrf_client.set_cookie("token", server.create_token("alice", is_admin=False),
                           domain="localhost")
    resp = csrf_client.get("/api/me")
    assert resp.status_code == 401
    assert "expired" in resp.get_json()["error"].lower()


def test_me_reports_identity(auth_client):
    resp = auth_client.get("/api/me")
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_non_admin_cannot_reach_admin_endpoint(auth_client):
    assert auth_client.get("/api/permission-matrix").status_code == 403


def test_admin_claim_alone_is_not_enough(server, csrf_client, monkeypatch):
    """The 'admin' claim is frozen into the JWT for 8h; a user demoted in MinIO
    must be rejected on the live re-check."""
    csrf_client.set_cookie("token",
                           server.create_token("root", True, "AK", "SK"),
                           domain="localhost")
    monkeypatch.setattr(server, "_verify_admin_live", lambda: False)
    assert csrf_client.get("/api/permission-matrix").status_code == 403

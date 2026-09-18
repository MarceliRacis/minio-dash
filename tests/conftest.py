"""Shared fixtures.

server.py reads its config at import time and refuses to start without
SECRET_KEY / ENCRYPTION_KEY, so the environment must be set up *before* the
import. DEBUG is deliberately left unset so the tests exercise the same
production code path users run (no insecure key fallbacks, no /api/debug-users).
"""

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Fixed, throwaway keys — plain http endpoint so Secure cookies are not required
# and the Flask test client can round-trip them.
os.environ.setdefault("SECRET_KEY", "0" * 64)
os.environ.setdefault("ENCRYPTION_KEY", "1" * 32)
os.environ.setdefault("MINIO_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("SESSION_BACKEND", "jwt")
os.environ.pop("DEBUG", None)
os.environ.pop("REDIS_URL", None)

import server as srv  # noqa: E402


@pytest.fixture(scope="session")
def server():
    """The imported server module."""
    return srv


@pytest.fixture()
def client():
    """Unauthenticated Flask test client."""
    srv.app.config["TESTING"] = True
    with srv.app.test_client() as c:
        yield c


@pytest.fixture()
def csrf_client(client):
    """Client carrying a CSRF cookie, with a helper to echo it as a header."""
    client.set_cookie("csrf_token", "test-csrf-token", domain="localhost")
    client.csrf_headers = {"X-CSRF-Token": "test-csrf-token"}
    return client


@pytest.fixture()
def auth_client(csrf_client):
    """Client with a valid session: CSRF cookie + JWT cookie carrying creds."""
    token = srv.create_token("alice", is_admin=False, ak="AKIAALICE", sk="s3cr3t")
    csrf_client.set_cookie("token", token, domain="localhost")
    return csrf_client


@pytest.fixture()
def admin_client(csrf_client, monkeypatch):
    """Client with an admin session. _verify_admin_live() is stubbed out because
    the real one calls MinIO over the network."""
    token = srv.create_token("root", is_admin=True, ak="AKIAROOT", sk="s3cr3t")
    csrf_client.set_cookie("token", token, domain="localhost")
    monkeypatch.setattr(srv, "_verify_admin_live", lambda: True)
    return csrf_client


@pytest.fixture(autouse=True)
def _clear_admin_cache():
    """_verify_admin_live() memoises per-credential results for ADMIN_VERIFY_TTL
    seconds; a leaked entry would make later tests pass for the wrong reason."""
    srv._admin_verify_cache.clear()
    yield
    srv._admin_verify_cache.clear()


@pytest.fixture()
def frozen_clock(monkeypatch):
    """Freeze the clock inside server.py so SigV4 signatures are reproducible."""
    import datetime as real_datetime

    fixed = real_datetime.datetime(2026, 1, 15, 12, 30, 45,
                                   tzinfo=real_datetime.timezone.utc)

    class _FrozenDatetime(real_datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz is None else fixed.astimezone(tz)

    class _FakeModule:
        datetime = _FrozenDatetime
        timezone = real_datetime.timezone

    monkeypatch.setattr(srv, "datetime", _FakeModule)
    return fixed

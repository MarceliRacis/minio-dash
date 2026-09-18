"""Endpoint smoke tests that need no MinIO: static shell, i18n, login validation
and the security headers."""

import json
from pathlib import Path

import pytest


def test_index_serves_the_ui(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"<html" in resp.data.lower()


def test_index_sets_hardening_headers(client):
    h = client.get("/").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "no-store" in h["Cache-Control"]


@pytest.mark.parametrize("lang", ["en", "pl"])
def test_i18n_returns_a_locale(client, lang):
    resp = client.get(f"/i18n/{lang}")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), dict)
    assert resp.get_json()


@pytest.mark.parametrize("lang", ["de", "../server", "..%2fserver", "EN"])
def test_i18n_rejects_anything_not_allowlisted(client, lang):
    """The lang segment reaches the filesystem, so the allowlist is the only
    thing standing between it and a path traversal."""
    assert client.get(f"/i18n/{lang}").status_code == 404


def test_locales_are_in_sync():
    """A key present in one language but not the other shows up as a raw
    translation key in the UI."""
    root = Path(__file__).resolve().parent.parent / "locales"
    en = json.loads((root / "en.json").read_text(encoding="utf-8"))
    pl = json.loads((root / "pl.json").read_text(encoding="utf-8"))
    assert set(en) == set(pl), (
        f"only in en: {sorted(set(en) - set(pl))}; "
        f"only in pl: {sorted(set(pl) - set(en))}"
    )


@pytest.mark.parametrize("payload", [
    {},
    {"username": "alice"},
    {"password": "pw"},
    {"username": "", "password": "pw"},
    {"username": "alice", "password": "   "},
])
def test_login_rejects_incomplete_credentials(client, payload):
    resp = client.post("/api/login", json=payload)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing credentials"


def test_login_survives_a_non_json_body(client):
    """login() uses force=True, so a bogus content type must still 400 rather
    than raise a 500."""
    resp = client.post("/api/login", data="not json",
                       content_type="text/plain")
    assert resp.status_code == 400


def test_login_reports_unreachable_minio_as_503(client, server, monkeypatch):
    def _boom(ak, sk):
        raise OSError("connection refused")
    monkeypatch.setattr(server, "make_client", _boom)
    resp = client.post("/api/login", json={"username": "a", "password": "b"})
    assert resp.status_code == 503


def test_login_reports_bad_credentials_as_401(client, server, monkeypatch):
    def _denied(ak, sk):
        raise RuntimeError("InvalidAccessKeyId: nope")
    monkeypatch.setattr(server, "make_client", _denied)
    resp = client.post("/api/login", json={"username": "a", "password": "b"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid credentials"


def test_debug_endpoint_is_off_when_debug_is_unset(client):
    """/api/debug-users leaks user data and must never be reachable in a
    default (production) configuration."""
    resp = client.get("/api/debug-users")
    assert resp.status_code in (401, 403, 404)


def test_unknown_api_route_is_404(client):
    assert client.get("/api/does-not-exist").status_code == 404

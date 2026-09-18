"""MODE=PREVIEW — the public demo sandbox.

server.py reads MODE once at import time, so this module reloads it under a
preview environment in its own fixtures rather than reusing the session-wide
one from conftest.
"""

import importlib
import io
import json
import os
import sys

import pytest


@pytest.fixture(scope="module")
def psrv():
    """server.py re-imported with MODE=PREVIEW."""
    old_mode = os.environ.get("MODE")
    os.environ["MODE"] = "PREVIEW"
    for mod in ("server", "preview"):
        sys.modules.pop(mod, None)
    module = importlib.import_module("server")
    yield module
    # Restore the shared, non-preview module for every other test file.
    if old_mode is None:
        os.environ.pop("MODE", None)
    else:
        os.environ["MODE"] = old_mode
    for mod in ("server", "preview"):
        sys.modules.pop(mod, None)
    importlib.import_module("server")


@pytest.fixture()
def pclient(psrv):
    psrv.app.config["TESTING"] = True
    with psrv.app.test_client() as c:
        yield c


@pytest.fixture()
def session(pclient):
    """A logged-in preview session with CSRF wired up."""
    resp = pclient.post("/api/login", json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    csrf = next(c.split("csrf_token=")[1].split(";")[0]
                for c in resp.headers.getlist("Set-Cookie")
                if c.startswith("csrf_token="))
    pclient.headers = {"X-CSRF-Token": csrf}
    return pclient


def _get(session, path):
    return session.get(path, headers=session.headers)


def _post(session, path, **kw):
    return session.post(path, headers=session.headers, **kw)


# ─── mode plumbing ───────────────────────────────────────────────────────────

def test_preview_mode_is_on(psrv):
    assert psrv.PREVIEW_MODE is True


def test_config_endpoint_advertises_preview(pclient):
    assert pclient.get("/api/config").get_json() == {"preview": True}


def test_login_needs_no_credentials(pclient):
    resp = pclient.post("/api/login", json={})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["preview"] is True
    assert body["admin"] is True


def test_no_real_minio_client_is_ever_built(psrv, session, monkeypatch):
    """The whole point: a public demo must not be able to reach a real server."""
    import preview
    def _explode(*a, **k):
        raise AssertionError("real Minio client constructed in preview mode")
    monkeypatch.setattr(psrv, "Minio", _explode)
    monkeypatch.setattr(psrv, "_http", None)
    assert _get(session, "/api/buckets").status_code == 200
    assert _get(session, "/api/users").status_code == 200
    assert _get(session, "/api/permission-matrix").status_code == 200


def test_each_login_gets_its_own_sandbox(pclient):
    a = pclient.post("/api/login", json={}).get_json()["token"]
    b = pclient.post("/api/login", json={}).get_json()["token"]
    assert a != b


def test_sandboxes_are_isolated(psrv):
    """One visitor deleting a bucket must not affect anybody else."""
    import preview
    one = preview.FakeMinio(preview.REGISTRY.get("sandbox-one"))
    two = preview.FakeMinio(preview.REGISTRY.get("sandbox-two"))
    one.remove_object("public-assets", "logo.svg")
    one.remove_bucket("public-assets")
    one.make_bucket("only-in-one")
    assert "public-assets" not in {b.name for b in one.list_buckets()}
    assert "public-assets" in {b.name for b in two.list_buckets()}
    assert "only-in-one" not in {b.name for b in two.list_buckets()}


# ─── the panel actually works against the fake ───────────────────────────────

def test_seeded_buckets_are_listed(session):
    resp = _get(session, "/api/buckets")
    assert resp.status_code == 200
    names = {b["name"] for b in resp.get_json()}
    assert {"photos", "backups", "logs"} <= names


def test_stats_render(session):
    resp = _get(session, "/api/stats")
    assert resp.status_code == 200
    assert resp.get_json()["buckets"] >= 3


def test_users_and_policies_are_seeded(session):
    users = _get(session, "/api/users").get_json()
    by_name = {u["username"]: u for u in users}
    assert by_name["alice"]["policies"] == ["photos-readonly"]
    assert by_name["intern"]["status"] == "disabled"
    names = set(_get(session, "/api/policies").get_json())
    assert {"readwrite", "readonly", "photos-readonly"} <= names


def test_permission_matrix_reflects_seeded_policies(session):
    m = _get(session, "/api/permission-matrix").get_json()
    assert "alice" in m["users"]
    assert "photos" in m["buckets"]
    # alice holds photos-readonly, which grants read on photos and nothing else.
    assert m["matrix"]["alice"]["photos"] == "r"
    assert m["matrix"]["alice"]["backups"] == "none"
    # carol holds readwrite, a built-in covering every bucket.
    assert m["matrix"]["carol"]["photos"] == "rw"


def test_file_listing_synthesises_folders(session):
    items = _get(session, "/api/buckets/photos/files").get_json()
    by_name = {i["name"]: i for i in items}
    assert by_name["holiday"]["isDir"] is True
    assert by_name["README.md"]["isDir"] is False
    assert by_name["README.md"]["size"] > 0


def test_browsing_into_a_folder(session):
    items = _get(session, "/api/buckets/photos/files?prefix=holiday/").get_json()
    assert {i["name"] for i in items} == {"beach.jpg", "sunset.jpg"}


def test_full_write_cycle(session):
    assert _post(session, "/api/buckets",
                 json={"name": "scratch"}).status_code in (200, 201)
    assert "scratch" in {b["name"] for b in _get(session, "/api/buckets").get_json()}

    up = _post(session, "/api/buckets/scratch/files/upload",
               data={"file": (io.BytesIO(b"hello preview"), "note.txt")},
               content_type="multipart/form-data")
    assert up.status_code in (200, 201)

    items = _get(session, "/api/buckets/scratch/files").get_json()
    assert [i["name"] for i in items] == ["note.txt"]

    dl = session.get("/api/buckets/scratch/files/download?key=note.txt",
                     headers=session.headers)
    assert dl.status_code == 200
    assert dl.get_data() == b"hello preview"

    assert _post(session, "/api/buckets/scratch/files/delete",
                 json={"key": "note.txt"}).status_code == 200
    assert _get(session, "/api/buckets/scratch/files").get_json() == []

    assert session.delete("/api/buckets/scratch", json={},
                          headers=session.headers).status_code == 200


def test_user_lifecycle(session):
    assert _post(session, "/api/users",
                 json={"username": "newbie", "password": "hunter2hunter2"}
                 ).status_code in (200, 201)
    assert any(u["username"] == "newbie"
               for u in _get(session, "/api/users").get_json())

    assert _post(session, "/api/users/newbie/disable").status_code == 200
    users = {u["username"]: u for u in _get(session, "/api/users").get_json()}
    assert users["newbie"]["status"] == "disabled"

    assert session.delete("/api/users/newbie", json={},
                          headers=session.headers).status_code == 200
    assert not any(u["username"] == "newbie"
                   for u in _get(session, "/api/users").get_json())


def test_presigned_link_is_obviously_fake(session):
    resp = _post(session, "/api/buckets/photos/files/share",
                 json={"key": "README.md", "expire": 2})
    assert resp.status_code == 200
    assert "preview.invalid" in resp.get_json()["url"]


# ─── sandbox guard rails ─────────────────────────────────────────────────────

def test_upload_is_size_capped(psrv):
    import preview
    box = preview.REGISTRY.get("cap-test")
    client = preview.FakeMinio(box)
    oversized = io.BytesIO(b"x" * (preview.MAX_OBJECT_BYTES + 10))
    with pytest.raises(preview.PreviewError) as exc:
        client.put_object("photos", "big.bin", oversized)
    assert exc.value.code == "EntityTooLarge"


def test_registry_is_capped(psrv, monkeypatch):
    import preview
    monkeypatch.setattr(preview, "MAX_SANDBOXES", 5)
    reg = preview.SandboxRegistry()
    for i in range(20):
        reg.get(f"visitor-{i}")
    assert reg.stats()["sandboxes"] <= 5


def test_missing_bucket_reports_a_useful_code(psrv):
    import preview
    client = preview.FakeMinio(preview.REGISTRY.get("missing-test"))
    with pytest.raises(preview.PreviewError) as exc:
        client.list_objects("no-such-bucket")
    assert exc.value.code == "NoSuchBucket"
    assert "NoSuchBucket" in str(exc.value)


def test_builtin_policies_cannot_be_deleted(psrv):
    import preview
    admin = preview.FakeAdmin(preview.REGISTRY.get("builtin-test"))
    with pytest.raises(preview.PreviewError):
        admin.policy_remove("readwrite")

#!/usr/bin/env python3
"""Preview mode — a self-contained, in-memory stand-in for MinIO.

Set MODE=PREVIEW and the panel runs against a fake backend instead of a real
MinIO server: every visitor gets their own disposable sandbox, seeded with demo
buckets, users and policies, and can click anything — create, delete, upload,
reassign permissions — without touching real infrastructure. Sandboxes live in
RAM, expire, and are never shared between visitors.

This exists so the project can be demoed at a public URL. It is deliberately
isolated in its own module: server.py only swaps the three factory functions
(make_client / make_admin_client / admin_request), so the 36 endpoints and all
of their logic run completely unmodified against the fake.

Not a MinIO emulator. It implements exactly the surface the panel calls, and
returns the shapes the panel expects.
"""

from __future__ import annotations

import datetime
import io
import json
import secrets
import threading
import time
from dataclasses import dataclass, field

SANDBOX_TTL = 2 * 3600      # a visitor's sandbox lives 2h after last use
MAX_SANDBOXES = 200         # hard cap so a crawler cannot exhaust memory
MAX_OBJECT_BYTES = 5 * 1024 * 1024   # uploads are held in RAM — keep them small
MAX_OBJECTS_PER_SANDBOX = 500


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# ─── error type ──────────────────────────────────────────────────────────────

class PreviewError(Exception):
    """Mirrors the shape server.py expects from S3Error (it reads .code)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code


# ─── stored values ───────────────────────────────────────────────────────────

@dataclass
class _Obj:
    object_name: str
    data: bytes
    content_type: str = "application/octet-stream"
    last_modified: datetime.datetime = field(default_factory=_now)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def etag(self) -> str:
        return f"{abs(hash(self.data)):032x}"[:32]


@dataclass
class _Entry:
    """What list_objects() yields — either an object or a synthesised prefix."""
    object_name: str
    is_dir: bool = False
    size: int = 0
    etag: str = ""
    content_type: str = ""
    last_modified: datetime.datetime | None = None


@dataclass
class _Bucket:
    name: str
    creation_date: datetime.datetime = field(default_factory=_now)
    policy: str | None = None


@dataclass
class _User:
    access_key: str
    status: str = "enabled"
    policies: list = field(default_factory=list)


BUILTIN_POLICIES = {
    "readwrite": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::*"]}]},
    "readonly": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
         "Resource": ["arn:aws:s3:::*"]}]},
    "writeonly": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::*"]}]},
    "diagnostics": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["admin:ServerInfo"], "Resource": ["arn:aws:s3:::*"]}]},
    "consoleAdmin": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["admin:*", "s3:*"], "Resource": ["arn:aws:s3:::*"]}]},
}


class Sandbox:
    """One visitor's isolated world."""

    def __init__(self):
        self.lock = threading.RLock()
        self.touched = time.time()
        self.buckets: dict[str, _Bucket] = {}
        self.objects: dict[str, dict[str, _Obj]] = {}
        self.users: dict[str, _User] = {}
        self.policies: dict[str, dict] = dict(BUILTIN_POLICIES)
        self._seed()

    # ── demo content ────────────────────────────────────────────────────────
    def _seed(self):
        readme = (
            b"# minio-dash preview\n\n"
            b"You are looking at a disposable in-memory sandbox.\n"
            b"Create, delete and upload freely - nothing here is real, and it\n"
            b"resets on its own. No MinIO server is involved.\n"
        )
        seed_files = {
            "photos": [
                ("holiday/beach.jpg", b"\xff\xd8\xff\xe0JFIF-placeholder", "image/jpeg"),
                ("holiday/sunset.jpg", b"\xff\xd8\xff\xe0JFIF-placeholder", "image/jpeg"),
                ("profile.png", b"\x89PNG\r\n\x1a\nplaceholder", "image/png"),
                ("README.md", readme, "text/markdown"),
            ],
            "backups": [
                ("db/2026-09-01.sql.gz", b"\x1f\x8b" + b"0" * 2048, "application/gzip"),
                ("db/2026-09-08.sql.gz", b"\x1f\x8b" + b"0" * 2048, "application/gzip"),
                ("config.json", json.dumps({"retention_days": 30}, indent=2).encode(),
                 "application/json"),
            ],
            "logs": [
                ("nginx/access.log", b"127.0.0.1 - - [14/Sep/2026] \"GET / HTTP/1.1\" 200\n" * 20,
                 "text/plain"),
                ("nginx/error.log", b"", "text/plain"),
            ],
            "public-assets": [
                ("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml"),
            ],
        }
        for i, (bname, files) in enumerate(seed_files.items()):
            self.buckets[bname] = _Bucket(
                bname, _now() - datetime.timedelta(days=90 - i * 20))
            self.objects[bname] = {
                key: _Obj(key, body, ctype,
                          _now() - datetime.timedelta(days=(i + 1) * 3))
                for key, body, ctype in files
            }

        self.policies["photos-readonly"] = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]}]}
        self.policies["backups-writer"] = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
             "Resource": ["arn:aws:s3:::backups/*"]}]}

        self.users = {
            "alice":   _User("alice", "enabled", ["photos-readonly"]),
            "bob":     _User("bob", "enabled", ["backups-writer"]),
            "carol":   _User("carol", "enabled", ["readwrite"]),
            "deploy":  _User("deploy", "enabled", ["backups-writer", "photos-readonly"]),
            "intern":  _User("intern", "disabled", ["readonly"]),
        }

    def touch(self):
        self.touched = time.time()

    # ── bucket ops ──────────────────────────────────────────────────────────
    def require_bucket(self, name):
        if name not in self.buckets:
            raise PreviewError("NoSuchBucket", f"Bucket '{name}' does not exist")

    def count_objects(self):
        return sum(len(v) for v in self.objects.values())


class SandboxRegistry:
    """Keeps sandboxes alive per visitor, with a TTL and a hard cap."""

    def __init__(self):
        self._boxes: dict[str, Sandbox] = {}
        self._lock = threading.Lock()

    def get(self, sandbox_id: str) -> Sandbox:
        now = time.time()
        with self._lock:
            self._evict(now)
            box = self._boxes.get(sandbox_id)
            if box is None:
                if len(self._boxes) >= MAX_SANDBOXES:
                    # Drop the least recently used rather than refuse service.
                    oldest = min(self._boxes, key=lambda k: self._boxes[k].touched)
                    self._boxes.pop(oldest, None)
                box = Sandbox()
                self._boxes[sandbox_id] = box
            box.touch()
            return box

    def _evict(self, now):
        for key in [k for k, v in self._boxes.items()
                    if now - v.touched > SANDBOX_TTL]:
            self._boxes.pop(key, None)

    def stats(self):
        with self._lock:
            return {"sandboxes": len(self._boxes)}


REGISTRY = SandboxRegistry()


def new_sandbox_id() -> str:
    return "preview-" + secrets.token_urlsafe(12)


# ─── fake S3 client ──────────────────────────────────────────────────────────

class _GetResponse:
    """Stands in for the urllib3 response the MinIO SDK hands back."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)
        self.data = data

    def read(self, amt=None):
        return self._buf.read(amt)

    def stream(self, chunk_size=32 * 1024):
        while True:
            chunk = self._buf.read(chunk_size)
            if not chunk:
                return
            yield chunk

    def close(self):
        self._buf.close()

    def release_conn(self):
        pass


class FakeMinio:
    """Implements only what server.py calls on a Minio client."""

    def __init__(self, sandbox: Sandbox):
        self.s = sandbox

    # buckets
    def list_buckets(self):
        with self.s.lock:
            return sorted(self.s.buckets.values(), key=lambda b: b.name)

    def bucket_exists(self, bucket):
        return bucket in self.s.buckets

    def make_bucket(self, bucket, location=None):
        with self.s.lock:
            if bucket in self.s.buckets:
                raise PreviewError("BucketAlreadyOwnedByYou",
                                   f"Bucket '{bucket}' already exists")
            if len(self.s.buckets) >= 20:
                raise PreviewError("TooManyBuckets",
                                   "Preview sandbox is limited to 20 buckets")
            self.s.buckets[bucket] = _Bucket(bucket)
            self.s.objects[bucket] = {}

    def remove_bucket(self, bucket):
        with self.s.lock:
            self.s.require_bucket(bucket)
            if self.s.objects.get(bucket):
                raise PreviewError("BucketNotEmpty", f"Bucket '{bucket}' is not empty")
            self.s.buckets.pop(bucket, None)
            self.s.objects.pop(bucket, None)

    # objects
    def list_objects(self, bucket, prefix="", recursive=False):
        with self.s.lock:
            self.s.require_bucket(bucket)
            prefix = prefix or ""
            store = self.s.objects.get(bucket, {})
            if recursive:
                return [
                    _Entry(o.object_name, False, o.size, o.etag,
                           o.content_type, o.last_modified)
                    for o in sorted(store.values(), key=lambda o: o.object_name)
                    if o.object_name.startswith(prefix)
                ]

            entries, seen_dirs = [], set()
            for o in sorted(store.values(), key=lambda o: o.object_name):
                if not o.object_name.startswith(prefix):
                    continue
                rest = o.object_name[len(prefix):]
                if "/" in rest:
                    # Synthesise the common prefix, the way S3 delimiters do.
                    d = prefix + rest.split("/", 1)[0] + "/"
                    if d not in seen_dirs:
                        seen_dirs.add(d)
                        entries.append(_Entry(d, is_dir=True))
                else:
                    entries.append(_Entry(o.object_name, False, o.size, o.etag,
                                          o.content_type, o.last_modified))
            return entries

    def put_object(self, bucket, key, data, length=None, content_type=None, **kw):
        with self.s.lock:
            self.s.require_bucket(bucket)
            if self.s.count_objects() >= MAX_OBJECTS_PER_SANDBOX:
                raise PreviewError("TooManyObjects",
                                   "Preview sandbox object limit reached")
            raw = data.read(MAX_OBJECT_BYTES + 1) if hasattr(data, "read") else bytes(data)
            if len(raw) > MAX_OBJECT_BYTES:
                raise PreviewError(
                    "EntityTooLarge",
                    f"Preview mode caps uploads at {MAX_OBJECT_BYTES // (1024*1024)} MB")
            self.s.objects[bucket][key] = _Obj(
                key, raw, content_type or "application/octet-stream")

    def get_object(self, bucket, key):
        with self.s.lock:
            self.s.require_bucket(bucket)
            obj = self.s.objects.get(bucket, {}).get(key)
            if obj is None:
                raise PreviewError("NoSuchKey", f"Object '{key}' does not exist")
            return _GetResponse(obj.data)

    def stat_object(self, bucket, key):
        with self.s.lock:
            obj = self.s.objects.get(bucket, {}).get(key)
            if obj is None:
                raise PreviewError("NoSuchKey", f"Object '{key}' does not exist")
            return obj

    def remove_object(self, bucket, key):
        with self.s.lock:
            self.s.require_bucket(bucket)
            self.s.objects.get(bucket, {}).pop(key, None)

    def remove_objects(self, bucket, delete_object_list):
        with self.s.lock:
            self.s.require_bucket(bucket)
            store = self.s.objects.get(bucket, {})
            for d in delete_object_list:
                store.pop(getattr(d, "name", getattr(d, "_name", str(d))), None)
        return iter(())   # server.py drains this looking for per-object errors

    def copy_object(self, bucket, dst, source):
        with self.s.lock:
            self.s.require_bucket(bucket)
            src_key = getattr(source, "object_name", None) or getattr(source, "_object_name", "")
            obj = self.s.objects.get(bucket, {}).get(src_key)
            if obj is None:
                raise PreviewError("NoSuchKey", f"Object '{src_key}' does not exist")
            self.s.objects[bucket][dst] = _Obj(dst, obj.data, obj.content_type)

    def presigned_get_object(self, bucket, key, expires=None):
        self.s.require_bucket(bucket)
        hours = int(expires.total_seconds() // 3600) if expires else 1
        token = secrets.token_urlsafe(16)
        return (f"https://preview.invalid/{bucket}/{key}"
                f"?X-Amz-Expires={hours * 3600}&X-Amz-Signature={token}"
                f"&X-Amz-Preview=this-link-is-not-real")

    # bucket policy
    def get_bucket_policy(self, bucket):
        with self.s.lock:
            self.s.require_bucket(bucket)
            pol = self.s.buckets[bucket].policy
            if not pol:
                raise PreviewError("NoSuchBucketPolicy", "Bucket has no policy")
            return pol

    def set_bucket_policy(self, bucket, policy):
        with self.s.lock:
            self.s.require_bucket(bucket)
            self.s.buckets[bucket].policy = (
                policy if isinstance(policy, str) else json.dumps(policy))

    def delete_bucket_policy(self, bucket):
        with self.s.lock:
            self.s.require_bucket(bucket)
            self.s.buckets[bucket].policy = None


# ─── fake admin client ───────────────────────────────────────────────────────

class FakeAdmin:
    """Implements only what server.py calls on a MinioAdmin client.
    The real SDK returns JSON strings from these, so this does too."""

    def __init__(self, sandbox: Sandbox):
        self.s = sandbox

    def info(self):
        return json.dumps({"mode": "preview", "servers": [
            {"state": "online", "endpoint": "preview-sandbox"}]})

    # users
    def user_list(self):
        with self.s.lock:
            return json.dumps({
                u.access_key: {"status": u.status, "memberOf": list(u.policies)}
                for u in self.s.users.values()
            })

    def user_add(self, access_key, secret_key=None):
        with self.s.lock:
            if access_key in self.s.users:
                raise PreviewError("UserAlreadyExists", f"User '{access_key}' exists")
            if len(self.s.users) >= 50:
                raise PreviewError("TooManyUsers",
                                   "Preview sandbox is limited to 50 users")
            self.s.users[access_key] = _User(access_key)

    def user_remove(self, access_key):
        with self.s.lock:
            self.s.users.pop(access_key, None)

    def user_enable(self, access_key):
        self._set_status(access_key, "enabled")

    def user_disable(self, access_key):
        self._set_status(access_key, "disabled")

    def _set_status(self, access_key, status):
        with self.s.lock:
            if access_key not in self.s.users:
                raise PreviewError("NoSuchUser", f"User '{access_key}' does not exist")
            self.s.users[access_key].status = status

    # policies
    def policy_list(self):
        with self.s.lock:
            return json.dumps({name: doc for name, doc in self.s.policies.items()})

    def policy_info(self, policy_name):
        with self.s.lock:
            if policy_name not in self.s.policies:
                raise PreviewError("NoSuchPolicy", f"Policy '{policy_name}' does not exist")
            return json.dumps(self.s.policies[policy_name])

    def policy_add(self, policy_name, policy=None, policy_file=None):
        with self.s.lock:
            doc = policy
            if isinstance(doc, str):
                doc = json.loads(doc)
            self.s.policies[policy_name] = doc or {}

    def policy_remove(self, policy_name):
        with self.s.lock:
            if policy_name in BUILTIN_POLICIES:
                raise PreviewError("PolicyBuiltIn",
                                   f"'{policy_name}' is a built-in policy")
            self.s.policies.pop(policy_name, None)
            for u in self.s.users.values():
                if policy_name in u.policies:
                    u.policies.remove(policy_name)

    def policy_set(self, policy_name, user=None, group=None):
        with self.s.lock:
            if user not in self.s.users:
                raise PreviewError("NoSuchUser", f"User '{user}' does not exist")
            if policy_name not in self.s.policies:
                raise PreviewError("NoSuchPolicy", f"Policy '{policy_name}' does not exist")
            if policy_name not in self.s.users[user].policies:
                self.s.users[user].policies.append(policy_name)

    def policy_unset(self, policy_name, user=None, group=None):
        with self.s.lock:
            u = self.s.users.get(user)
            if u and policy_name in u.policies:
                u.policies.remove(policy_name)


# ─── fake raw admin REST API ─────────────────────────────────────────────────

def fake_admin_request(sandbox: Sandbox, method: str, path: str,
                       body: bytes = b"", query: str = "") -> dict:
    """Stands in for admin_request() — same dispatch the real /minio/admin/v3
    endpoints provide, for the twelve paths server.py actually uses."""
    from urllib.parse import parse_qs, unquote

    if "?" in path and not query:
        path, query = path.split("?", 1)
    args = {k: v[0] for k, v in parse_qs(query).items()}
    admin = FakeAdmin(sandbox)

    if path == "/info":
        return json.loads(admin.info())

    if path == "/list-users":
        return json.loads(admin.user_list())

    if path == "/user-info":
        user = sandbox.users.get(unquote(args.get("accessKey", "")))
        if not user:
            raise PreviewError("NoSuchUser", "User does not exist")
        return {"status": user.status, "memberOf": list(user.policies)}

    if path == "/add-user":
        admin.user_add(unquote(args.get("accessKey", "")))
        return {}

    if path == "/remove-user":
        admin.user_remove(unquote(args.get("accessKey", "")))
        return {}

    if path == "/set-user-status":
        key = unquote(args.get("accessKey", ""))
        admin._set_status(key, args.get("status", "enabled"))
        return {}

    if path == "/list-canned-policies":
        return json.loads(admin.policy_list())

    if path == "/info-canned-policy":
        return json.loads(admin.policy_info(unquote(args.get("name", ""))))

    if path == "/add-canned-policy":
        doc = json.loads(body.decode() or "{}") if body else {}
        admin.policy_add(unquote(args.get("name", "")), policy=doc)
        return {}

    if path == "/remove-canned-policy":
        admin.policy_remove(unquote(args.get("name", "")))
        return {}

    if path in ("/attach-user-or-group-policy", "/detach-user-or-group-policy"):
        payload = json.loads(body.decode() or "{}") if body else {}
        user = payload.get("user") or unquote(args.get("user", ""))
        names = payload.get("policies") or []
        if isinstance(names, str):
            names = [names]
        for name in names:
            if path.startswith("/attach"):
                admin.policy_set(name, user=user)
            else:
                admin.policy_unset(name, user=user)
        return {}

    raise PreviewError("NotImplemented", f"Preview mode does not implement {path}")

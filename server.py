#!/usr/bin/env python3
"""
minio-dash v2  –  Full S3 Admin Dashboard
No mc CLI needed – uses MinIO Python SDK + admin REST API directly.

Env vars (required unless DEBUG=1):
  MINIO_ENDPOINT   – e.g. s3.racis.dev  or  http://localhost:9000
  SECRET_KEY       – JWT signing secret (required; no insecure fallback)
  ENCRYPTION_KEY   – AES-256 key material for stored creds (required; no insecure fallback)
  PORT             – HTTP port (default: 7474)
  REDIS_URL        – optional; enables Redis-backed sessions
  DEBUG            – set to 1 to allow insecure dev key fallbacks

Run:
  pip install -r requirements.txt
  MINIO_ENDPOINT=s3.racis.dev SECRET_KEY=... ENCRYPTION_KEY=... python server.py
"""

import os, sys, json, time, secrets, string, hashlib, hmac, base64, mimetypes, io, struct, datetime, threading, re, fnmatch
from pathlib import Path
from functools import wraps
from urllib.parse import urlparse, quote

from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context

try:
    from minio import Minio
    from minio.error import S3Error
    from minio.commonconfig import CopySource
    import urllib3
    import redis
    import jwt as pyjwt
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
except ImportError as e:
    raise SystemExit(f"Missing dependency: {e}. Run: pip install -r requirements.txt")

try:
    from minio.minioadmin import MinioAdmin
    try:
        from minio.credentials import StaticProvider
    except ImportError:
        try:
            from minio.credentials import Credentials as StaticProvider
        except ImportError:
            StaticProvider = None
    _HAS_MINIOADMIN = True
except ImportError:
    _HAS_MINIOADMIN = False
    MinioAdmin = None
    StaticProvider = None

# ─── SETUP BOOTSTRAP ─────────────────────────────────────────────────────────

def _write_env_file(path: str = ".env") -> int:
    """Generate a ready-to-run .env so nobody has to hand-assemble secrets.

    Runs before the config validation below, because the whole point is to be
    usable when SECRET_KEY / ENCRYPTION_KEY are not set yet.
    """
    target = Path(path)
    if target.exists():
        print(f"Refusing to overwrite existing {target} — "
              f"delete it first or copy the values by hand.")
        return 1

    example = Path(__file__).parent / ".env.example"
    if example.exists():
        body = example.read_text(encoding="utf-8")
        body = body.replace("SECRET_KEY=changeme", f"SECRET_KEY={secrets.token_hex(32)}")
        body = body.replace("ENCRYPTION_KEY=changeme-encryption-key",
                            f"ENCRYPTION_KEY={secrets.token_hex(16)}")
    else:
        body = (f"MINIO_ENDPOINT=https://s3.example.com\n"
                f"SECRET_KEY={secrets.token_hex(32)}\n"
                f"ENCRYPTION_KEY={secrets.token_hex(16)}\n"
                f"PORT=7474\n")

    target.write_text(body, encoding="utf-8")
    try:
        target.chmod(0o600)   # it holds secrets — keep it owner-only
    except OSError:
        pass
    print(f"Wrote {target} with freshly generated SECRET_KEY and ENCRYPTION_KEY.")
    print("Set MINIO_ENDPOINT to your MinIO server, then: python server.py")
    return 0


if __name__ == "__main__" and "--init-env" in sys.argv:
    raise SystemExit(_write_env_file())


# ─── CONFIG ──────────────────────────────────────────────────────────────────
_raw_endpoint    = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
SECRET_KEY       = os.environ.get("SECRET_KEY")
ENC_KEY_RAW      = os.environ.get("ENCRYPTION_KEY")
REDIS_URL        = os.environ.get("REDIS_URL")
SESSION_BACKEND  = os.environ.get("SESSION_BACKEND", "jwt").lower() # jwt or redis
PORT             = int(os.environ.get("PORT", 7474))
SESSION_TTL      = 8 * 3600   # 8 hours
# DEBUG must be explicitly opted-in; it enables dev-only conveniences that are
# unsafe in production (insecure key fallbacks, the /api/debug-users endpoint).
DEBUG            = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes", "on")
# Whether the panel itself is served over HTTPS. Deliberately independent of
# MINIO_ENDPOINT: in k8s MinIO usually sits on plain http://minio:9000 while the
# panel is behind a TLS ingress, and the session cookie must still be Secure.
COOKIE_SECURE    = os.environ.get("COOKIE_SECURE", "1").lower() not in ("0", "false", "no", "off")

# MODE=PREVIEW swaps the MinIO backend for an in-memory sandbox (preview.py) so
# the panel can be exposed publicly as a clickable demo. Nothing it touches is
# real: no MinIO connection is ever opened and every visitor gets their own
# disposable world.
PREVIEW_MODE = os.environ.get("MODE", "").strip().upper() == "PREVIEW"

if PREVIEW_MODE and (not SECRET_KEY or not ENC_KEY_RAW):
    # A preview session protects nothing of value and is meant to be thrown
    # away, so generate ephemeral keys rather than make the demo need config.
    # Restarting the process logs everyone out, which is the desired behaviour.
    SECRET_KEY  = SECRET_KEY or secrets.token_hex(32)
    ENC_KEY_RAW = ENC_KEY_RAW or secrets.token_hex(16)
    print("  [preview] using ephemeral SECRET_KEY / ENCRYPTION_KEY for this process")

if not SECRET_KEY or not ENC_KEY_RAW:
    print("CRITICAL: SECRET_KEY and ENCRYPTION_KEY must be set in environment!")
    print(f"Generated SECRET_KEY suggestion: {secrets.token_hex(32)}")
    print(f"Generated ENCRYPTION_KEY suggestion: {secrets.token_hex(16)}")
    if not DEBUG:
        # Fail fast everywhere unless DEBUG is explicitly enabled. Falling back to
        # a hardcoded key would let anyone forge JWTs and decrypt stored creds.
        raise SystemExit(
            "Missing required security environment variables SECRET_KEY / ENCRYPTION_KEY "
            "(set DEBUG=1 to allow insecure dev defaults)"
        )
    print("WARNING: DEBUG mode — using insecure hardcoded keys. DO NOT use in production.")

SECRET_KEY = SECRET_KEY or "dev-only-secret-key"
ENC_KEY_RAW = ENC_KEY_RAW or "dev-only-encryption-key"

# Derive a proper 32-byte key for AES-256
# PBKDF2-HMAC-SHA256, 600k iterations (per OWASP guidance)
# hmac_hash_module= uses pycryptodome's native PBKDF2-HMAC-SHA256 path. Passing
# an equivalent Python `prf=` lambda instead forces a per-iteration callback into
# Python and costs ~44s here versus ~0.5s — paid at import, so by every gunicorn
# worker at boot. Both derive byte-identical keys, so this is safe for sessions
# and credential blobs sealed before the change (see tests/test_crypto.py).
_enc_key = PBKDF2(
    ENC_KEY_RAW, b"minio-dash-salt-v1", dkLen=32, count=600000,
    hmac_hash_module=SHA256,
)

_parsed = urlparse(_raw_endpoint if "://" in _raw_endpoint else "https://" + _raw_endpoint)
MINIO_HOST   = _parsed.netloc or _raw_endpoint.rstrip("/")
MINIO_SECURE = _parsed.scheme != "http"

# No static folder: serving "." would expose .env, server.py and everything else
# in the working directory. ui.html and locales/ are served by explicit routes.
APP_DIR = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=None)

# Number of trusted reverse proxies in front of the panel (ingress, nginx…).
# Only then is X-Forwarded-For trusted for the client IP used by the login
# throttle; without a proxy leave it 0, or clients could spoof their IP.
PROXY_HOPS = int(os.environ.get("PROXY_HOPS", 0))
if PROXY_HOPS:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS, x_proto=PROXY_HOPS)

# ─── SESSION MANAGEMENT (REDIS + AES-GCM) ────────────────────────────────────

def encrypt_creds(ak: str, sk: str) -> str:
    nonce = secrets.token_bytes(12)
    cipher = AES.new(_enc_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(json.dumps({"ak": ak, "sk": sk}).encode())
    return base64.b64encode(nonce + tag + ct).decode()

def decrypt_creds(blob: str) -> dict | None:
    try:
        raw = base64.b64decode(blob)
        nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(_enc_key, AES.MODE_GCM, nonce=nonce)
        return json.loads(cipher.decrypt_and_verify(ct, tag).decode())
    except Exception:
        return None

class SessionManager:
    def __init__(self, redis_url: str | None):
        self.r = redis.from_url(redis_url) if redis_url else None
        self._local_cache = {} # Fallback for dev

    def set(self, username: str, ak: str, sk: str, ttl: int):
        if SESSION_BACKEND == "jwt": return # Creds stored in JWT
        blob = encrypt_creds(ak, sk)
        if self.r:
            self.r.setex(f"sess:{username}", ttl, blob)
        else:
            self._local_cache[username] = {"blob": blob, "exp": time.time() + ttl}

    def get(self, username: str) -> dict | None:
        if SESSION_BACKEND == "jwt": return None # Extract from JWT instead
        if self.r:
            blob = self.r.get(f"sess:{username}")
            if not blob: return None
            return decrypt_creds(blob.decode())
        else:
            entry = self._local_cache.get(username)
            if not entry or entry["exp"] < time.time():
                self._local_cache.pop(username, None)
                return None
            return decrypt_creds(entry["blob"])

    def delete(self, username: str):
        if self.r:
            self.r.delete(f"sess:{username}")
        else:
            self._local_cache.pop(username, None)

    # Logout denylist, keyed by the JWT's jti. Without Redis it is per-process,
    # so with several gunicorn workers a revoked token may still work on another
    # worker until it expires — set REDIS_URL for reliable revocation.
    def revoke(self, jti: str, ttl: int):
        if ttl <= 0:
            return
        if self.r:
            self.r.setex(f"revoked:{jti}", ttl, b"1")
        else:
            now = time.time()
            self._revoked = {k: v for k, v in getattr(self, "_revoked", {}).items() if v > now}
            self._revoked[jti] = now + ttl

    def is_revoked(self, jti: str) -> bool:
        if self.r:
            return bool(self.r.exists(f"revoked:{jti}"))
        return getattr(self, "_revoked", {}).get(jti, 0) > time.time()

_sessions = SessionManager(REDIS_URL)

# ─── MinIO client factory ─────────────────────────────────────────────────────

def _preview_sandbox(sandbox_id: str):
    import preview
    return preview.REGISTRY.get(sandbox_id or "anonymous")


def make_client(access_key: str, secret_key: str) -> Minio:
    if PREVIEW_MODE:
        import preview
        return preview.FakeMinio(_preview_sandbox(access_key))
    http_client = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=5, read=20),
        retries=urllib3.Retry(total=2),
        cert_reqs="CERT_NONE" if not MINIO_SECURE else "CERT_REQUIRED",
    )
    return Minio(
        MINIO_HOST,
        access_key=access_key,
        secret_key=secret_key,
        secure=MINIO_SECURE,
        http_client=http_client,
    )


def make_admin_client(access_key: str, secret_key: str):
    if PREVIEW_MODE:
        import preview
        return preview.FakeAdmin(_preview_sandbox(access_key))
    if not _HAS_MINIOADMIN or MinioAdmin is None:
        raise RuntimeError("MinioAdmin not available — pip install -U minio")
    creds = StaticProvider(access_key, secret_key)
    import inspect
    sig = inspect.signature(MinioAdmin.__init__)
    params = set(sig.parameters.keys())
    kwargs = {"endpoint": MINIO_HOST, "credentials": creds, "secure": MINIO_SECURE}
    if "cert_check" in params:
        # cert_check=True means "verify the certificate". It was `not MINIO_SECURE`,
        # which disabled verification on exactly the HTTPS endpoints. For plain
        # HTTP the flag is irrelevant.
        kwargs["cert_check"] = True
    return MinioAdmin(**kwargs)


_http = urllib3.PoolManager(
    cert_reqs="CERT_NONE" if not MINIO_SECURE else "CERT_REQUIRED",
    timeout=urllib3.Timeout(connect=5, read=20),
)

def _sign_v4_admin(method, path, access_key, secret_key, body=b"", query=""):
    host   = MINIO_HOST
    now    = datetime.datetime.now(datetime.timezone.utc)
    amz_date   = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    region, service = "us-east-1", "s3"
    payload_hash = hashlib.sha256(body).hexdigest()
    headers_str  = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_hdrs  = "host;x-amz-content-sha256;x-amz-date"
    full_path    = f"/minio/admin/v3{path}"
    canonical    = f"{method}\n{full_path}\n{query}\n{headers_str}\n{signed_hdrs}\n{payload_hash}"
    cred_scope   = f"{date_stamp}/{region}/{service}/aws4_request"
    sts          = f"AWS4-HMAC-SHA256\n{amz_date}\n{cred_scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    def _h(key, msg): return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    sk  = _h(_h(_h(_h(f"AWS4{secret_key}".encode(), date_stamp), region), service), "aws4_request")
    sig = hmac.new(sk, sts.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{cred_scope},SignedHeaders={signed_hdrs},Signature={sig}",
        "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash, "Host": host,
    }

def _q(value) -> str:
    """URL-encode a value for safe insertion into an admin API query string.
    Prevents names containing & ? = etc. from injecting extra query params or
    breaking the SigV4 signature (the query string is part of the signed payload)."""
    return quote(str(value), safe="")


def admin_request(method: str, path: str, access_key: str, secret_key: str,
                  body: bytes = b"", query: str = "") -> dict:
    if PREVIEW_MODE:
        import preview
        return preview.fake_admin_request(
            _preview_sandbox(access_key), method, path, body, query)
    if "?" in path and not query:
        path, query = path.split("?", 1)
    scheme = "https" if MINIO_SECURE else "http"
    url    = f"{scheme}://{MINIO_HOST}/minio/admin/v3{path}"
    if query: url += "?" + query
    headers = _sign_v4_admin(method, path, access_key, secret_key, body, query)
    if body: headers["Content-Type"] = "application/json"
    resp = _http.request(method, url, body=body or None, headers=headers)
    if resp.status >= 400:
        raise RuntimeError(f"Admin API {path} → {resp.status}")
    if resp.data:
        try: return json.loads(resp.data)
        except Exception: return {"raw": "binary data"}
    return {}


# ─── JWT auth ─────────────────────────────────────────────────────────────────

def create_token(username: str, is_admin: bool, ak: str = None, sk: str = None) -> str:
    payload = {
        "sub":      username,
        "admin":    is_admin,
        "iat":      int(time.time()),
        "exp":      int(time.time()) + SESSION_TTL,
        "jti":      secrets.token_urlsafe(16),
    }
    if SESSION_BACKEND == "jwt" and ak and sk:
        payload["creds"] = encrypt_creds(ak, sk)
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


def _issue_csrf_cookie(resp):
    """Set a fresh CSRF token cookie (readable by JS for the double-submit check)."""
    token = secrets.token_urlsafe(32)
    resp.set_cookie(
        "csrf_token", token,
        max_age=SESSION_TTL,
        httponly=False,      # must be readable by JS to echo back in X-CSRF-Token
        samesite="Lax",
        secure=COOKIE_SECURE,
    )
    return resp


def _set_session_cookie(resp, token: str):
    resp.set_cookie("token", token, max_age=SESSION_TTL, httponly=True,
                    samesite="Lax", secure=COOKIE_SECURE)
    _issue_csrf_cookie(resp)
    return resp


def _csrf_ok() -> bool:
    """Double-submit CSRF check: the X-CSRF-Token header must match the cookie.
    A cross-site attacker cannot read the cookie value, so cannot forge the header."""
    cookie = request.cookies.get("csrf_token", "")
    header = request.headers.get("X-CSRF-Token", "")
    return bool(cookie) and bool(header) and hmac.compare_digest(cookie, header)


def require_csrf(f):
    """Enforce the CSRF token on GET endpoints that return sensitive data
    (require_auth only guards mutating methods)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _csrf_ok():
            return jsonify({"error": "CSRF token missing or invalid"}), 403
        return f(*args, **kwargs)
    return wrapper


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1. Check CSRF for modifying methods (double-submit token)
        if request.method in ("POST", "PUT", "DELETE"):
            if not _csrf_ok():
                return jsonify({"error": "CSRF token missing or invalid"}), 403

        # 2. The session lives only in the HttpOnly cookie — it is never handed
        #    to JS, so there is no Bearer header path to steal it through.
        claims = decode_token(request.cookies.get("token", ""))
        if not claims or _sessions.is_revoked(claims.get("jti", "")):
            return jsonify({"error": "Unauthorized"}), 401

        request.token_claims = claims
        request.username = claims["sub"]
        request.is_admin = claims.get("admin", False)
        
        # 3. Get Credentials
        creds = None
        if SESSION_BACKEND == "jwt":
            creds_blob = claims.get("creds")
            if creds_blob:
                creds = decrypt_creds(creds_blob)
        else:
            creds = _sessions.get(claims["sub"])

        if not creds:
            return jsonify({"error": "Session expired, please login again"}), 401
            
        request.minio_ak = creds["ak"]
        request.minio_sk = creds["sk"]
        request.client   = make_client(creds["ak"], creds["sk"])
        try:
            request.admin_client = make_admin_client(creds["ak"], creds["sk"])
        except Exception:
            request.admin_client = None
        return f(*args, **kwargs)
    return wrapper


# Short-lived cache of admin-liveness checks so we don't hit MinIO /info on every
# admin request (the permission matrix already fans out N calls per request). A
# demoted admin is rejected within ADMIN_VERIFY_TTL seconds rather than instantly.
ADMIN_VERIFY_TTL = 45  # seconds
_admin_verify_cache: dict = {}
_admin_verify_lock = threading.Lock()


def _verify_admin_live() -> bool:
    """Re-check that the caller still holds MinIO admin rights right now, instead of
    trusting the 'admin' claim frozen into the JWT (valid up to SESSION_TTL). If an
    admin is demoted in MinIO, this makes the panel/API reject them within
    ADMIN_VERIFY_TTL seconds. Results are cached per-credential to avoid an /info
    round-trip on every admin request."""
    ak = getattr(request, "minio_ak", None)
    sk = getattr(request, "minio_sk", None)
    cache_key = hashlib.sha256(f"{ak}\x00{sk}".encode()).hexdigest() if ak else None
    now = time.time()
    if cache_key:
        with _admin_verify_lock:
            hit = _admin_verify_cache.get(cache_key)
            if hit and hit[0] > now:
                return hit[1]

    result = _do_verify_admin_live()

    if cache_key:
        with _admin_verify_lock:
            _admin_verify_cache[cache_key] = (now + ADMIN_VERIFY_TTL, result)
            # Opportunistically evict expired entries so the dict can't grow unbounded.
            if len(_admin_verify_cache) > 512:
                for k, (exp, _) in list(_admin_verify_cache.items()):
                    if exp <= now:
                        _admin_verify_cache.pop(k, None)
    return result


def _do_verify_admin_live() -> bool:
    ac = getattr(request, "admin_client", None)
    try:
        if ac and _HAS_MINIOADMIN:
            ac.info()
            return True
    except Exception:
        pass
    try:
        admin_request("GET", "/info", request.minio_ak, request.minio_sk)
        return True
    except Exception:
        return False


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_admin or not _verify_admin_live():
            request.is_admin = False
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return wrapper


def not_self(f):
    """For user endpoints that would lock the caller out of their own session
    (delete, disable, password reset). Must sit below require_auth."""
    @wraps(f)
    def wrapper(username, *args, **kwargs):
        if username == request.username:
            return jsonify({"error": "You cannot do this to your own account"}), 400
        return f(username, *args, **kwargs)
    return wrapper

# ─── STATIC ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    resp = send_from_directory(APP_DIR, "ui.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/api/config")
def public_config():
    """Unauthenticated: the handful of facts the login screen needs before a
    session exists. Deliberately exposes nothing beyond the deployment mode."""
    return jsonify({"preview": PREVIEW_MODE})


# ─── I18N ─────────────────────────────────────────────────────────────────────

@app.route("/i18n/<lang>")
def i18n(lang):
    allowed = {"en", "pl"}
    if lang not in allowed:
        return jsonify({"error": "Unknown language"}), 404
    script_dir = Path(__file__).parent
    for search_dir in [Path("locales"), script_dir / "locales", script_dir]:
        locale_path = search_dir / f"{lang}.json"
        if locale_path.exists():
            with open(locale_path, encoding="utf-8") as f:
                data = json.load(f)
            resp = jsonify(data)
            resp.headers["Cache-Control"] = "public, max-age=3600"
            return resp
    return jsonify({"error": "Locale file not found"}), 404


# ─── REQUEST / RESPONSE HELPERS ──────────────────────────────────────────────

def _json_body() -> dict:
    """Request JSON, or {} for an empty/invalid body. get_json(force=True)
    raises 400 on an empty body before `or {}` ever runs (e.g. a DELETE with
    no body)."""
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else {}


def _err(e: Exception, status: int = 500):
    """Error response that doesn't leak internals. S3 errors carry a code and
    message that are meant for the caller; anything else (connection errors,
    tracebacks with internal hostnames) is logged and replaced."""
    if isinstance(e, S3Error) or (PREVIEW_MODE and type(e).__name__ == "PreviewError"):
        return jsonify({"error": f"{e.code}: {e.message}"}), status
    app.logger.exception("request failed: %s", request.path)
    return jsonify({"error": "Internal error — see server logs"}), status


def _content_disposition(disposition: str, filename: str) -> str:
    """RFC 6266 header that survives quotes and non-ASCII names: an ASCII
    fallback in filename= plus the exact name in filename*=UTF-8''."""
    fallback = "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else "_" for c in filename) or "download"
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


# Brute-force throttle for /api/login. Only failures count, tracked per
# (client IP, username) and per client IP. Behind a reverse proxy set
# PROXY_HOPS so the real client IP is used — otherwise every visitor shares the
# proxy's address and the per-IP limit becomes a global one. It is per-process;
# put limit_req in front of the panel (nginx/ingress) for a hard global limit.
LOGIN_WINDOW        = 300   # seconds
LOGIN_MAX_PER_USER  = 10
LOGIN_MAX_PER_IP    = 50
_login_failures: dict = {}
_login_lock = threading.Lock()


def _login_keys(username: str) -> list[tuple[str, int]]:
    ip = request.remote_addr
    return [(f"u:{ip}:{username}", LOGIN_MAX_PER_USER),
            (f"ip:{ip}", LOGIN_MAX_PER_IP)]


def _login_blocked(username: str) -> bool:
    now = time.time()
    with _login_lock:
        for key, limit in _login_keys(username):
            hits = [t for t in _login_failures.get(key, []) if t > now - LOGIN_WINDOW]
            _login_failures[key] = hits
            if len(hits) >= limit:
                return True
    return False


def _login_failed(username: str):
    now = time.time()
    with _login_lock:
        for key, _ in _login_keys(username):
            _login_failures.setdefault(key, []).append(now)
        if len(_login_failures) > 10000:
            for k in [k for k, v in _login_failures.items() if not v or v[-1] <= now - LOGIN_WINDOW]:
                _login_failures.pop(k, None)


# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data     = _json_body()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")   # not stripped: spaces are valid in a secret key

    if PREVIEW_MODE:
        # No real credentials exist. Hand out a brand-new sandbox so every visit
        # starts from clean demo data, and grant admin so the whole panel is
        # explorable. The sandbox id travels as the access key, which is what
        # make_client()/admin_request() key the in-memory world on.
        import preview
        sandbox_id = preview.new_sandbox_id()
        display    = username or "preview-admin"
        token = create_token(display, True, ak=sandbox_id, sk="preview")
        resp = jsonify({"username": display, "admin": True,
                        "backend": SESSION_BACKEND, "preview": True})
        return _set_session_cookie(resp, token)

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if _login_blocked(username):
        return jsonify({"error": "Too many failed attempts, try again later"}), 429

    _BAD_CRED_CODES = {
        "AccessDenied", "InvalidAccessKeyId",
        "SignatureDoesNotMatch", "InvalidClientTokenId",
        "AuthorizationHeaderMalformed", "InvalidSignatureException",
    }
    try:
        client = make_client(username, password)
        # Optimized check: list_buckets might fail with AccessDenied for valid creds
        try:
            client.list_buckets()
        except S3Error as e:
            if e.code in ("AccessDenied", "AllAccessDisabled"):
                pass # Creds are valid, just no permission to list buckets
            elif any(code in str(e) for code in _BAD_CRED_CODES):
                _login_failed(username)
                return jsonify({"error": "Invalid credentials"}), 401
            else:
                raise
    except Exception as e:
        err_str = str(e)
        if any(code in err_str for code in _BAD_CRED_CODES):
            _login_failed(username)
            return jsonify({"error": "Invalid credentials"}), 401
        # The exception text includes the internal MinIO address — log it only.
        app.logger.error("login: cannot reach MinIO: %s", e)
        return jsonify({"error": "Cannot connect to MinIO"}), 503

    is_admin = False
    try:
        if _HAS_MINIOADMIN:
            tmp_ac = make_admin_client(username, password)
            tmp_ac.info()
            is_admin = True
    except Exception:
        try:
            admin_request("GET", "/info", username, password)
            is_admin = True
        except Exception:
            pass

    _sessions.set(username, username, password, SESSION_TTL)
    token = create_token(username, is_admin, ak=username, sk=password)

    # The token goes out only as an HttpOnly cookie, never in the body, so page
    # JS (and anything injected into it) cannot read or persist it.
    resp = jsonify({"username": username, "admin": is_admin, "backend": SESSION_BACKEND})
    return _set_session_cookie(resp, token)

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    _sessions.delete(request.username)
    claims = request.token_claims
    if claims.get("jti"):
        _sessions.revoke(claims["jti"], int(claims.get("exp", 0) - time.time()))
    resp = jsonify({"ok": True})
    resp.delete_cookie("token", samesite="Lax", secure=COOKIE_SECURE, httponly=True)
    resp.delete_cookie("csrf_token", samesite="Lax", secure=COOKIE_SECURE)
    return resp


@app.route("/api/me")
@require_auth
def me():
    # Report the *live* admin status (not the possibly-stale JWT claim) so the UI
    # only shows admin panels to users who still have admin rights in MinIO.
    live_admin = bool(request.is_admin) and _verify_admin_live()
    resp = jsonify({"username": request.username, "admin": live_admin,
                    "preview": PREVIEW_MODE})
    # Refresh the CSRF cookie so an auto-logged-in session (valid token cookie but
    # no/expired csrf cookie) can perform mutating requests without re-login.
    if not request.cookies.get("csrf_token"):
        _issue_csrf_cookie(resp)
    return resp


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _sdk_parse(raw) -> dict:
    """Parse SDK response — may be JSON string, bytes, or already a dict."""
    if isinstance(raw, (bytes,)):
        try:
            return json.loads(raw.decode())
        except Exception:
            return {}
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return raw if isinstance(raw, dict) else {}


def _policies_from_userinfo(uinfo: dict) -> list:
    """
    Extract policy list from a user info dict.
    MinIO SDK returns either:
      - memberOf: ["pol1", "pol2"]   (new format)
      - policyName: "pol1,pol2"      (old format, comma-separated string)
    """
    if not isinstance(uinfo, dict):
        return []

    # Prefer memberOf
    member_of = uinfo.get("memberOf")
    if member_of:
        if isinstance(member_of, list):
            return [p for p in member_of if p]
        if isinstance(member_of, str):
            return [p for p in member_of.split(",") if p]

    # Fall back to policyName (comma-separated)
    policy_name = uinfo.get("policyName", "")
    if policy_name:
        return [p.strip() for p in policy_name.split(",") if p.strip()]

    return []


def _sdk_user_list(ac) -> dict:
    """
    Call SDK user_list() and return parsed dict {username: {status, policies:[]}}.
    SDK returns a JSON string with structure:
      {"username": {"policyName": "pol1,pol2", "status": "enabled", ...}}
    """
    raw = ac.user_list()
    data = _sdk_parse(raw)
    result = {}
    for uname, uinfo in data.items():
        if isinstance(uinfo, dict):
            result[uname] = {
                "status": uinfo.get("status", "unknown"),
                "policies": _policies_from_userinfo(uinfo),
            }
        elif isinstance(uinfo, str):
            result[uname] = {"status": uinfo, "policies": []}
        else:
            result[uname] = {"status": "unknown", "policies": []}
    return result


def _sdk_user_info_single(ac, username: str, ak: str, sk: str) -> dict:
    """
    Get full user info for a single user.
    Tries SDK first, falls back to raw admin request.
    Returns dict with at least {status, policies: []}.
    """
    # Try raw admin request first (returns plaintext for user-info)
    try:
        raw = admin_request("GET", f"/user-info?accessKey={_q(username)}", ak, sk)
        if isinstance(raw, dict) and "status" in raw:
            return {
                "status": raw.get("status", "unknown"),
                "policies": _policies_from_userinfo(raw),
                **raw,
            }
    except Exception:
        pass

    # Fall back to SDK user_list (has full info including policyName)
    try:
        all_users = _sdk_user_list(ac)
        if username in all_users:
            return all_users[username]
    except Exception:
        pass

    return {"status": "unknown", "policies": []}


# ─── STATS ────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@require_auth
def get_stats():
    try:
        buckets = request.client.list_buckets()
        bucket_count = len(buckets)
    except Exception:
        bucket_count = 0

    users_count = 0
    active_count = 0
    disabled_count = 0
    used_bytes = 0

    if request.is_admin and _verify_admin_live():
        try:
            ac = request.admin_client
            if ac and _HAS_MINIOADMIN:
                users_data = _sdk_user_list(ac)
                for uname, uinfo in users_data.items():
                    users_count += 1
                    if uinfo.get("status") == "enabled":
                        active_count += 1
                    else:
                        disabled_count += 1
        except Exception:
            pass

        try:
            ac = request.admin_client
            if ac and _HAS_MINIOADMIN:
                info_raw = ac.info()
                info = _sdk_parse(info_raw)
            else:
                info = admin_request("GET", "/info", request.minio_ak, request.minio_sk)
            for srv in info.get("servers", []):
                for disk in srv.get("drives", []):
                    used_bytes += disk.get("usedSpace", 0)
        except Exception:
            pass

    return jsonify({
        "buckets":  bucket_count,
        "users":    users_count,
        "active":   active_count,
        "disabled": disabled_count,
        "usedBytes": used_bytes,
    })


# ─── POLICIES ─────────────────────────────────────────────────────────────────

@app.route("/api/policies")
@require_auth
@require_admin
def list_policies():
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            raw  = ac.policy_list()
            data = _sdk_parse(raw)
        else:
            data = admin_request("GET", "/list-canned-policies", request.minio_ak, request.minio_sk)
        if isinstance(data, dict):
            return jsonify(list(data.keys()))
    except Exception:
        pass
    return jsonify(["readwrite", "readonly", "writeonly", "diagnostics"])


@app.route("/api/policies/<name>")
@require_auth
@require_admin
def get_policy(name):
    try:
        data = admin_request("GET", f"/info-canned-policy?name={_q(name)}", request.minio_ak, request.minio_sk)
        return jsonify(data)
    except Exception as e:
        return _err(e)


@app.route("/api/policies", methods=["POST"])
@require_auth
@require_admin
def create_policy():
    data   = _json_body()
    name   = (data.get("name") or "").strip()
    policy = data.get("policy")

    if not name or not policy:
        return jsonify({"error": "Missing name or policy"}), 400

    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.policy_add(name, policy=policy)
        else:
            admin_request("PUT", f"/add-canned-policy?name={_q(name)}",
                          request.minio_ak, request.minio_sk, body=json.dumps(policy).encode())
        return jsonify({"name": name}), 201
    except Exception as e:
        return _err(e)


@app.route("/api/policies/<name>", methods=["DELETE"])
@require_auth
@require_admin
def delete_policy(name):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.policy_remove(name)
        else:
            admin_request("DELETE", f"/remove-canned-policy?name={_q(name)}", request.minio_ak, request.minio_sk)
        return jsonify({"deleted": name})
    except Exception as e:
        return _err(e)


# ─── USERS ────────────────────────────────────────────────────────────────────

@app.route("/api/debug-users")
@require_auth
@require_admin
def debug_users():
    # Diagnostic endpoint: leaks raw SDK internals. Only available in DEBUG mode.
    if not DEBUG:
        return jsonify({"error": "Not found"}), 404
    result = {}
    ak, sk = request.minio_ak, request.minio_sk
    ac = request.admin_client

    try:
        users = _sdk_user_list(ac)
        result["parsed_users"] = users
    except Exception as e:
        result["parsed_users_error"] = str(e)

    try:
        if ac and _HAS_MINIOADMIN:
            sdk_raw = ac.user_list()
            result["sdk_user_list_type"] = type(sdk_raw).__name__
            result["sdk_user_list_preview"] = repr(sdk_raw)[:500]
    except Exception as e:
        result["sdk_user_list_error"] = str(e)

    return jsonify(result)


@app.route("/api/users")
@require_auth
@require_admin
def list_users():
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            users_data = _sdk_user_list(ac)
        else:
            raw = admin_request("GET", "/list-users", request.minio_ak, request.minio_sk)
            users_data = {}
            if isinstance(raw, dict):
                for uname, uinfo in raw.items():
                    if isinstance(uinfo, dict):
                        users_data[uname] = {
                            "status": uinfo.get("status", "unknown"),
                            "policies": _policies_from_userinfo(uinfo),
                        }
                    else:
                        users_data[uname] = {"status": str(uinfo), "policies": []}

        users = []
        for uname, uinfo in users_data.items():
            users.append({
                "username": uname,
                "status":   uinfo.get("status", "unknown"),
                "policies": uinfo.get("policies", []),
            })
        return jsonify(users)
    except Exception as e:
        return _err(e)


@app.route("/api/users", methods=["POST"])
@require_auth
@require_admin
def create_user():
    data     = _json_body()
    username = (data.get("username") or "").strip()
    password = data.get("password") or _gen_password()
    # No implicit readwrite: a user created without explicit policies gets none.
    policies = data.get("policies", [])

    if not username:
        return jsonify({"error": "Missing username"}), 400
    if not isinstance(password, str):
        return jsonify({"error": "password must be a string"}), 400
    if not isinstance(policies, list) or not all(isinstance(p, str) for p in policies):
        return jsonify({"error": "policies must be a list of names"}), 400

    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_add(username, password)
        else:
            body = json.dumps({"secretKey": password, "status": "enabled"}).encode()
            admin_request("PUT", f"/add-user?accessKey={_q(username)}", request.minio_ak, request.minio_sk, body=body)
    except Exception as e:
        return _err(e)

    warn = []
    ac = request.admin_client
    for p in policies:
        try:
            if ac and _HAS_MINIOADMIN:
                ac.policy_set(p, user=username)
            else:
                body2 = json.dumps({"policies": [p], "userOrGroup": username, "isGroup": False}).encode()
                admin_request("POST", "/attach-user-or-group-policy", request.minio_ak, request.minio_sk, body=body2)
        except Exception as ex:
            warn.append(str(ex))

    resp = {"username": username, "password": password, "policies": policies}
    if warn:
        resp["warnings"] = warn
    return jsonify(resp), 201


@app.route("/api/users/<username>", methods=["DELETE"])
@require_auth
@require_admin
@not_self
def delete_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_remove(username)
        else:
            admin_request("DELETE", f"/remove-user?accessKey={_q(username)}", request.minio_ak, request.minio_sk)
        return jsonify({"deleted": username})
    except Exception as e:
        return _err(e)


@app.route("/api/users/<username>/enable", methods=["POST"])
@require_auth
@require_admin
def enable_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_enable(username)
        else:
            admin_request("PUT", f"/set-user-status?accessKey={_q(username)}&status=enabled", request.minio_ak, request.minio_sk)
        return jsonify({"status": "enabled", "username": username})
    except Exception as e:
        return _err(e)


@app.route("/api/users/<username>/disable", methods=["POST"])
@require_auth
@require_admin
@not_self
def disable_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_disable(username)
        else:
            admin_request("PUT", f"/set-user-status?accessKey={_q(username)}&status=disabled", request.minio_ak, request.minio_sk)
        return jsonify({"status": "disabled", "username": username})
    except Exception as e:
        return _err(e)


@app.route("/api/users/<username>/info")
@require_auth
@require_admin
def user_info(username):
    try:
        data = _sdk_user_info_single(request.admin_client, username, request.minio_ak, request.minio_sk)
        return jsonify(data)
    except Exception as e:
        return _err(e)


@app.route("/api/users/<username>/policies", methods=["GET"])
@require_auth
@require_admin
def get_user_policies(username):
    try:
        data = _sdk_user_info_single(request.admin_client, username, request.minio_ak, request.minio_sk)
        return jsonify(data.get("policies", []))
    except Exception as e:
        return _err(e)


@app.route("/api/users/<username>/policies", methods=["PUT"])
@require_auth
@require_admin
def set_user_policies(username):
    data     = _json_body()
    policies = data.get("policies", [])
    if not isinstance(policies, list) or not all(isinstance(p, str) for p in policies):
        return jsonify({"error": "policies must be a list of names"}), 400

    ac = request.admin_client
    try:
        info    = _sdk_user_info_single(ac, username, request.minio_ak, request.minio_sk)
        current = info.get("policies", [])
    except Exception:
        current = []

    if username == request.username and any(
            p in _ADMIN_POLICIES and p not in policies for p in current):
        return jsonify({"error": "You cannot remove admin policies from yourself"}), 400

    errors = []

    for p in current:
        if p not in policies:
            try:
                if ac and _HAS_MINIOADMIN:
                    ac.policy_unset(p, user=username)
                else:
                    body = json.dumps({"policies": [p], "userOrGroup": username, "isGroup": False}).encode()
                    admin_request("POST", "/detach-user-or-group-policy", request.minio_ak, request.minio_sk, body=body)
            except Exception as ex:
                errors.append(f"detach {p}: {ex}")

    for p in policies:
        if p not in current:
            try:
                if ac and _HAS_MINIOADMIN:
                    ac.policy_set(p, user=username)
                else:
                    body = json.dumps({"policies": [p], "userOrGroup": username, "isGroup": False}).encode()
                    admin_request("POST", "/attach-user-or-group-policy", request.minio_ak, request.minio_sk, body=body)
            except Exception as ex:
                errors.append(f"attach {p}: {ex}")

    resp = {"policies": policies}
    if errors:
        resp["warnings"] = errors
    return jsonify(resp)


@app.route("/api/users/<username>/reset-password", methods=["POST"])
@require_auth
@require_admin
@not_self
def reset_password(username):
    password = _gen_password()
    # user_add / add-user re-enables the account as a side effect. Capture the
    # current status first so a disabled user stays disabled after a reset.
    try:
        info = _sdk_user_info_single(request.admin_client, username, request.minio_ak, request.minio_sk)
        prev_status = str(info.get("status", "enabled")).lower()
    except Exception:
        prev_status = "enabled"
    was_disabled = prev_status == "disabled"

    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_add(username, password)
            if was_disabled:
                ac.user_disable(username)
        else:
            status = "disabled" if was_disabled else "enabled"
            body = json.dumps({"secretKey": password, "status": status}).encode()
            admin_request("PUT", f"/add-user?accessKey={_q(username)}", request.minio_ak, request.minio_sk, body=body)
        return jsonify({
            "username": username,
            "password": password,
            "status": "disabled" if was_disabled else "enabled",
        })
    except Exception as e:
        return _err(e)


# ─── BUCKETS ──────────────────────────────────────────────────────────────────

@app.route("/api/buckets")
@require_auth
def list_buckets():
    try:
        buckets = request.client.list_buckets()
        return jsonify([{
            "name":         b.name,
            "creationDate": b.creation_date.isoformat() if b.creation_date else "",
        } for b in buckets])
    except Exception as e:
        return _err(e)


@app.route("/api/buckets", methods=["POST"])
@require_auth
@require_admin
def create_bucket():
    data   = _json_body()
    name   = (data.get("name") or "").strip()
    region = (data.get("region") or "").strip() or None

    if not name:
        return jsonify({"error": "Missing name"}), 400

    try:
        if region:
            request.client.make_bucket(name, location=region)
        else:
            request.client.make_bucket(name)
        return jsonify({"name": name}), 201
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>", methods=["DELETE"])
@require_auth
@require_admin
def delete_bucket(bucket):
    data  = _json_body()
    force = data.get("force", False)

    try:
        if force:
            objects = request.client.list_objects(bucket, recursive=True)
            delete_list = [obj.object_name for obj in objects]
            if delete_list:
                from minio.deleteobjects import DeleteObject
                errors = request.client.remove_objects(bucket, [DeleteObject(n) for n in delete_list])
                list(errors)
        request.client.remove_bucket(bucket)
        return jsonify({"deleted": bucket})
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/info")
@require_auth
def bucket_info(bucket):
    try:
        objects = request.client.list_objects(bucket, recursive=True)
        count = 0
        total_size = 0
        for obj in objects:
            count += 1
            total_size += obj.size or 0
        return jsonify({"name": bucket, "objects": count, "size": total_size})
    except Exception as e:
        return _err(e)


# ─── FILES ────────────────────────────────────────────────────────────────────

@app.route("/api/buckets/<bucket>/files")
@require_auth
def list_files(bucket):
    prefix = request.args.get("prefix", "")
    try:
        objects = request.client.list_objects(bucket, prefix=prefix, recursive=False)
        items = []
        for obj in objects:
            name = obj.object_name
            rel = name[len(prefix):]
            is_dir = obj.is_dir
            items.append({
                "name":         rel.rstrip("/"),
                "fullKey":      name,
                "isDir":        is_dir,
                "size":         obj.size or 0,
                "lastModified": obj.last_modified.isoformat() if obj.last_modified else "",
                "etag":         obj.etag or "",
                "contentType":  obj.content_type or "",
            })
        return jsonify(items)
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/upload", methods=["POST"])
@require_auth
def upload_file(bucket):
    prefix = request.args.get("prefix", "")
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Missing file name"}), 400
    key = f"{prefix}{f.filename}"
    mime = mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
    
    # Calculate size without reading everything into RAM
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)

    try:
        request.client.put_object(
            bucket, key, 
            f.stream, # Use the stream directly
            size, 
            content_type=mime
        )
        return jsonify({"uploaded": key}), 201
    except Exception as e:
        return _err(e)


_ACTIVE_MIME_TYPES = {
    "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml",
    "application/xml", "application/javascript", "text/javascript",
    "application/x-javascript", "text/css",
}


@app.route("/api/buckets/<bucket>/files/view")
@require_auth
@require_csrf
def view_file(bucket):
    key = request.args.get("key", "")
    if not key:
        return jsonify({"error": "Missing key"}), 400

    try:
        response = request.client.get_object(bucket, key)
        mime     = mimetypes.guess_type(key)[0] or "application/octet-stream"

        # Bucket contents are untrusted and this endpoint shares the panel's
        # origin. Anything a browser would execute (HTML, SVG, XML, JS) goes out
        # as plain text; the UI re-types it itself and renders HTML only in an
        # iframe sandboxed without allow-same-origin.
        if mime in _ACTIVE_MIME_TYPES or mime.endswith(("+xml", "/xml")):
            mime = "text/plain; charset=utf-8"

        is_inline = mime.startswith(("image/", "video/", "audio/", "text/")) or \
                    mime in ("application/json", "application/pdf")

        headers = {
            "Content-Type": mime,
            "X-Content-Type-Options": "nosniff",
            # Even if the response is ever opened directly, it gets an opaque
            # origin: no scripts, no access to the panel's cookies or API.
            "Content-Security-Policy": "sandbox",
            "Cache-Control": "private, no-store",
        }
        if not is_inline:
            headers["Content-Disposition"] = _content_disposition("attachment", Path(key).name)

        def generate():
            try:
                for chunk in response.stream(32 * 1024):
                    yield chunk
            finally:
                response.close()
                response.release_conn()

        return Response(stream_with_context(generate()), headers=headers)
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/download")
@require_auth
@require_csrf
def download_file(bucket):
    key = request.args.get("key", "")
    if not key:
        return jsonify({"error": "Missing key"}), 400

    try:
        response = request.client.get_object(bucket, key)
        mime     = mimetypes.guess_type(key)[0] or "application/octet-stream"
        filename = Path(key).name

        def generate():
            try:
                for chunk in response.stream(32 * 1024):
                    yield chunk
            finally:
                response.close()
                response.release_conn()

        return Response(
            stream_with_context(generate()),
            headers={
                "Content-Type": mime,
                "Content-Disposition": _content_disposition("attachment", filename),
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "sandbox",
                "Cache-Control": "private, no-store",
            },
        )
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/delete", methods=["POST"])
@require_auth
def delete_file(bucket):
    data      = _json_body()
    key       = str(data.get("key") or "")
    recursive = data.get("recursive", False)

    if not key:
        return jsonify({"error": "Missing key"}), 400
    if recursive and not key.endswith("/"):
        # Without the slash, prefix "photo" would also wipe "photos/…".
        return jsonify({"error": "Recursive delete needs a folder key ending in '/'"}), 400

    try:
        if recursive:
            from minio.deleteobjects import DeleteObject
            objects = request.client.list_objects(bucket, prefix=key, recursive=True)
            names   = [obj.object_name for obj in objects]
            if names:
                errs = request.client.remove_objects(bucket, [DeleteObject(n) for n in names])
                list(errs)
        else:
            request.client.remove_object(bucket, key)
        return jsonify({"deleted": key})
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/rename", methods=["POST"])
@require_auth
def rename_file(bucket):
    data = _json_body()
    # Keys are not stripped: leading/trailing spaces are part of an S3 key.
    src  = str(data.get("src") or "")
    dst  = str(data.get("dst") or "")

    if not src or not dst:
        return jsonify({"error": "Missing src or dst"}), 400
    if src == dst:
        # Copy-then-delete onto itself would delete the object.
        return jsonify({"src": src, "dst": dst})

    try:
        if src.endswith("/"):
            # A folder is just a prefix: move every object under it.
            if not dst.endswith("/"):
                dst += "/"
            if dst.startswith(src):
                return jsonify({"error": "Cannot move a folder into itself"}), 400
            from minio.deleteobjects import DeleteObject
            names = [o.object_name for o in
                     request.client.list_objects(bucket, prefix=src, recursive=True)]
            for n in names:
                request.client.copy_object(bucket, dst + n[len(src):], CopySource(bucket, n))
            # Delete only after every copy succeeded.
            errs = list(request.client.remove_objects(bucket, [DeleteObject(n) for n in names]))
            if errs:
                return jsonify({"error": f"Copied, but {len(errs)} source objects could not be deleted"}), 500
        else:
            request.client.copy_object(bucket, dst, CopySource(bucket, src))
            request.client.remove_object(bucket, src)
        return jsonify({"src": src, "dst": dst})
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/mkdir", methods=["POST"])
@require_auth
def make_folder(bucket):
    data   = _json_body()
    prefix = (data.get("prefix") or "").strip()
    name   = (data.get("name")   or "").strip()

    if not name:
        return jsonify({"error": "Missing name"}), 400

    key = f"{prefix}{name}/.keep"
    try:
        request.client.put_object(bucket, key, io.BytesIO(b""), 0, content_type="application/x-directory")
        return jsonify({"created": f"{prefix}{name}/"}), 201
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/files/share", methods=["POST"])
@require_auth
def share_file(bucket):
    data   = _json_body()
    key    = str(data.get("key") or "")
    try:
        expire_h = int(data.get("expire", 168))
    except (TypeError, ValueError):
        return jsonify({"error": "expire must be a number of hours"}), 400

    if not key:
        return jsonify({"error": "Missing key"}), 400
    # SigV4 presigned URLs are capped at 7 days.
    if not 1 <= expire_h <= 168:
        return jsonify({"error": "expire must be between 1 and 168 hours"}), 400

    try:
        import datetime
        url = request.client.presigned_get_object(
            bucket, key,
            expires=datetime.timedelta(hours=expire_h),
        )
        return jsonify({"url": url, "expire": f"{expire_h}h"})
    except Exception as e:
        return _err(e)


# ─── BUCKET POLICY ────────────────────────────────────────────────────────────

@app.route("/api/buckets/<bucket>/policy")
@require_auth
@require_admin
def get_bucket_policy(bucket):
    try:
        policy = request.client.get_bucket_policy(bucket)
        return jsonify({"policy": json.loads(policy) if isinstance(policy, str) else policy})
    except S3Error as e:
        if "NoSuchBucketPolicy" in str(e):
            return jsonify({"policy": None})
        return _err(e)
    except Exception as e:
        return _err(e)


@app.route("/api/buckets/<bucket>/policy", methods=["PUT"])
@require_auth
@require_admin
def set_bucket_policy(bucket):
    data   = _json_body()
    policy = data.get("policy")

    try:
        if policy is None:
            request.client.delete_bucket_policy(bucket)
        else:
            request.client.set_bucket_policy(bucket, json.dumps(policy))
        return jsonify({"ok": True})
    except Exception as e:
        return _err(e)


# ─── PERMISSION MATRIX ────────────────────────────────────────────────────────

@app.route("/api/permission-matrix")
@require_auth
@require_admin
def permission_matrix():
    ac = request.admin_client

    try:
        if ac and _HAS_MINIOADMIN:
            users_parsed = _sdk_user_list(ac)
            raw2 = ac.policy_list()
            policies_raw = _sdk_parse(raw2)
        else:
            # fallback: raw is encrypted for list-users, so we can't use it
            users_parsed = {}
            policies_raw = admin_request("GET", "/list-canned-policies", request.minio_ak, request.minio_sk)
    except Exception as e:
        return _err(e)

    try:
        buckets = [b.name for b in request.client.list_buckets()]
    except Exception:
        buckets = []

    policies = list(policies_raw.keys()) if isinstance(policies_raw, dict) else []

    # Build {policyName: {bucket: access}} by parsing policy JSON
    policy_access: dict[str, dict[str, str]] = {}
    for pname in policies:
        try:
            pdata = admin_request("GET", f"/info-canned-policy?name={_q(pname)}",
                                  request.minio_ak, request.minio_sk)
            policy_access[pname] = _parse_policy_access(pdata, buckets)
        except Exception:
            policy_access[pname] = {}

    # Well-known built-ins cover all buckets
    for bname in buckets:
        policy_access.setdefault("readwrite", {})[bname] = "rw"
        policy_access.setdefault("readonly",  {})[bname] = "r"
        policy_access.setdefault("writeonly", {})[bname] = "w"

    # Build matrix from already-parsed user list (has policies embedded)
    matrix = {}
    users  = list(users_parsed.keys())

    for uname, uinfo in users_parsed.items():
        member_of = uinfo.get("policies", [])

        # If no policies in list result, try fetching user info individually
        if not member_of:
            try:
                full = _sdk_user_info_single(ac, uname, request.minio_ak, request.minio_sk)
                member_of = full.get("policies", [])
            except Exception:
                pass

        matrix[uname] = {}
        for bucket in buckets:
            access = "none"
            for p in member_of:
                pa = policy_access.get(p, {}).get(bucket, "none")
                if pa == "rw":
                    access = "rw"; break
                elif pa == "r" and access == "none":
                    access = "r"
                elif pa == "w" and access == "none":
                    access = "w"
                elif pa == "r" and access == "w":
                    access = "rw"
                elif pa == "w" and access == "r":
                    access = "rw"
            matrix[uname][bucket] = access

    return jsonify({
        "users": users,
        "buckets": buckets,
        "matrix": matrix,
        "userPolicies": {u: v.get("policies", []) for u, v in users_parsed.items()},
        # Derived from policy text only: ignores Conditions, group policies,
        # bucket policies and cross-policy Deny. Not an effective-access check.
        "approximate": True,
    })


def _action_matches(actions: list[str], targets: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(t, a) for a in actions for t in targets)


def _resource_buckets(res: str, buckets: list[str]) -> list[str]:
    """Buckets whose objects a Resource covers, honouring wildcards such as
    arn:aws:s3:::logs-* or arn:aws:s3:::*/*."""
    if res == "*":
        return list(buckets)
    if not res.startswith("arn:aws:s3:::"):
        return []
    bucket_pat = res[len("arn:aws:s3:::"):].split("/", 1)[0]
    return [b for b in buckets if fnmatch.fnmatchcase(b, bucket_pat)]


def _parse_policy_access(policy_doc: dict, buckets: list[str]) -> dict[str, str]:
    """Approximate per-bucket access from a policy document.

    Read means object reads (GetObject), write means PutObject/DeleteObject —
    s3:ListAllMyBuckets or GetBucketLocation alone grant neither. Deny
    statements are applied after Allows. Statements with a Condition are
    skipped (both Allow and Deny), so conditional access is not shown."""
    READ  = ("s3:GetObject",)
    WRITE = ("s3:PutObject", "s3:DeleteObject")
    allow: dict[str, set] = {}
    deny:  dict[str, set] = {}

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Condition"):
            continue
        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        perms = set()
        if _action_matches(actions, READ):
            perms.add("r")
        if _action_matches(actions, WRITE):
            perms.add("w")
        if not perms:
            continue

        target = allow if effect == "Allow" else deny
        for res in resources:
            for bucket in _resource_buckets(res, buckets):
                target.setdefault(bucket, set()).update(perms)

    result = {}
    for bucket, perms in allow.items():
        perms = perms - deny.get(bucket, set())
        if perms:
            result[bucket] = "rw" if perms == {"r", "w"} else perms.pop()
    return result


_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ADMIN_POLICIES = {"consoleAdmin", "diagnostics"}


@app.route("/api/users/<username>/bucket-access", methods=["PUT"])
@require_auth
@require_admin
def set_bucket_access(username):
    data   = _json_body()
    access = data.get("access", {})  # {bucketName: 'rw'|'r'|'w'|'none'}

    # This endpoint detaches the user's other policies; run against yourself it
    # would strip your own admin rights mid-session.
    if username == request.username:
        return jsonify({"error": "You cannot edit your own bucket access"}), 400
    if not isinstance(access, dict):
        return jsonify({"error": "access must be an object"}), 400
    for bucket, level in access.items():
        # Names go straight into ARNs: '*' or 'a*' would grant every bucket.
        if not isinstance(bucket, str) or not _BUCKET_NAME_RE.match(bucket):
            return jsonify({"error": f"Invalid bucket name: {bucket!r}"}), 400
        if level not in ("none", "r", "w", "rw"):
            return jsonify({"error": f"Invalid access level for {bucket}: {level!r}"}), 400

    statements = []
    for bucket, level in access.items():
        if level == "none":
            continue
        arn_objects = f"arn:aws:s3:::{bucket}/*"
        arn_bucket  = f"arn:aws:s3:::{bucket}"

        if level in ("r", "rw"):
            statements.append({
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket",
                           "s3:GetBucketLocation"],
                "Resource": [arn_bucket, arn_objects],
            })
        if level in ("w", "rw"):
            statements.append({
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload",
                           "s3:ListMultipartUploadParts"],
                "Resource": [arn_objects],
            })

    policy_doc  = {"Version": "2012-10-17", "Statement": statements}
    policy_name = f"user-{username}-custom"

    ac = request.admin_client
    errors = []

    # 1. Create/update the custom policy
    try:
        if ac and _HAS_MINIOADMIN:
            ac.policy_add(policy_name, policy=policy_doc)
        else:
            admin_request("PUT", f"/add-canned-policy?name={_q(policy_name)}",
                          request.minio_ak, request.minio_sk, body=json.dumps(policy_doc).encode())
    except Exception as e:
        return _err(e)

    # 2. Get current user policies
    try:
        info    = _sdk_user_info_single(ac, username, request.minio_ak, request.minio_sk)
        current = info.get("policies", [])
    except Exception:
        current = []

    # 3. Detach all bucket-scoped policies that are NOT the new custom one.
    #    Administrative policies are left alone — the matrix only manages
    #    bucket access and must never silently demote an admin.
    for p in current:
        if p == policy_name or p in _ADMIN_POLICIES:
            continue
        try:
            if ac and _HAS_MINIOADMIN:
                ac.policy_unset(p, user=username)
            else:
                body2 = json.dumps({"policies": [p], "userOrGroup": username, "isGroup": False}).encode()
                admin_request("POST", "/detach-user-or-group-policy",
                              request.minio_ak, request.minio_sk, body=body2)
        except Exception as ex:
            errors.append(f"detach {p}: {ex}")

    # 4. Attach the custom policy (always, even if it was already there — ensures fresh assignment)
    try:
        if ac and _HAS_MINIOADMIN:
            ac.policy_set(policy_name, user=username)
        else:
            body3 = json.dumps({"policies": [policy_name], "userOrGroup": username, "isGroup": False}).encode()
            admin_request("POST", "/attach-user-or-group-policy",
                          request.minio_ak, request.minio_sk, body=body3)
    except Exception as ex:
        errors.append(f"attach {policy_name}: {ex}")

    resp = {"ok": True, "policy": policy_name, "access": access}
    if errors:
        resp["warnings"] = errors
    return jsonify(resp)


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _gen_password(n=20):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(n))


# ─── MAIN ─────────────────────────────────────────────────────────────────────

WEBUI_HOST = os.environ.get("WEBUI_HOST", f"http://localhost:{PORT}")

def _print_banner():
    print(f"""
  ╔══════════════════════════════════════════════╗
  ║                minio-dash v2                 ║
  ╚══════════════════════════════════════════════╝

  Endpoint : {'https' if MINIO_SECURE else 'http'}://{MINIO_HOST}
  Port     : {PORT}
  Mode     : {'PREVIEW — in-memory sandbox, no real MinIO' if PREVIEW_MODE else 'normal'}
  Auth     : JWT (HS256), TTL {SESSION_TTL//3600}h
  WebUI    : {WEBUI_HOST}
""")

GUNICORN_WORKERS = int(os.environ.get("GUNICORN_WORKERS", 0))
GUNICORN_THREADS  = int(os.environ.get("GUNICORN_THREADS", 0))

if __name__ == "__main__":
    _print_banner()
    try:
        import gunicorn.app.base

        workers = GUNICORN_WORKERS or 2
        threads  = GUNICORN_THREADS  or 8
        if PREVIEW_MODE:
            # Preview state (the sandboxes, and the ephemeral signing keys when
            # none were supplied) lives in this process's memory. A second worker
            # would hold a different world and reject the first one's tokens, so
            # preview scales with threads only.
            workers = 1
            threads = GUNICORN_THREADS or 16
            print("  [preview] forcing workers=1 — sandbox state is per-process")
        if not GUNICORN_WORKERS and not GUNICORN_THREADS:
            print(f"  [gunicorn] GUNICORN_WORKERS / GUNICORN_THREADS not set — "
                  f"using defaults (workers={workers}, threads={threads})")
        else:
            print(f"  [gunicorn] workers={workers}  threads={threads}")

        class _App(gunicorn.app.base.BaseApplication):
            def load_config(self):
                self.cfg.set("bind",      f"0.0.0.0:{PORT}")
                self.cfg.set("workers",   workers)
                self.cfg.set("threads",   threads)
                self.cfg.set("timeout",   120)
                self.cfg.set("accesslog", "-")
                self.cfg.set("errorlog",  "-")
            def load(self):
                return app

        _App().run()
    except ImportError:
        print("  [warn] gunicorn not installed — falling back to Flask dev server")
        print("         pip install gunicorn")
        app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
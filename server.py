#!/usr/bin/env python3
"""
minio-dash v2  –  Full S3 Admin Dashboard
No mc CLI needed – uses MinIO Python SDK + admin REST API directly.

Env vars (only ONE required):
  MINIO_ENDPOINT   – e.g. s3.racis.dev  or  http://localhost:9000
  SECRET_KEY       – JWT secret (auto-generated if not set)
  PORT             – HTTP port (default: 7474)

Run:
  pip install flask minio PyJWT
  MINIO_ENDPOINT=s3.racis.dev python server.py
"""

import os, json, time, secrets, string, hashlib, hmac, base64, mimetypes, io, struct, datetime
from pathlib import Path
from functools import wraps
from urllib.parse import urlparse

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

# ─── CONFIG ──────────────────────────────────────────────────────────────────
_raw_endpoint    = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
SECRET_KEY       = os.environ.get("SECRET_KEY")
ENC_KEY_RAW      = os.environ.get("ENCRYPTION_KEY")
REDIS_URL        = os.environ.get("REDIS_URL")
SESSION_BACKEND  = os.environ.get("SESSION_BACKEND", "jwt").lower() # jwt or redis
PORT             = int(os.environ.get("PORT", 7474))
SESSION_TTL      = 8 * 3600   # 8 hours

if not SECRET_KEY or not ENC_KEY_RAW:
    print("CRITICAL: SECRET_KEY and ENCRYPTION_KEY must be set in environment!")
    print(f"Generated SECRET_KEY suggestion: {secrets.token_hex(32)}")
    print(f"Generated ENCRYPTION_KEY suggestion: {secrets.token_hex(16)}")
    if os.environ.get("KUBERNETES_SERVICE_HOST"): # Fail fast in K8s
        raise SystemExit("Missing required security environment variables")

SECRET_KEY = SECRET_KEY or "dev-only-secret-key"
ENC_KEY_RAW = ENC_KEY_RAW or "dev-only-encryption-key"

# Derive a proper 32-byte key for AES-256
_enc_key = PBKDF2(ENC_KEY_RAW, b"minio-dash-salt-v1", dkLen=32, count=1000)

_parsed = urlparse(_raw_endpoint if "://" in _raw_endpoint else "https://" + _raw_endpoint)
MINIO_HOST   = _parsed.netloc or _raw_endpoint.rstrip("/")
MINIO_SECURE = _parsed.scheme != "http"

app = Flask(__name__, static_folder=".", static_url_path="")

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

_sessions = SessionManager(REDIS_URL)

# ─── MinIO client factory ─────────────────────────────────────────────────────

def make_client(access_key: str, secret_key: str) -> Minio:
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
    if not _HAS_MINIOADMIN or MinioAdmin is None:
        raise RuntimeError("MinioAdmin not available — pip install -U minio")
    creds = StaticProvider(access_key, secret_key)
    import inspect
    sig = inspect.signature(MinioAdmin.__init__)
    params = set(sig.parameters.keys())
    kwargs = {"endpoint": MINIO_HOST, "credentials": creds, "secure": MINIO_SECURE}
    if "cert_check" in params:
        kwargs["cert_check"] = False
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

def admin_request(method: str, path: str, access_key: str, secret_key: str,
                  body: bytes = b"", query: str = "") -> dict:
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
    }
    if SESSION_BACKEND == "jwt" and ak and sk:
        payload["creds"] = encrypt_creds(ak, sk)
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1. Check CSRF for modifying methods
        if request.method in ("POST", "PUT", "DELETE"):
            if request.headers.get("X-Requested-With") != "XMLHttpRequest":
                return jsonify({"error": "CSRF protection: X-Requested-With header missing"}), 403

        # 2. Get token from Cookie (preferred) or Header
        token = request.cookies.get("token")
        if not token:
            token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        
        claims = decode_token(token)
        if not claims:
            return jsonify({"error": "Unauthorized"}), 401
        
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


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_admin:
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ─── STATIC ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    resp = send_from_directory(".", "ui.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


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


# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

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
                return jsonify({"error": "Invalid credentials"}), 401
            else:
                raise
    except Exception as e:
        err_str = str(e)
        if any(code in err_str for code in _BAD_CRED_CODES):
            return jsonify({"error": "Invalid credentials"}), 401
        return jsonify({"error": f"Cannot connect to MinIO: {e}"}), 503

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

    resp = jsonify({"token": token, "username": username, "admin": is_admin, "backend": SESSION_BACKEND})
    resp.set_cookie(
        "token", token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="Lax",
        secure=MINIO_SECURE,
    )
    return resp

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    _sessions.delete(request.username)
    resp = jsonify({"ok": True})
    resp.delete_cookie("token")
    return resp


@app.route("/api/me")
@require_auth
def me():
    return jsonify({"username": request.username, "admin": request.is_admin})


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
        raw = admin_request("GET", f"/user-info?accessKey={username}", ak, sk)
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

    if request.is_admin:
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
        data = admin_request("GET", f"/info-canned-policy?name={name}", request.minio_ak, request.minio_sk)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/policies", methods=["POST"])
@require_auth
@require_admin
def create_policy():
    data   = request.get_json(force=True) or {}
    name   = (data.get("name") or "").strip()
    policy = data.get("policy")

    if not name or not policy:
        return jsonify({"error": "Missing name or policy"}), 400

    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.policy_add(name, policy=policy)
        else:
            admin_request("PUT", f"/add-canned-policy?name={name}",
                          request.minio_ak, request.minio_sk, body=json.dumps(policy).encode())
        return jsonify({"name": name}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/policies/<name>", methods=["DELETE"])
@require_auth
@require_admin
def delete_policy(name):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.policy_remove(name)
        else:
            admin_request("DELETE", f"/remove-canned-policy?name={name}", request.minio_ak, request.minio_sk)
        return jsonify({"deleted": name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── USERS ────────────────────────────────────────────────────────────────────

@app.route("/api/debug-users")
@require_auth
@require_admin
def debug_users():
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
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
@require_auth
@require_admin
def create_user():
    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or _gen_password()
    policies = data.get("policies", ["readwrite"])

    if not username:
        return jsonify({"error": "Missing username"}), 400

    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_add(username, password)
        else:
            body = json.dumps({"secretKey": password, "status": "enabled"}).encode()
            admin_request("PUT", f"/add-user?accessKey={username}", request.minio_ak, request.minio_sk, body=body)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
def delete_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_remove(username)
        else:
            admin_request("DELETE", f"/remove-user?accessKey={username}", request.minio_ak, request.minio_sk)
        return jsonify({"deleted": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/enable", methods=["POST"])
@require_auth
@require_admin
def enable_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_enable(username)
        else:
            admin_request("PUT", f"/set-user-status?accessKey={username}&status=enabled", request.minio_ak, request.minio_sk)
        return jsonify({"status": "enabled", "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/disable", methods=["POST"])
@require_auth
@require_admin
def disable_user(username):
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_disable(username)
        else:
            admin_request("PUT", f"/set-user-status?accessKey={username}&status=disabled", request.minio_ak, request.minio_sk)
        return jsonify({"status": "disabled", "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/info")
@require_auth
@require_admin
def user_info(username):
    try:
        data = _sdk_user_info_single(request.admin_client, username, request.minio_ak, request.minio_sk)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/policies", methods=["GET"])
@require_auth
@require_admin
def get_user_policies(username):
    try:
        data = _sdk_user_info_single(request.admin_client, username, request.minio_ak, request.minio_sk)
        return jsonify(data.get("policies", []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<username>/policies", methods=["PUT"])
@require_auth
@require_admin
def set_user_policies(username):
    data     = request.get_json(force=True) or {}
    policies = data.get("policies", [])

    ac = request.admin_client
    try:
        info    = _sdk_user_info_single(ac, username, request.minio_ak, request.minio_sk)
        current = info.get("policies", [])
    except Exception:
        current = []

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
def reset_password(username):
    password = _gen_password()
    try:
        ac = request.admin_client
        if ac and _HAS_MINIOADMIN:
            ac.user_add(username, password)
        else:
            body = json.dumps({"secretKey": password, "status": "enabled"}).encode()
            admin_request("PUT", f"/add-user?accessKey={username}", request.minio_ak, request.minio_sk, body=body)
        return jsonify({"username": username, "password": password})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets", methods=["POST"])
@require_auth
@require_admin
def create_bucket():
    data   = request.get_json(force=True) or {}
    name   = (data.get("name") or "").strip()
    region = (data.get("region") or "").strip() or None

    if not name:
        return jsonify({"error": "Missing name"}), 400

    try:
        request.client.make_bucket(name)
        return jsonify({"name": name}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>", methods=["DELETE"])
@require_auth
@require_admin
def delete_bucket(bucket):
    data  = request.get_json(force=True) or {}
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
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/upload", methods=["POST"])
@require_auth
def upload_file(bucket):
    prefix = request.args.get("prefix", "")
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files["file"]
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
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/view")
@require_auth
def view_file(bucket):
    key = request.args.get("key", "")
    if not key:
        return jsonify({"error": "Missing key"}), 400

    try:
        response = request.client.get_object(bucket, key)
        mime     = mimetypes.guess_type(key)[0] or "application/octet-stream"

        is_inline = mime.startswith(("image/", "video/", "audio/", "text/")) or \
                    mime in ("application/json", "application/javascript", "application/pdf")

        headers = {"Content-Type": mime}
        if not is_inline:
            headers["Content-Disposition"] = f'attachment; filename="{Path(key).name}"'

        def generate():
            try:
                for chunk in response.stream(32 * 1024):
                    yield chunk
            finally:
                response.close()
                response.release_conn()

        return Response(stream_with_context(generate()), headers=headers)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/download")
@require_auth
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
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/delete", methods=["POST"])
@require_auth
def delete_file(bucket):
    data      = request.get_json(force=True) or {}
    key       = (data.get("key") or "").strip()
    recursive = data.get("recursive", False)

    if not key:
        return jsonify({"error": "Missing key"}), 400

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
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/rename", methods=["POST"])
@require_auth
def rename_file(bucket):
    data = request.get_json(force=True) or {}
    src  = (data.get("src") or "").strip()
    dst  = (data.get("dst") or "").strip()

    if not src or not dst:
        return jsonify({"error": "Missing src or dst"}), 400

    try:
        request.client.copy_object(bucket, dst, CopySource(bucket, src))
        request.client.remove_object(bucket, src)
        return jsonify({"src": src, "dst": dst})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/mkdir", methods=["POST"])
@require_auth
def make_folder(bucket):
    data   = request.get_json(force=True) or {}
    prefix = (data.get("prefix") or "").strip()
    name   = (data.get("name")   or "").strip()

    if not name:
        return jsonify({"error": "Missing name"}), 400

    key = f"{prefix}{name}/.keep"
    try:
        request.client.put_object(bucket, key, io.BytesIO(b""), 0, content_type="application/x-directory")
        return jsonify({"created": f"{prefix}{name}/"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/files/share", methods=["POST"])
@require_auth
def share_file(bucket):
    data   = request.get_json(force=True) or {}
    key    = (data.get("key")    or "").strip()
    expire_h = int(data.get("expire", 168))

    if not key:
        return jsonify({"error": "Missing key"}), 400

    try:
        import datetime
        url = request.client.presigned_get_object(
            bucket, key,
            expires=datetime.timedelta(hours=expire_h),
        )
        return jsonify({"url": url, "expire": f"{expire_h}h"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buckets/<bucket>/policy", methods=["PUT"])
@require_auth
@require_admin
def set_bucket_policy(bucket):
    data   = request.get_json(force=True) or {}
    policy = data.get("policy")

    try:
        if policy is None:
            request.client.delete_bucket_policy(bucket)
        else:
            request.client.set_bucket_policy(bucket, json.dumps(policy))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500

    try:
        buckets = [b.name for b in request.client.list_buckets()]
    except Exception:
        buckets = []

    policies = list(policies_raw.keys()) if isinstance(policies_raw, dict) else []

    # Build {policyName: {bucket: access}} by parsing policy JSON
    policy_access: dict[str, dict[str, str]] = {}
    for pname in policies:
        try:
            pdata = admin_request("GET", f"/info-canned-policy?name={pname}",
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
    })


def _parse_policy_access(policy_doc: dict, buckets: list[str]) -> dict[str, str]:
    import re as _re
    result = {}
    statements = policy_doc.get("Statement", [])
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_read  = any("GetObject" in a or "s3:Get" in a or "s3:List" in a or a == "s3:*" for a in actions)
        has_write = any("PutObject" in a or "DeleteObject" in a or "s3:Put" in a or a == "s3:*" for a in actions)

        for res in resources:
            # Wildcard covering all buckets
            if res in ("*", "arn:aws:s3:::*", "arn:aws:s3:::*/*"):
                matched = list(buckets)
            else:
                # Extract exact bucket name from ARN: arn:aws:s3:::BUCKET or arn:aws:s3:::BUCKET/*
                m = _re.match(r'^arn:aws:s3:::([^/]+)(/.*)?$', res)
                matched = []
                if m:
                    b = m.group(1)
                    if b == "*":
                        matched = list(buckets)
                    elif b in buckets:
                        matched = [b]
                else:
                    # plain bucket name fallback
                    matched = [b for b in buckets if b == res]

            for bucket in matched:
                cur = result.get(bucket, "none")
                if has_read and has_write:
                    result[bucket] = "rw"
                elif has_read:
                    if cur == "none":   result[bucket] = "r"
                    elif cur == "w":    result[bucket] = "rw"
                elif has_write:
                    if cur == "none":   result[bucket] = "w"
                    elif cur == "r":    result[bucket] = "rw"
    return result


@app.route("/api/users/<username>/bucket-access", methods=["PUT"])
@require_auth
@require_admin
def set_bucket_access(username):
    data   = request.get_json(force=True) or {}
    access = data.get("access", {})  # {bucketName: 'rw'|'r'|'w'|'none'}

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
            admin_request("PUT", f"/add-canned-policy?name={policy_name}",
                          request.minio_ak, request.minio_sk, body=json.dumps(policy_doc).encode())
    except Exception as e:
        return jsonify({"error": f"Failed to create policy: {e}"}), 500

    # 2. Get current user policies
    try:
        info    = _sdk_user_info_single(ac, username, request.minio_ak, request.minio_sk)
        current = info.get("policies", [])
    except Exception:
        current = []

    # 3. Detach all policies that are NOT the new custom one
    for p in current:
        if p == policy_name:
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
        threads  = GUNICORN_THREADS  or 1
        if not GUNICORN_WORKERS and not GUNICORN_THREADS:
            print("  [gunicorn] GUNICORN_WORKERS / GUNICORN_THREADS not set — using defaults (workers=2, threads=1)")
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
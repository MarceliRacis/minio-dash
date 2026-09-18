"""AWS Signature V4 signing for the MinIO admin API.

There is no SDK covering the admin API, so this signing code is hand-written
and every admin operation in the panel depends on it. The golden signature
below is a regression pin: it was produced by this implementation under a
frozen clock, and any unintended change to the canonical request, the credential
scope or the key-derivation chain will move it.
"""

import hashlib
import hmac

import pytest

FROZEN_AMZ_DATE = "20260115T123045Z"
FROZEN_DATE_STAMP = "20260115"


def test_header_shape(server, frozen_clock):
    h = server._sign_v4_admin("GET", "/info", "AKIATEST", "secret")
    assert h["x-amz-date"] == FROZEN_AMZ_DATE
    assert h["Host"] == server.MINIO_HOST
    # Empty body → the well-known SHA-256 of the empty string.
    assert h["x-amz-content-sha256"] == hashlib.sha256(b"").hexdigest()
    assert h["Authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert f"Credential=AKIATEST/{FROZEN_DATE_STAMP}/us-east-1/s3/aws4_request" in h["Authorization"]
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in h["Authorization"]


def test_body_hash_is_the_real_payload_hash(server, frozen_clock):
    body = b'{"name":"readonly"}'
    h = server._sign_v4_admin("PUT", "/add-canned-policy", "AKIATEST", "secret", body=body)
    assert h["x-amz-content-sha256"] == hashlib.sha256(body).hexdigest()


def _signature(headers):
    return headers["Authorization"].split("Signature=")[1]


def test_signature_is_deterministic_under_a_frozen_clock(server, frozen_clock):
    a = server._sign_v4_admin("GET", "/info", "AKIATEST", "secret")
    b = server._sign_v4_admin("GET", "/info", "AKIATEST", "secret")
    assert _signature(a) == _signature(b)


# GET /info, AKIATEST/secret, clock frozen at 2026-01-15T12:30:45Z.
_EXPECTED_GOLDEN = "3666c0f946677abb78e0cf635434d29b6226d11944bb8c0b4981eab342a85e60"


def test_golden_signature(server, frozen_clock):
    """Regression pin — see module docstring."""
    h = server._sign_v4_admin("GET", "/info", "AKIATEST", "secret")
    assert _signature(h) == _EXPECTED_GOLDEN


@pytest.mark.parametrize("kwargs", [
    {"method": "PUT"},
    {"path": "/remove-user"},
    {"secret_key": "other-secret"},
    {"body": b"x"},
    {"query": "accessKey=bob"},
])
def test_every_signed_input_changes_the_signature(server, frozen_clock, kwargs):
    base = dict(method="GET", path="/info", access_key="AKIATEST",
                secret_key="secret", body=b"", query="")
    ref = _signature(server._sign_v4_admin(**base))
    assert _signature(server._sign_v4_admin(**{**base, **kwargs})) != ref


def test_access_key_is_advertised_but_not_signed(server, frozen_clock):
    """Per the SigV4 spec the access key identifies the credential in the
    Authorization header; only the secret key feeds the signature. Same secret
    plus a different access key must therefore sign identically."""
    a = server._sign_v4_admin("GET", "/info", "AKIATEST", "secret")
    b = server._sign_v4_admin("GET", "/info", "AKIAOTHER", "secret")
    assert _signature(a) == _signature(b)
    assert "Credential=AKIATEST/" in a["Authorization"]
    assert "Credential=AKIAOTHER/" in b["Authorization"]


def test_signing_key_derivation_matches_the_aws_scheme(server, frozen_clock):
    """Independently re-derive the signature from the documented SigV4 steps
    and check the implementation agrees."""
    method, path, ak, sk = "GET", "/info", "AKIATEST", "secret"
    payload_hash = hashlib.sha256(b"").hexdigest()
    full_path = f"/minio/admin/v3{path}"
    canonical = (
        f"{method}\n{full_path}\n\n"
        f"host:{server.MINIO_HOST}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{FROZEN_AMZ_DATE}\n"
        f"\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}"
    )
    scope = f"{FROZEN_DATE_STAMP}/us-east-1/s3/aws4_request"
    sts = (f"AWS4-HMAC-SHA256\n{FROZEN_AMZ_DATE}\n{scope}\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")

    def _h(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    key = _h(_h(_h(_h(f"AWS4{sk}".encode(), FROZEN_DATE_STAMP),
                   "us-east-1"), "s3"), "aws4_request")
    expected = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()

    assert _signature(server._sign_v4_admin(method, path, ak, sk)) == expected


# ─── query encoding ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,encoded", [
    ("simple", "simple"),
    ("with space", "with%20space"),
    ("a&b", "a%26b"),
    ("a=b", "a%3Db"),
    ("a?b", "a%3Fb"),
    ("a/b", "a%2Fb"),
    ("użytkownik", "u%C5%BCytkownik"),
])
def test_q_encodes_query_metacharacters(server, raw, encoded):
    assert server._q(raw) == encoded


def test_q_blocks_query_parameter_injection(server):
    """A username like `bob&policy=consoleAdmin` must not smuggle a second
    parameter into the signed admin request."""
    hostile = "bob&policyName=consoleAdmin"
    assert "&" not in server._q(hostile)
    assert f"accessKey={server._q(hostile)}" == "accessKey=bob%26policyName%3DconsoleAdmin"

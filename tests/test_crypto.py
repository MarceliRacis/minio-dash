"""AES-GCM credential sealing.

These creds ride inside a cookie the client holds, so confidentiality and
tamper-detection are the whole security story here.
"""

import base64

import pytest


def test_roundtrip(server):
    blob = server.encrypt_creds("AKIAEXAMPLE", "sup3r-s3cret")
    assert server.decrypt_creds(blob) == {"ak": "AKIAEXAMPLE", "sk": "sup3r-s3cret"}


def test_ciphertext_does_not_leak_plaintext(server):
    blob = server.encrypt_creds("AKIAEXAMPLE", "sup3r-s3cret")
    assert "sup3r-s3cret" not in blob
    assert "sup3r-s3cret" not in base64.b64decode(blob).decode("latin-1")


def test_nonce_is_fresh_per_call(server):
    """A reused GCM nonce would be catastrophic — same input must not produce
    the same ciphertext twice."""
    a = server.encrypt_creds("AKIAEXAMPLE", "sup3r-s3cret")
    b = server.encrypt_creds("AKIAEXAMPLE", "sup3r-s3cret")
    assert a != b


@pytest.mark.parametrize("blob", [
    "",
    "not-base64!!",
    base64.b64encode(b"too-short").decode(),
    base64.b64encode(b"\x00" * 64).decode(),
])
def test_garbage_returns_none_instead_of_raising(server, blob):
    assert server.decrypt_creds(blob) is None


def test_tampered_ciphertext_is_rejected(server):
    """GCM auth tag must reject a flipped bit rather than return garbage creds."""
    raw = bytearray(base64.b64decode(server.encrypt_creds("AKIAEXAMPLE", "s3cret")))
    raw[-1] ^= 0x01
    assert server.decrypt_creds(base64.b64encode(bytes(raw)).decode()) is None


def test_tampered_tag_is_rejected(server):
    raw = bytearray(base64.b64decode(server.encrypt_creds("AKIAEXAMPLE", "s3cret")))
    raw[13] ^= 0xFF  # inside the 16-byte tag at offset 12..28
    assert server.decrypt_creds(base64.b64encode(bytes(raw)).decode()) is None


def test_blob_from_a_different_key_is_rejected(server, monkeypatch):
    """A blob sealed under someone else's ENCRYPTION_KEY must not decrypt."""
    blob = server.encrypt_creds("AKIAEXAMPLE", "s3cret")
    monkeypatch.setattr(server, "_enc_key", b"\xAA" * 32)
    assert server.decrypt_creds(blob) is None


def test_key_derivation_is_pinned(server):
    """The AES key is derived from ENCRYPTION_KEY via PBKDF2-HMAC-SHA256,
    600k iterations, salt 'minio-dash-salt-v1'. Changing any of those silently
    invalidates every credential blob and session already in the wild, so the
    derived key is pinned here. conftest sets ENCRYPTION_KEY='1'*32."""
    assert server._enc_key.hex() == (
        "ddc410c68c30a570e1647253be108153"
        "624fbb1c9f950f880cc4c3f2f6eff974"
    )

"""Ký entitlement token bằng Ed25519 (PyNaCl).

Token format trả cho client/launcher:
  { "claims_b64": "<base64 canonical JSON>", "signature": "<base64 64B>", "alg": "Ed25519" }

Launcher (C/libsodium) decode claims_b64 -> bytes, verify chữ ký TRÊN ĐÚNG bytes đó (không
serialize lại) rồi parse JSON để đọc field. Nhờ vậy không lệch byte giữa Python và C.
"""
import base64
import json
from datetime import datetime, timedelta, timezone

import nacl.signing
import nacl.utils

from ..config import DATA_DIR

SEED_FILE = DATA_DIR / "server_ed25519.seed"


def _load_or_create_signing_key() -> nacl.signing.SigningKey:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SEED_FILE.exists():
        seed = SEED_FILE.read_bytes()
    else:
        seed = nacl.utils.random(32)
        SEED_FILE.write_bytes(seed)
    return nacl.signing.SigningKey(seed)


_signing_key = _load_or_create_signing_key()


def server_public_key_b64() -> str:
    return base64.b64encode(_signing_key.verify_key.encode()).decode()


def _iso(dt: datetime) -> str:
    # Định dạng cố định, sort được theo thời gian (launcher so sánh chuỗi để check offline).
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def issue_entitlement_token(user_id: int, product_id: str, device_hash: str,
                            offline_days: int) -> dict:
    now = datetime.now(timezone.utc)
    claims = {
        "user_id": user_id,
        "product_id": product_id,
        "device_hash": device_hash,
        "issued_at": _iso(now),
        "offline_until": _iso(now + timedelta(days=offline_days)),
    }
    # canonical: sort_keys + bỏ khoảng trắng -> deterministic
    claims_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = _signing_key.sign(claims_bytes).signature  # detached 64 byte
    return {
        "claims_b64": base64.b64encode(claims_bytes).decode(),
        "signature": base64.b64encode(sig).decode(),
        "alg": "Ed25519",
        "offline_until": claims["offline_until"],
    }

"""Mật khẩu (Argon2id qua PyNaCl) + session token (JWT HS256).

Lưu ý: token entitlement cho launcher (C) sẽ dùng Ed25519/PyNaCl ở giai đoạn 5 — không phải JWT ở đây.
Session token người dùng chỉ server tự verify nên HS256 là đủ và đơn giản.
"""
from datetime import datetime, timedelta, timezone

import jwt
import nacl.exceptions
import nacl.pwhash

from .config import settings


# ---------- Password ----------
def hash_password(password: str) -> str:
    return nacl.pwhash.str(password.encode("utf-8")).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return nacl.pwhash.verify(password_hash.encode("ascii"), password.encode("utf-8"))
    except nacl.exceptions.InvalidkeyError:
        return False


# ---------- JWT session tokens ----------
def _create_token(subject: int, token_type: str, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject),
        "type": token_type,
        "iat": now,
        "exp": now + expires,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(user_id: int) -> str:
    return _create_token(user_id, "access", timedelta(minutes=settings.access_token_minutes))


def create_refresh_token(user_id: int) -> str:
    return _create_token(user_id, "refresh", timedelta(days=settings.refresh_token_days))


def decode_token(token: str, expected_type: str) -> int:
    """Trả về user_id. Raise jwt.PyJWTError nếu token sai/hết hạn/sai loại."""
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"expected token type '{expected_type}'")
    return int(payload["sub"])

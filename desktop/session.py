"""Lưu/đọc session: token + thông tin user + cache thư viện + cache entitlement (offline).

File được mã hóa bằng Windows DPAPI (xem dpapi.py): bí mật (session token, payload key) bị
trói vào tài khoản Windows trên máy này -> copy .session.json sang máy khác là vô dụng.
"""
import json
import os

import config
import dpapi


def _write(data: dict) -> None:
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    blob = dpapi.protect(raw)            # mã hóa trước khi ghi
    with open(config.SESSION_FILE, "wb") as f:
        f.write(blob)


def save(user: dict, tokens: dict, library: list[dict] | None = None) -> None:
    data = load() or {}
    data.update({"user": user, "tokens": tokens, "library": library or data.get("library", [])})
    _write(data)


def update_library(library: list[dict]) -> None:
    data = load()
    if data:
        data["library"] = library
        _write(data)


def load() -> dict | None:
    if not os.path.exists(config.SESSION_FILE):
        return None
    try:
        with open(config.SESSION_FILE, "rb") as f:
            blob = f.read()
        try:
            raw = dpapi.unprotect(blob)          # file mã hóa của máy/user này
        except OSError:
            # Không giải mã được: file plaintext cũ (migrate) HOẶC copy từ máy khác (vô dụng).
            raw = blob
        return json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        # Copy từ máy khác -> blob lạ -> coi như chưa đăng nhập (phải login lại).
        return None


def clear() -> None:
    if os.path.exists(config.SESSION_FILE):
        os.remove(config.SESSION_FILE)


# ---------- Cache entitlement bundle cho offline mode ----------
# Lưu ý: bundle chứa payload_key_b64 (bí mật) — chấp nhận lưu local để chạy offline,
# được bảo vệ bởi offline_until (hết hạn phải online lại) + hardware binding.
# File .session.json đã gitignore. GĐ7 sẽ mã hóa bằng DPAPI.
def cache_entitlement(product_id: str, bundle: dict) -> None:
    data = load() or {}
    data.setdefault("entitlements", {})[product_id] = bundle
    _write(data)


def get_cached_entitlement(product_id: str) -> dict | None:
    return (load() or {}).get("entitlements", {}).get(product_id)

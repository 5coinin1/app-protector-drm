"""Lưu/đọc session: token + thông tin user + cache thư viện + cache entitlement (offline)."""
import json
import os

import config


def _write(data: dict) -> None:
    with open(config.SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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
        with open(config.SESSION_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
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

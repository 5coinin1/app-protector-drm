"""GĐ7: rate-limit đăng nhập + JWT secret không hardcode + validate payload key."""
import base64
import os

from app.config import settings, _DEFAULT_JWT_SECRET
from app.services import ratelimit
from tests.conftest import auth_header


def test_login_rate_limited_after_max_attempts(client):
    ratelimit._failures.clear()  # bắt đầu sạch cho test xác định

    # Sai mật khẩu đúng login_max_attempts lần -> mỗi lần 401.
    for _ in range(settings.login_max_attempts):
        r = client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong"})
        assert r.status_code == 401

    # Lần kế tiếp -> bị khóa (429), kể cả khi mật khẩu đúng.
    r = client.post("/auth/login",
                    json={"email": settings.admin_email, "password": settings.admin_password})
    assert r.status_code == 429

    ratelimit._failures.clear()  # dọn để không ảnh hưởng test khác


def test_successful_login_resets_counter(client):
    ratelimit._failures.clear()

    # Vài lần sai (dưới ngưỡng) rồi đăng nhập đúng -> reset.
    for _ in range(settings.login_max_attempts - 1):
        client.post("/auth/login", json={"email": settings.admin_email, "password": "wrong"})
    ok = client.post("/auth/login",
                     json={"email": settings.admin_email, "password": settings.admin_password})
    assert ok.status_code == 200

    # Sau reset, lại sai vẫn là 401 (không phải 429).
    r = client.post("/auth/login", json={"email": settings.admin_email, "password": "wrong"})
    assert r.status_code == 401

    ratelimit._failures.clear()


def test_jwt_secret_not_default():
    # get_settings() đã thay placeholder bằng secret thật (random bền hoặc từ .env).
    assert settings.jwt_secret != _DEFAULT_JWT_SECRET
    assert len(settings.jwt_secret) >= 16


def test_set_payload_key_rejects_invalid(client, admin_token):
    h = auth_header(admin_token)
    client.post("/admin/products", json={"product_id": "keychk", "name": "K", "version": "1.0.0"}, headers=h)

    # Key rác / sai độ dài -> 400
    bad = client.post("/admin/products/keychk/key",
                      json={"payload_key_b64": "khong-phai-key"}, headers=h)
    assert bad.status_code == 400
    short = client.post("/admin/products/keychk/key",
                        json={"payload_key_b64": base64.b64encode(os.urandom(16)).decode()}, headers=h)
    assert short.status_code == 400

    # Key base64 của đúng 32 byte -> 200
    good = client.post("/admin/products/keychk/key",
                       json={"payload_key_b64": base64.b64encode(os.urandom(32)).decode()}, headers=h)
    assert good.status_code == 200

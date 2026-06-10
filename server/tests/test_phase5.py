"""Test giai đoạn 5: runtime issue-token, hardware/device limit, revoke, payload key, chữ ký."""
import base64

import nacl.signing
from tests.conftest import auth_header


def _setup_owned(client, admin_token, email="player@test.com"):
    """Tạo product + key + user sở hữu demo_app. Trả (user access token, user_id)."""
    h = auth_header(admin_token)
    client.post("/admin/products", json={"product_id": "demo_app", "name": "Demo App"}, headers=h)
    # payload key giả (base64 của 32 byte)
    key_b64 = base64.b64encode(b"0" * 32).decode()
    r = client.post("/admin/products/demo_app/key", json={"payload_key_b64": key_b64}, headers=h)
    assert r.status_code == 200, r.text

    r = client.post("/admin/users", json={"email": email, "password": "password123"}, headers=h)
    uid = r.json()["id"]
    client.post("/admin/entitlements/grant", json={"user_id": uid, "product_id": "demo_app"}, headers=h)

    r = client.post("/auth/login", json={"email": email, "password": "password123"})
    return r.json()["tokens"]["access_token"], uid, key_b64


def test_public_key(client):
    r = client.get("/runtime/public-key")
    assert r.status_code == 200
    assert r.json()["alg"] == "Ed25519"
    base64.b64decode(r.json()["server_public_key_b64"])  # decode được


def test_issue_token_and_verify_signature(client, admin_token):
    token, uid, key_b64 = _setup_owned(client, admin_token)

    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-ABC-123", "device_name": "PC1"},
                    headers=auth_header(token))
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["payload_key_b64"] == key_b64  # server trả đúng key

    tok = data["token"]
    claims_bytes = base64.b64decode(tok["claims_b64"])
    sig = base64.b64decode(tok["signature"])
    pub = base64.b64decode(data["server_public_key_b64"])

    # verify chữ ký Ed25519 trên đúng claims bytes (mô phỏng điều launcher C làm)
    nacl.signing.VerifyKey(pub).verify(claims_bytes, sig)  # raise nếu sai

    import json
    claims = json.loads(claims_bytes)
    assert claims["product_id"] == "demo_app"
    assert claims["device_hash"] == "HW-ABC-123"
    assert "offline_until" in claims


def test_not_owned_blocked(client, admin_token):
    h = auth_header(admin_token)
    client.post("/admin/products", json={"product_id": "demo_app", "name": "Demo App"}, headers=h)
    client.post("/admin/products/demo_app/key",
                json={"payload_key_b64": base64.b64encode(b"0" * 32).decode()}, headers=h)
    r = client.post("/admin/users", json={"email": "nope@test.com", "password": "password123"}, headers=h)
    # KHÔNG grant
    r = client.post("/auth/login", json={"email": "nope@test.com", "password": "password123"})
    token = r.json()["tokens"]["access_token"]

    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-X"},
                    headers=auth_header(token))
    assert r.status_code == 403


def test_device_limit(client, admin_token):
    token, uid, _ = _setup_owned(client, admin_token)
    h = auth_header(token)
    # device_limit mặc định = 3 -> 3 thiết bị OK, thiết bị thứ 4 bị chặn
    for i in range(3):
        r = client.post("/runtime/issue-token",
                        json={"product_id": "demo_app", "hardware_hash": f"HW-{i}"}, headers=h)
        assert r.status_code == 200, f"device {i}: {r.text}"
    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-4"}, headers=h)
    assert r.status_code == 403


def test_device_revoke_blocks(client, admin_token):
    token, uid, _ = _setup_owned(client, admin_token)
    # đăng ký 1 device
    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-REVOKE"},
                    headers=auth_header(token))
    assert r.status_code == 200

    # admin tìm device id rồi revoke
    ah = auth_header(admin_token)
    devices = client.get("/admin/devices", headers=ah).json()
    did = next(d["id"] for d in devices if d["hardware_hash"] == "HW-REVOKE")
    r = client.post(f"/admin/devices/{did}/revoke", headers=ah)
    assert r.status_code == 200

    # lần chạy sau từ device đó bị chặn
    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-REVOKE"},
                    headers=auth_header(token))
    assert r.status_code == 403


def test_revoke_entitlement_blocks_runtime(client, admin_token):
    token, uid, _ = _setup_owned(client, admin_token)
    ah = auth_header(admin_token)
    client.post("/admin/entitlements/revoke", json={"user_id": uid, "product_id": "demo_app"}, headers=ah)
    r = client.post("/runtime/issue-token",
                    json={"product_id": "demo_app", "hardware_hash": "HW-1"},
                    headers=auth_header(token))
    assert r.status_code == 403

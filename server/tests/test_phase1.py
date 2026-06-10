"""Test giai đoạn 1: auth, library, admin entitlement flow."""
from tests.conftest import auth_header


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_register_and_login(client):
    r = client.post("/auth/register", json={"email": "u1@test.com", "password": "password123"})
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["user"]["email"] == "u1@test.com"
    assert data["user"]["role"] == "user"
    assert data["tokens"]["access_token"]

    # đăng nhập lại
    r = client.post("/auth/login", json={"email": "u1@test.com", "password": "password123"})
    assert r.status_code == 200

    # sai mật khẩu
    r = client.post("/auth/login", json={"email": "u1@test.com", "password": "wrongwrong"})
    assert r.status_code == 401


def test_register_duplicate(client):
    client.post("/auth/register", json={"email": "dup@test.com", "password": "password123"})
    r = client.post("/auth/register", json={"email": "dup@test.com", "password": "password123"})
    assert r.status_code == 409


def test_refresh(client):
    r = client.post("/auth/register", json={"email": "r@test.com", "password": "password123"})
    refresh = r.json()["tokens"]["refresh_token"]
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_admin_required(client):
    # user thường không được vào admin
    r = client.post("/auth/register", json={"email": "norm@test.com", "password": "password123"})
    token = r.json()["tokens"]["access_token"]
    r = client.get("/admin/products", headers=auth_header(token))
    assert r.status_code == 403


def test_full_entitlement_flow(client, admin_token):
    h = auth_header(admin_token)

    # tạo product
    r = client.post("/admin/products", json={"product_id": "demo_app", "name": "Demo App", "version": "1.0.0"}, headers=h)
    assert r.status_code == 201, r.text

    # tạo user
    r = client.post("/admin/users", json={"email": "buyer@test.com", "password": "password123"}, headers=h)
    assert r.status_code == 201
    uid = r.json()["id"]

    # user login, library rỗng
    r = client.post("/auth/login", json={"email": "buyer@test.com", "password": "password123"})
    user_token = r.json()["tokens"]["access_token"]
    r = client.get("/me/library", headers=auth_header(user_token))
    assert r.json() == []

    # admin cấp quyền
    r = client.post("/admin/entitlements/grant", json={"user_id": uid, "product_id": "demo_app"}, headers=h)
    assert r.status_code == 200

    # library có app
    r = client.get("/me/library", headers=auth_header(user_token))
    lib = r.json()
    assert len(lib) == 1 and lib[0]["product_id"] == "demo_app"

    # revoke
    r = client.post("/admin/entitlements/revoke", json={"user_id": uid, "product_id": "demo_app"}, headers=h)
    assert r.status_code == 200

    # library rỗng lại
    r = client.get("/me/library", headers=auth_header(user_token))
    assert r.json() == []

    # audit log có ghi sự kiện grant
    r = client.get("/admin/audit-logs", headers=h)
    events = {e["event_type"] for e in r.json()}
    assert "grant" in events and "revoke" in events

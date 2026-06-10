"""Test giai đoạn 6: Admin Dashboard (cookie auth + render + thao tác)."""
from app.config import settings


def test_login_page(client):
    r = client.get("/dashboard/login")
    assert r.status_code == 200
    assert "Đăng nhập" in r.text


def test_protected_redirects_when_anonymous(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard/login"


def test_admin_login_and_overview(client):
    r = client.post("/dashboard/login",
                    data={"email": settings.admin_email, "password": settings.admin_password},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "dash_token" in r.cookies  # cookie được set

    # client giữ cookie -> vào được overview
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "Tổng quan" in r.text


def test_non_admin_cannot_login(client):
    # tạo user thường qua API rồi thử login dashboard
    client.post("/auth/register", json={"email": "u@test.com", "password": "password123"})
    r = client.post("/dashboard/login",
                    data={"email": "u@test.com", "password": "password123"},
                    follow_redirects=False)
    assert r.status_code == 401


def test_dashboard_create_product_and_grant(client):
    client.post("/dashboard/login",
                data={"email": settings.admin_email, "password": settings.admin_password})
    # tạo product qua form dashboard
    r = client.post("/dashboard/products",
                    data={"product_id": "demo_app", "name": "Demo App", "version": "1.0.0"},
                    follow_redirects=False)
    assert r.status_code == 303
    # product xuất hiện ở trang products
    r = client.get("/dashboard/products")
    assert "demo_app" in r.text

    # tạo user + cấp quyền qua dashboard, kiểm tra audit có ghi
    client.post("/dashboard/users", data={"email": "buy@test.com", "password": "password123", "role": "user"})
    # lấy user id qua API admin (đang đăng nhập cookie nhưng API cần Bearer; dùng login API)
    admin_api = client.post("/auth/login",
                            json={"email": settings.admin_email, "password": settings.admin_password}).json()
    h = {"Authorization": f"Bearer {admin_api['tokens']['access_token']}"}
    users = client.get("/admin/users", headers=h).json()
    uid = next(u["id"] for u in users if u["email"] == "buy@test.com")

    r = client.post(f"/dashboard/users/{uid}/grant", data={"product_id": "demo_app"}, follow_redirects=False)
    assert r.status_code == 303
    # xác nhận quyền active qua API
    lib = client.get("/admin/audit-logs", headers=h).json()
    assert any(e["event_type"] == "grant" for e in lib)

"""HTTP client gọi License Server."""
import requests

import config


class ApiError(Exception):
    """Lỗi nghiệp vụ (sai mật khẩu, hết quyền...) — có message hiển thị được."""


class NetworkError(Exception):
    """Không kết nối được server (dùng để kích hoạt offline mode)."""


def _detail(resp: requests.Response, fallback: str) -> str:
    try:
        d = resp.json().get("detail")
        if isinstance(d, list) and d:
            return d[0].get("msg", fallback)
        return d or fallback
    except Exception:
        return fallback


def login(email: str, password: str) -> dict:
    """Trả {user, tokens}. Raise ApiError nếu sai thông tin, NetworkError nếu mất mạng."""
    try:
        r = requests.post(
            f"{config.SERVER_URL}/auth/login",
            json={"email": email, "password": password},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as e:
        raise NetworkError(str(e))
    if r.status_code != 200:
        raise ApiError(_detail(r, "Đăng nhập thất bại"))
    return r.json()


def get_library(access_token: str) -> list[dict]:
    """Danh sách app đã sở hữu. Raise NetworkError nếu mất mạng, ApiError nếu token hỏng."""
    try:
        r = requests.get(
            f"{config.SERVER_URL}/me/library",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as e:
        raise NetworkError(str(e))
    if r.status_code == 401:
        raise ApiError("Phiên đăng nhập hết hạn, vui lòng đăng nhập lại")
    if r.status_code != 200:
        raise ApiError(_detail(r, "Không tải được thư viện"))
    return r.json()


def issue_token(access_token: str, product_id: str, hardware_hash: str,
                device_name: str = "") -> dict:
    """Xin entitlement token đã ký + payload key từ server (sau khi server check quyền).

    Trả {token, payload_key_b64, server_public_key_b64, offline_until}.
    Raise NetworkError nếu mất mạng (để client chuyển sang dùng cache offline),
    ApiError nếu server từ chối (không sở hữu / vượt thiết bị / bị thu hồi).
    """
    try:
        r = requests.post(
            f"{config.SERVER_URL}/runtime/issue-token",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"product_id": product_id, "hardware_hash": hardware_hash, "device_name": device_name},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as e:
        raise NetworkError(str(e))
    if r.status_code != 200:
        raise ApiError(_detail(r, "Server từ chối cấp quyền chạy"))
    return r.json()

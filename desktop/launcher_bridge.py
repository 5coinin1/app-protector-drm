"""Cầu nối tới Protected Launcher: cài (tải) app, lấy hwid, xin entitlement token, chạy launcher.

Mức 3 (auto): app được TẢI từ server vào apps/<product_id>/ qua install(). Một launcher.exe
DÙNG CHUNG (desktop/launcher.exe) chạy mọi app qua --package, không nhân bản mỗi thư mục.
"""
import json
import os
import platform
import subprocess

import api
import config
import session

# Launcher dùng chung cho mọi app (trỏ --package tới từng thư mục).
SHARED_LAUNCHER = os.path.join(config.BASE_DIR, "launcher.exe")

# Các file phát hành của một package (tải từ server). Không gồm payload key.
PACKAGE_FILES = ("payload.enc", "manifest.signed.json", "public_key.pem")


def package_dir(product_id: str) -> str:
    return os.path.join(config.APPS_DIR, product_id)


def is_installed(product_id: str) -> bool:
    """Đã cài = có đủ file app trong apps/<id>/ (launcher.exe là dùng chung, tách riêng)."""
    d = package_dir(product_id)
    return all(os.path.isfile(os.path.join(d, f)) for f in PACKAGE_FILES)


def install(product_id: str, access_token: str) -> None:
    """Tải package từ server về apps/<id>/. Raise NetworkError/ApiError nếu lỗi.

    Tải vào file .part rồi đổi tên để tránh 'cài dở' khi mất mạng giữa chừng.
    """
    info = api.get_package_info(access_token, product_id)  # cũng kiểm tra quyền sở hữu
    names = {f["name"] for f in info.get("files", [])}
    missing = [f for f in PACKAGE_FILES if f not in names]
    if missing:
        raise api.ApiError(f"Server thiếu file: {', '.join(missing)}")

    d = package_dir(product_id)
    os.makedirs(d, exist_ok=True)
    for name in PACKAGE_FILES:
        tmp = os.path.join(d, name + ".part")
        api.download_package_file(access_token, product_id, name, tmp)
        os.replace(tmp, os.path.join(d, name))


def get_hwid() -> str:
    """Hỏi launcher hardware id của máy (để gửi server đăng ký thiết bị)."""
    proc = subprocess.run([SHARED_LAUNCHER, "--print-hwid"],
                          capture_output=True, text=True, timeout=15)
    return proc.stdout.strip()


def play(product_id: str, access_token: str) -> tuple[int, str]:
    """Chạy launcher cho product. Trả (exit_code, output)."""
    pkg = package_dir(product_id)
    if not os.path.isfile(SHARED_LAUNCHER):
        return (-1, f"Không thấy launcher dùng chung ({SHARED_LAUNCHER})")
    if not is_installed(product_id):
        return (-1, f"Chưa cài app '{product_id}' — bấm Cài đặt trước")

    hwid = get_hwid()
    device_name = platform.node() or "PC"

    # Lấy entitlement: ưu tiên online (server check quyền), mất mạng -> dùng cache.
    note = ""
    try:
        bundle = api.issue_token(access_token, product_id, hwid, device_name)
        session.cache_entitlement(product_id, bundle)
    except api.NetworkError:
        bundle = session.get_cached_entitlement(product_id)
        if not bundle:
            return (-1, "Không kết nối được server và chưa có entitlement đã lưu.\n"
                        "Cần online ít nhất một lần để chạy offline.")
        note = "⚠ OFFLINE: dùng entitlement đã lưu (chạy được tới hạn offline_until).\n\n"
    except api.ApiError as e:
        return (-1, f"Server từ chối cấp quyền chạy:\n{e}")

    # Ghi entitlement token ra file tạm trong package để truyền cho launcher.
    token_path = os.path.join(pkg, ".entitlement.json")
    with open(token_path, "w", encoding="utf-8") as f:
        json.dump(bundle["token"], f)

    cmd = [
        SHARED_LAUNCHER,
        "--package", pkg,
        "--entitlement", token_path,
        "--server-pubkey", bundle["server_public_key_b64"],
        "--key-b64", bundle["payload_key_b64"],
    ]
    try:
        proc = subprocess.run(cmd, cwd=pkg, capture_output=True, text=True, timeout=120)
        return (proc.returncode, note + (proc.stdout or "") + (proc.stderr or ""))
    except subprocess.TimeoutExpired:
        return (-1, "App chạy quá lâu (timeout)")
    except OSError as e:
        return (-1, f"Không chạy được launcher: {e}")
    finally:
        if os.path.exists(token_path):
            os.remove(token_path)

"""Cầu nối tới Protected Launcher: lấy hwid, xin entitlement token, chạy launcher (GĐ5)."""
import json
import os
import platform
import subprocess

import api
import config
import session


def package_dir(product_id: str) -> str:
    return os.path.join(config.APPS_DIR, product_id)


def _exe(product_id: str) -> str:
    return os.path.join(package_dir(product_id), "launcher.exe")


def is_installed(product_id: str) -> bool:
    return os.path.isfile(_exe(product_id))


def get_hwid(product_id: str) -> str:
    """Hỏi launcher hardware id của máy (để gửi server đăng ký thiết bị)."""
    proc = subprocess.run([_exe(product_id), "--print-hwid"],
                          capture_output=True, text=True, timeout=15)
    return proc.stdout.strip()


def play(product_id: str, access_token: str) -> tuple[int, str]:
    """Chạy launcher cho product. Trả (exit_code, output)."""
    pkg = package_dir(product_id)
    exe = _exe(product_id)
    if not os.path.isfile(exe):
        return (-1, f"Chưa cài app '{product_id}' (không thấy {exe})")

    hwid = get_hwid(product_id)
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
        exe,
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

"""Publish một protected package lên License Server (tự động hóa bước 'đăng' của developer).

Một lệnh làm trọn: đăng nhập admin → tạo product → đăng ký payload key → upload package.
Sau khi publish, user có entitlement có thể bấm 'Cài đặt' trên desktop client để tải về.

Ví dụ:
    python tools/publish.py \
        --dist protector/dist/DemoAppProtected \
        --product-id demo_app --name "Demo App" --version 1.0.0

Mặc định server http://127.0.0.1:8000, admin admin@example.com / admin12345
(đổi bằng cờ hoặc biến môi trường DRM_SERVER / DRM_ADMIN_EMAIL / DRM_ADMIN_PASSWORD).
"""
import argparse
import os
import sys
from pathlib import Path

import requests

ALLOWED = ("payload.enc", "manifest.signed.json", "public_key.pem")


def main() -> int:
    # Console Windows mặc định cp1252 không in được tiếng Việt -> ép UTF-8.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Publish protected package lên License Server")
    ap.add_argument("--dist", required=True, help="thư mục output của protector (chứa payload.enc, ...)")
    ap.add_argument("--product-id", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--server", default=os.environ.get("DRM_SERVER", "https://127.0.0.1:8000"))
    ap.add_argument("--admin-email", default=os.environ.get("DRM_ADMIN_EMAIL", "admin@example.com"))
    ap.add_argument("--admin-password", default=os.environ.get("DRM_ADMIN_PASSWORD", "admin12345"))
    # Cert pinning: chỉ tin cert tự ký của server (certs/server.crt). Để trống nếu server dùng CA thật.
    default_cert = Path(__file__).resolve().parent.parent / "certs" / "server.crt"
    ap.add_argument("--cert", default=os.environ.get("DRM_SERVER_CERT", str(default_cert)),
                    help="đường dẫn cert server để pin (verify TLS)")
    args = ap.parse_args()

    dist = Path(args.dist)
    for f in (*ALLOWED, "SECRET_payload_key.b64"):
        if not (dist / f).is_file():
            print(f"LỖI: thiếu {f} trong {dist} (đã chạy `protector pack` chưa?)")
            return 1
    payload_key = (dist / "SECRET_payload_key.b64").read_text(encoding="utf-8").strip()

    s = requests.Session()
    # Pin cert server nếu file tồn tại (HTTPS); ngược lại để mặc định (CA hệ thống / HTTP).
    if args.cert and os.path.isfile(args.cert):
        s.verify = args.cert

    # 1. login admin
    r = s.post(f"{args.server}/auth/login",
               json={"email": args.admin_email, "password": args.admin_password}, timeout=15)
    if r.status_code != 200:
        print(f"LỖI đăng nhập admin: {r.status_code} {r.text}")
        return 1
    token = r.json()["tokens"]["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    print(f"[OK] đăng nhập admin {args.admin_email}")

    # 2. tạo product (bỏ qua nếu đã tồn tại)
    r = s.post(f"{args.server}/admin/products", headers=h,
               json={"product_id": args.product_id, "name": args.name, "version": args.version}, timeout=15)
    if r.status_code == 201:
        print(f"[OK] tạo product {args.product_id}")
    elif r.status_code == 409:
        print(f"[-] product {args.product_id} đã tồn tại — dùng lại")
    else:
        print(f"LỖI tạo product: {r.status_code} {r.text}")
        return 1

    # 3. đăng ký payload key
    r = s.post(f"{args.server}/admin/products/{args.product_id}/key", headers=h,
               json={"payload_key_b64": payload_key}, timeout=15)
    if r.status_code != 200:
        print(f"LỖI đăng ký key: {r.status_code} {r.text}")
        return 1
    print("[OK] đăng ký payload key")

    # 4. upload package
    files = {
        "payload": (ALLOWED[0], (dist / ALLOWED[0]).read_bytes(), "application/octet-stream"),
        "manifest": (ALLOWED[1], (dist / ALLOWED[1]).read_bytes(), "application/json"),
        "public_key": (ALLOWED[2], (dist / ALLOWED[2]).read_bytes(), "application/x-pem-file"),
    }
    r = s.post(f"{args.server}/admin/products/{args.product_id}/package", headers=h, files=files, timeout=60)
    if r.status_code != 200:
        print(f"LỖI upload package: {r.status_code} {r.text}")
        return 1
    print("[OK] upload package (payload.enc, manifest.signed.json, public_key.pem)")

    print(f"\n[DONE] Đã publish '{args.product_id}'. User có entitlement giờ có thể Cài đặt từ desktop client.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

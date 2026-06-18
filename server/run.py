"""Chạy License Server qua HTTPS (GĐ7 — bảo mật đường truyền).

Vì sao: client xin `payload key` (giải mã app) qua endpoint /runtime/issue-token. Nếu chạy HTTP trần,
key đó đi qua mạng dạng rõ → mọi công sức mã hóa AES-256 vô nghĩa. Bật TLS để mã hóa đường truyền,
client còn **pin** đúng cert này để chống MITM.

Dùng:
    cd server
    python ../tools/gen_cert.py     # sinh certs/server.crt + server.key (chạy 1 lần)
    python run.py                   # https://127.0.0.1:8000

Nếu chưa có cert → tự fallback HTTP kèm cảnh báo (chỉ để dev tạm, KHÔNG dùng cho demo bảo mật).
Đổi host/port qua biến môi trường DRM_HOST / DRM_PORT.
"""
import os
import sys

import uvicorn

from app.config import settings


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    host = os.environ.get("DRM_HOST", "127.0.0.1")
    port = int(os.environ.get("DRM_PORT", "8000"))
    cert, key = settings.tls_certfile, settings.tls_keyfile

    if os.path.isfile(cert) and os.path.isfile(key):
        print(f"[TLS] HTTPS bật → https://{host}:{port}")
        print(f"      cert: {cert}")
        uvicorn.run("app.main:app", host=host, port=port,
                    ssl_certfile=cert, ssl_keyfile=key)
    else:
        print("[!] CHƯA có cert TLS — đang chạy HTTP (KHÔNG mã hóa đường truyền).")
        print("    Bật HTTPS: python ../tools/gen_cert.py  rồi chạy lại `python run.py`.")
        uvicorn.run("app.main:app", host=host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())

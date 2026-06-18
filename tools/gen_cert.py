"""Sinh self-signed TLS cert cho License Server (GĐ7 — bật HTTPS).

Tạo:
  certs/server.crt  — cert PUBLIC: server dùng để chạy TLS, client dùng để **pin** (an toàn để commit).
  certs/server.key  — khóa PRIVATE: chỉ server giữ (đã nằm trong .gitignore qua quy tắc *.key).

Cert có SAN = IP:127.0.0.1, DNS:localhost để khớp địa chỉ chạy demo (client verify hostname).

Chạy:  python tools/gen_cert.py            (tạo nếu chưa có)
        python tools/gen_cert.py --force    (tạo lại, ghi đè)

Cần openssl: tự tìm trong PATH, nếu không có thì thử MSYS2 (C:\\msys64\\mingw64\\bin\\openssl.exe).
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CERTS = REPO / "certs"


def find_openssl() -> str:
    exe = shutil.which("openssl")
    if exe:
        return exe
    for cand in (
        r"C:\msys64\mingw64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL\bin\openssl.exe",
    ):
        if os.path.isfile(cand):
            return cand
    print("LỖI: không tìm thấy openssl. Cài MSYS2 (mingw64) hoặc thêm openssl vào PATH.")
    sys.exit(1)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    CERTS.mkdir(parents=True, exist_ok=True)
    crt = CERTS / "server.crt"
    key = CERTS / "server.key"

    if crt.exists() and key.exists() and "--force" not in sys.argv:
        print(f"[-] {crt} đã tồn tại — bỏ qua (dùng --force để tạo lại).")
        return 0

    openssl = find_openssl()
    cmd = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256",
        "-days", "825", "-nodes",
        "-keyout", str(key), "-out", str(crt),
        "-subj", "/CN=DRM License Server",
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
    ]
    print("Sinh cert tự ký (RSA-2048, SAN=127.0.0.1/localhost, hạn 825 ngày)...")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("LỖI: openssl thất bại.")
        return 1

    print(f"[OK] {crt}   (public — client pin cert này)")
    print(f"[OK] {key}   (private — KHÔNG commit, đã gitignore)")
    print("\nBật HTTPS: cd server ; python run.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

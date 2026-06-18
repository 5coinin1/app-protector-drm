# CLAUDE.md — Hướng dẫn dự án cho Claude Code

> File này được Claude tự động đọc mỗi phiên làm việc. Nó định nghĩa **dự án này là gì**,
> **dùng công nghệ gì**, **quy ước code**, và **cách build/chạy/test**. Cập nhật khi có thay đổi lớn.

## 1. Tổng quan dự án

**Tên đề tài:** Hệ thống App Protector & Mini Client phân phối ứng dụng theo mô hình Account-based DRM (kiểu Steam-like).

**Ý tưởng:** Developer đóng gói app gốc thành bản được bảo vệ (mã hóa + ký số). Người dùng đăng nhập tài khoản,
xem thư viện app đã sở hữu, bấm Play để chạy app qua một launcher kiểm tra quyền sở hữu ở phía server.
Người không sở hữu app thì không chạy được.

**6 thành phần (deliverables):**
1. **Protector CLI** — công cụ developer: nén + mã hóa app, tạo + ký manifest, xuất protected package.
2. **License/Entitlement Server** — backend trung tâm: user, product, entitlement, device, token, audit log.
3. **Protected Launcher** (`launcher.exe`) — chạy thay app gốc: verify manifest/token/hardware → decrypt → run → cleanup.
4. **Mini Desktop Client** — giống Steam: login, hiện library, bấm Play gọi launcher.
5. **Admin Dashboard** — quản trị: tạo product/user, grant/revoke entitlement, xem device & audit log.
6. **Sample App** — app mẫu để demo (chạy được trước khi protect, sau khi protect chỉ chạy qua launcher).

Nguồn yêu cầu gốc: `BMUDHT.docx` (giữ nguyên, không xóa). Đề bài **không** yêu cầu chống crack tuyệt đối —
KHÔNG làm PE loader thủ công, process hollowing, kernel driver, anti-debug phức tạp, VMProtect-style.

## 2. Tech stack (đã chốt)

| Thành phần | Ngôn ngữ / Công nghệ | Ghi chú |
|---|---|---|
| Protector CLI | **C** + libsodium + **OpenSSL** + miniz + cJSON | file thực thi `protector` (đã xong GĐ2) |
| Protected Launcher | **C** + libsodium + **OpenSSL** + libcurl + miniz + cJSON | file thực thi `launcher.exe` (GĐ3 xong; libcurl thêm ở GĐ5) |
| License Server | **Python** FastAPI + Uvicorn + SQLAlchemy + SQLite | host server cho dễ |
| Admin Dashboard | **Python** FastAPI + Jinja2 + Pico.css (CDN) | server-rendered, đẹp sẵn |
| Mini Desktop Client | **Python** + CustomTkinter | GUI hiện đại, ít code |
| Sample App | C hoặc Python nhỏ gọn | ví dụ Calculator / Note app |

**Crypto — quy tắc tương thích quan trọng:**
- **Ed25519** dùng **libsodium ở C** và **PyNaCl ở Python** → chữ ký **tương thích byte** giữa server (ký
  entitlement token) và launcher (verify). KHÔNG trộn thư viện khác cho phần ký.
- Thuật toán chuẩn của dự án:
  - Mã hóa payload: **AES-256-GCM** qua **OpenSSL EVP** (`EVP_aes_256_gcm`). *Lý do dùng OpenSSL thay vì
    libsodium: CPU máy dev không có AES-NI nên `crypto_aead_aes256gcm_is_available()` trả 0; OpenSSL có
    AES-GCM phần mềm chạy mọi CPU.* Layout `payload.enc` = ciphertext ‖ tag(16B); nonce(12B) lưu trong manifest.
    AES chỉ chạy trong C (protector mã hóa, launcher giải mã); server chỉ **lưu** payload key nên không cần AES.
  - Ký manifest & entitlement token: **Ed25519** (`crypto_sign_*` / PyNaCl `SigningKey`).
  - Hash toàn vẹn: **SHA-256** (`crypto_hash_sha256`).
  - Hash mật khẩu (server): **Argon2id** qua PyNaCl `pwhash`.

> Nếu một chỗ C quá phức tạp (vd. HTTP client, JSON), được phép đơn giản hóa nhưng **không đổi thuật toán crypto**
> (AES-256-GCM, Ed25519, SHA-256) và **không phá tương thích Ed25519 libsodium ↔ PyNaCl**. Nếu buộc phải đổi,
> ghi rõ lý do và cập nhật file này.

## 3. Môi trường máy (đã kiểm tra)

- OS: Windows 11, shell mặc định **PowerShell 7** (dùng cú pháp PowerShell, không phải bash).
- Python 3.11.9, pip 24.
- **GCC 14.2.0 từ MSYS2** (đường build C chính). MSVC `cl` KHÔNG có. Clang KHÔNG có.
- CMake 4.3.2, Git 2.45.

→ Build C bằng **MSYS2/MinGW (gcc)**. Cài thư viện C qua pacman trong MSYS2:
```
pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-curl mingw-w64-x86_64-cjson
```
(miniz có thể vendor sẵn dạng single-file trong repo nếu pacman không có.)

## 4. Cấu trúc thư mục dự định

```
license_app/
├── CLAUDE.md                 # file này
├── BMUDHT.docx               # yêu cầu gốc — KHÔNG sửa/xóa
├── README.md                 # hướng dẫn chạy tổng thể
├── .claude/settings.local.json
├── shared/                   # định dạng dùng chung (manifest schema, ví dụ)
├── server/                   # FastAPI: license server + admin dashboard
│   ├── app/{main.py,models/,routes/,services/,templates/,static/}
│   ├── requirements.txt
│   └── data/                 # sqlite db (gitignore)
├── protector/                # C: protector CLI (CMakeLists.txt, src/, include/)
├── launcher/                 # C: launcher.exe (CMakeLists.txt, src/, include/)
├── desktop/                  # Python: CustomTkinter mini client
├── sample-app/               # app mẫu để protect
└── docs/{architecture.md,threat-model.md,demo-script.md}
```

## 5. Lệnh build / chạy / test

> Trên Windows, các lệnh C cần chạy trong **MSYS2 MinGW64 shell** để có gcc + thư viện. Server/client Python chạy trong PowerShell bình thường.

**Server (Python):**
```powershell
cd server
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python ..\tools\gen_cert.py           # sinh cert TLS tự ký (1 lần) -> certs/server.crt + server.key
python run.py                         # HTTPS https://127.0.0.1:8000 ; admin: /dashboard
# (dev nhanh không cần TLS: uvicorn app.main:app --reload — nhưng client mặc định gọi HTTPS)
```

**Desktop client (Python):**
```powershell
cd desktop
pip install -r requirements.txt
python main.py
```

**Protector / Launcher (C, dùng CMake + MinGW):**
```bash
cd protector   # hoặc launcher
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

**Test:** server dùng `pytest` (`cd server ; pytest`). C dùng test nhỏ tự viết hoặc ctest nếu có thời gian.

## 6. Quy ước & nguyên tắc làm việc

- **Server-side verification là bất biến #1**: client/launcher KHÔNG tự quyết quyền sở hữu. Quyền do server xác nhận
  qua entitlement check + signed token. Mọi quyết định "được chạy hay không" phải truy về server (hoặc offline token đã ký còn hạn).
- **Không hardcode khóa bí mật** trong code/commit. Khóa private để ngoài repo (`.env`, file key) và đưa vào `.gitignore`.
- **Mỗi sự kiện quan trọng phải ghi audit log**: login ok/fail, run app ok/fail, grant/revoke, device register, token nghi vấn.
- Code khớp phong cách xung quanh; comment vừa phải, ưu tiên rõ ràng. Đặt tên rõ nghĩa.
- Khi sửa crypto/format manifest/token, cập nhật `shared/` và mục §2 ở trên để C và Python không lệch nhau.
- Tiếng Việt cho giải thích với người dùng; định danh code/commit message tiếng Anh.

## 7. Lộ trình (làm theo thứ tự — bám đề bài §14)

1. ✅ **GĐ1 Server**: user/product/entitlement + auth (register/login/refresh) + DB schema. *(xong, 6/6 test)*
2. ✅ **GĐ2 Protector**: pack app → `payload.enc` + `manifest.signed.json` + `public_key.pem`. *(xong)*
3. ✅ **GĐ3 Launcher**: đọc manifest → verify chữ ký + hash → decrypt → chạy app → cleanup. *(xong, offline; check server ở GĐ5)*
4. ✅ **GĐ4 Desktop client**: login, hiện library, bấm Play gọi launcher (truyền token), offline cơ bản. *(xong)*
5. ✅ **GĐ5 Bảo mật**: signed entitlement token (Ed25519), hardware binding, offline grace, device limit, revoke, server-side payload key. *(xong, 12/12 test + 5 demo bảo mật)*
6. ✅ **GĐ6 Admin Dashboard**: giao diện web (Jinja2 + Pico.css) — product/user, grant/revoke, device revoke, audit log. *(xong, 17/17 test)*
7. **GĐ7 (tùy chọn, đã làm nhiều)**: ✅ secure local storage (`.session.json` mã hóa **DPAPI**),
   ✅ **pin public key server** trong launcher, ✅ **bắt buộc entitlement token** (gate offline-local sau cờ `--dev`)
   → vá rủi ro copy `.session.json`/app sang máy khác; ✅ **rate-limit đăng nhập** (IP, chống brute-force);
   ✅ **JWT secret không hardcode** (qua `.env` hoặc tự sinh `data/jwt_secret.key`);
   ✅ **HTTPS/TLS + cert pinning** (server `run.py` chạy TLS; desktop client + `tools/publish.py` pin
   `certs/server.crt`) → payload key & JWT không còn truyền dạng rõ, chống MITM. *Còn lại (tùy chọn):*
   2FA/email-alert thiết bị mới, mã hóa payload key-at-rest trong DB, watermark, integrity/anti-tamper nâng cao.

Đến hết GĐ6 là bài đã rất ổn (có sản phẩm thật + nhiều kiến thức bảo mật).

## 8. DB schema tối thiểu (tham khảo đề bài §6)

`users, products, entitlements, devices, product_devices, audit_logs` (+ `product_keys` nếu cấp payload key từ server).
Xem chi tiết cột trong `BMUDHT.docx` mục 6 và `docs/architecture.md`.

## 9. Skill Claude Code hữu ích cho dự án này

- `/security-review` — review bảo mật diff hiện tại (rất hợp môn này; chạy sau mỗi giai đoạn crypto/auth).
- `/code-review` — soát bug & dọn code; `/code-review ultra` để review sâu nhiều agent trên cloud.
- `/verify`, `/run` — chạy thật app/launcher để xác nhận tính năng hoạt động (vd. người không sở hữu → bị chặn).
- `/simplify` — dọn code cho gọn sau khi tính năng đã chạy.
- `/init` — cập nhật lại CLAUDE.md khi cấu trúc thay đổi nhiều.

## 10. Định nghĩa "xong" cho một tính năng

Chạy được thật (không chỉ compile) + có test/đường demo thủ công minh họa + log đúng + cập nhật doc/CLAUDE.md nếu đổi kiến trúc.

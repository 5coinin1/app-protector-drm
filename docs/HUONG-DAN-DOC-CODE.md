# Hướng dẫn ĐỌC-HIỂU code dự án

> Tài liệu giúp bạn hiểu dự án từ **bức tranh lớn** → **luồng chạy chính** → **từng file làm gì**,
> kèm trỏ tới đúng file/hàm để mở ra xem. Đọc theo thứ tự từ trên xuống là dễ vào nhất.
> Mẹo: mở file này cạnh cửa sổ code, bấm vào link để nhảy tới file tương ứng.

---

## 1. Hệ thống này làm gì? (1 đoạn)

Đây là hệ **DRM kiểu Steam**: nhà phát triển (dev) đóng gói app gốc thành **bản mã hóa + ký số**;
người dùng đăng nhập tài khoản, thấy **thư viện app mình sở hữu**, bấm **Play** để chạy app qua một
**launcher** kiểm tra quyền ở **server**. Ai không sở hữu → không chạy được. Điểm cốt lõi:
**server mới là nơi quyết định quyền chạy**, không phải client.

---

## 2. Bốn "nhân vật" và ngôn ngữ

| Nhân vật | Là gì | Ngôn ngữ | Thư mục |
|---|---|---|---|
| **Protector** | Công cụ của *dev*: nén + mã hóa + ký app | C | [../protector/](../protector/) |
| **Server** | Bộ não: tài khoản, quyền sở hữu, cấp "vé" chạy + Dashboard web | Python (FastAPI) | [../server/](../server/) |
| **Launcher** | Chạy thay app: kiểm tra "vé" → giải mã → chạy → dọn | C | [../launcher/](../launcher/) |
| **Desktop client** | Giống Steam: login, thư viện, bấm Play | Python (CustomTkinter) | [../desktop/](../desktop/) |

Sơ đồ tổng thể:

```
   DEV                                          NGƯỜI DÙNG
    │ protector pack                                │ mở app
    ▼                                               ▼
[Protector] ──► payload.enc + manifest.signed   [Desktop client] ──login/Play──► [Server]
 (mã hóa,        + public_key + SECRET_key            │                           (Python)
  ký số)              │                                │ gọi                         ▲
                      │ upload                         ▼                             │ cấp "vé"
                      └──────────────────────────► [Launcher.exe] ──verify──────────┘ (entitlement
                                                    (giải mã, chạy app)                token đã ký)
```

---

## 3. Ba khái niệm phải nắm trước

Hiểu 3 thứ này thì đọc code mới "thông":

1. **payload.enc** = app gốc đã bị **nén (zip) rồi mã hóa**. Không có khóa thì không mở được.
2. **manifest.signed.json** = "tờ khai" của gói (tên app, file entry, mã băm payload, nonce…) + **chữ ký số**.
   Sửa 1 byte trong app hay tờ khai → chữ ký/mã băm sai → launcher phát hiện.
3. **entitlement token** = "tấm vé" server **ký** cấp cho đúng *user + app + máy*, có hạn dùng offline.
   Launcher chỉ chạy app khi tấm vé này hợp lệ.

---

## 4. LUỒNG XƯƠNG SỐNG: chuyện gì xảy ra khi bấm "Play"

Đây là phần **quan trọng nhất**. Hiểu luồng này là hiểu 80% dự án. Theo dõi dữ liệu đi qua từng chặng:

### Chặng A — Client chuẩn bị (Python)
1. Bạn bấm **Play** trên card app → [../desktop/main.py](../desktop/main.py) hàm `do_play()` (chạy nền cho khỏi đơ GUI).
2. Nó gọi [../desktop/launcher_bridge.py](../desktop/launcher_bridge.py) hàm `play()`:
   - Chạy `launcher.exe --print-hwid` để lấy **mã phần cứng (hwid)** của máy.
   - Gọi server xin "vé": `api.issue_token(...)` trong [../desktop/api.py](../desktop/api.py).

### Chặng B — Server xét quyền & cấp vé (Python) ← TRÁI TIM DRM
3. Request rơi vào [../server/app/routes/runtime.py](../server/app/routes/runtime.py) hàm `issue_token()`. Server làm 4 bước:
   - **(1) Sở hữu?** Có `Entitlement` active cho `user + product` không? Không → **403** (chặn).
   - **(2) Thiết bị?** Đăng ký máy theo `hardware_hash`, kiểm tra **giới hạn số thiết bị** + thiết bị có bị thu hồi không.
   - **(3) Lấy payload key** của product (server giữ key, không nhúng vào bản phát hành).
   - **(4) Ký vé**: gọi [../server/app/services/tokens.py](../server/app/services/tokens.py) `issue_entitlement_token()` — ký bằng **Ed25519**.
   - Trả về: `token` (vé đã ký) + `payload_key_b64` (khóa giải mã) + `server_public_key_b64`.
   - Mọi bước đều ghi **audit log** (`log_event`).
4. Trước khi vào được hàm trên, request phải qua [../server/app/deps.py](../server/app/deps.py) `get_current_user()` — xác thực **JWT** phiên đăng nhập.

### Chặng C — Client gọi launcher (Python)
5. `play()` lưu vé vào `.session.json` (cache để chạy offline) qua [../desktop/session.py](../desktop/session.py)
   (file này **mã hóa DPAPI**, xem §6).
6. Ghi vé ra file tạm rồi chạy:
   `launcher.exe --package <dir> --entitlement <vé> --server-pubkey <…> --key-b64 <khóa>`.

### Chặng D — Launcher kiểm tra & chạy (C)
7. Vào [../launcher/src/main.c](../launcher/src/main.c) `main()`, lần lượt:
   - **Verify chữ ký manifest** (app/tờ khai có bị sửa không) → sai thì thoát mã **2**.
   - **So mã băm payload** (`SHA-256`) → sai thì thoát mã **3**.
   - **Verify vé**: [../launcher/src/entitlement.c](../launcher/src/entitlement.c) `pk_entitlement_verify()` dùng **public key GHIM sẵn**
     ([../launcher/include/pk_server_key.h](../launcher/include/pk_server_key.h)), KHÔNG tin key client đưa. Token sai → thoát **7**.
   - **Hardware binding**: `device_hash` trong vé phải khớp hwid máy này (lấy ở [../launcher/src/fingerprint.c](../launcher/src/fingerprint.c)) → khác → **7**.
   - **Hạn offline**: `now <= offline_until`? quá hạn → **7**.
   - **Giải mã** `payload.enc` bằng **AES-256-GCM** (key vừa nhận) → ra file zip.
   - **Giải nén** ra thư mục tạm → **chạy app** (`entry`) qua [../launcher/src/runner.c](../launcher/src/runner.c) `pk_run_and_wait()`.
   - App thoát → **xóa thư mục tạm** (cleanup).
8. Client đọc **exit code** của launcher để báo "đã chạy / bị chặn" (popup trong `main.py`).

> **Mã thoát launcher** (rất tiện để hiểu/giải thích): 0 OK · 2 chữ ký sai · 3 hash sai · 4 giải mã thất bại ·
> 5 giải nén lỗi · 6 không chạy được app · 7 vé/hardware/hết hạn sai. Xem [../launcher/README.md](../launcher/README.md).

---

## 5. Còn các luồng khác (ngắn)

- **Đăng ký/đăng nhập:** [../server/app/routes/auth.py](../server/app/routes/auth.py) — tạo user, cấp **JWT** access/refresh,
  có **rate-limit** chống dò mật khẩu ([../server/app/services/ratelimit.py](../server/app/services/ratelimit.py)).
- **Thư viện:** [../server/app/routes/library.py](../server/app/routes/library.py) `/me/library` — join `entitlements × products`,
  nên **xóa product là app tự biến mất** khỏi thư viện.
- **Đóng gói từ web:** admin upload file ở Dashboard → [../server/app/services/packer.py](../server/app/services/packer.py) gọi
  `protector.exe` để mã hóa/ký → tự tạo product + lưu key + lưu package.
- **Admin Dashboard:** [../server/app/routes/dashboard.py](../server/app/routes/dashboard.py) (giao diện web, dùng cookie),
  còn [../server/app/routes/admin.py](../server/app/routes/admin.py) là API tương đương (dùng Bearer token).

---

## 6. Crypto giải thích bằng lời thường (đừng sợ)

| Thuật toán | Để làm gì | Ở đâu trong code |
|---|---|---|
| **AES-256-GCM** | Mã hóa nội dung app (payload). "Khóa đối xứng": cùng 1 khóa để khóa & mở. | `pk_aes_encrypt/decrypt` trong [../protector/src/crypto.c](../protector/src/crypto.c) (protector khóa, launcher mở) |
| **Ed25519** (chữ ký số) | Server "ký" manifest & entitlement token; ai cũng **verify** được bằng public key nhưng **không giả** được nếu thiếu private key. | Server: [../server/app/services/tokens.py](../server/app/services/tokens.py) (PyNaCl). Launcher verify: [../launcher/src/entitlement.c](../launcher/src/entitlement.c) (libsodium) |
| **SHA-256** | "Mã băm" để phát hiện file bị sửa (toàn vẹn). | so `payload_hash` trong [../launcher/src/main.c](../launcher/src/main.c) |
| **Argon2id** | Băm mật khẩu user (lưu DB không lưu mật khẩu thật). | [../server/app/security.py](../server/app/security.py) `hash_password` |
| **JWT (HS256)** | "Vé phiên đăng nhập" của user với server (khác entitlement token). | [../server/app/security.py](../server/app/security.py) |
| **DPAPI** (Windows) | Mã hóa `.session.json` ở máy client, trói vào tài khoản Windows → copy sang máy khác là vô dụng. | [../desktop/dpapi.py](../desktop/dpapi.py) |

> Điểm tương thích quan trọng: **Ed25519** dùng *libsodium ở C* và *PyNaCl ở Python* để chữ ký **khớp byte**
> giữa server (ký) và launcher (verify). Đó là lý do server ký bằng PyNaCl mà launcher C verify được.

---

## 7. Bản đồ file — mở cái nào để xem gì

### Server (Python) — [../server/app/](../server/app/)
| File | Vai trò |
|---|---|
| [main.py](../server/app/main.py) | Khởi động FastAPI, gắn router, seed admin |
| [config.py](../server/app/config.py) | Cấu hình (JWT secret, device limit, rate-limit, đường dẫn protector…) |
| [models.py](../server/app/models.py) | Bảng DB: users, products, entitlements, devices, product_keys, audit_logs |
| [security.py](../server/app/security.py) | Băm mật khẩu + tạo/giải JWT |
| [deps.py](../server/app/deps.py) | Lấy user từ token, guard admin |
| [routes/auth.py](../server/app/routes/auth.py) | register/login/refresh/logout |
| [routes/runtime.py](../server/app/routes/runtime.py) | **Cấp entitlement token** (lõi DRM) |
| [routes/library.py](../server/app/routes/library.py) | Thư viện app của user |
| [routes/admin.py](../server/app/routes/admin.py) · [routes/dashboard.py](../server/app/routes/dashboard.py) | Quản trị (API & web) |
| [routes/packages.py](../server/app/routes/packages.py) | Cho client tải package |
| [services/tokens.py](../server/app/services/tokens.py) | Ký entitlement token Ed25519 |
| [services/packer.py](../server/app/services/packer.py) | Đóng gói app từ web (gọi protector) |
| [services/audit.py](../server/app/services/audit.py) · [services/ratelimit.py](../server/app/services/ratelimit.py) · [services/storage.py](../server/app/services/storage.py) | Audit log · chống brute-force · lưu package |

### Protector (C) — [../protector/src/](../protector/src/)
| File | Vai trò |
|---|---|
| [main.c](../protector/src/main.c) | Lệnh `keygen` / `pack` / `verify` |
| [crypto.c](../protector/src/crypto.c) | AES-GCM, Ed25519, SHA-256, base64 |
| [archive.c](../protector/src/archive.c) | Nén/giải nén zip (đệ quy giữ thư mục con) |
| [manifest.c](../protector/src/manifest.c) | Ghi & verify manifest đã ký |
| [util.c](../protector/src/util.c) | Đọc/ghi file, tiện ích |

### Launcher (C) — [../launcher/src/](../launcher/src/)
| File | Vai trò |
|---|---|
| [main.c](../launcher/src/main.c) | Luồng chính: verify → giải mã → chạy → dọn |
| [entitlement.c](../launcher/src/entitlement.c) | Verify entitlement token (Ed25519) |
| [fingerprint.c](../launcher/src/fingerprint.c) | Tính hwid (hardware binding) |
| [runner.c](../launcher/src/runner.c) | Tạo thư mục tạm, chạy app, dọn dẹp |
| [include/pk_server_key.h](../launcher/include/pk_server_key.h) | **Public key server ghim sẵn** |
> Launcher *dùng chung* crypto/archive/manifest/util với protector (1 nguồn, không lặp code).

### Desktop client (Python) — [../desktop/](../desktop/)
| File | Vai trò |
|---|---|
| [main.py](../desktop/main.py) | GUI: login, thư viện, Play, tự refresh, gỡ cài đặt |
| [api.py](../desktop/api.py) | Gọi REST tới server |
| [launcher_bridge.py](../desktop/launcher_bridge.py) | Cài/Play/Gỡ — cầu nối tới launcher.exe |
| [session.py](../desktop/session.py) · [dpapi.py](../desktop/dpapi.py) | Lưu session (mã hóa DPAPI) |
| [config.py](../desktop/config.py) | URL server, thư mục apps |

---

## 8. Các "bất biến" thiết kế (hay bị hỏi)

1. **Server-side verification:** client/launcher KHÔNG tự quyết quyền. Quyền đến từ entitlement token **server ký**
   (xem `runtime.py` + `entitlement.c`).
2. **Không hardcode khóa bí mật:** private key dev để ngoài repo; payload key server giữ; JWT secret tự sinh ra file.
3. **Pin public key server** trong launcher → không tin key client đưa.
4. **Mọi sự kiện quan trọng ghi audit log** (login, run, grant/revoke, device, publish, delete…).
5. **Ed25519 phải khớp byte** giữa PyNaCl (Python) và libsodium (C).

---

## 9. Mẹo tự đọc + câu hỏi hội đồng hay hỏi

**Cách đọc hiệu quả:** đừng đọc tuần tự từng file. Hãy **bám 1 luồng** (vd "bấm Play" ở §4), mở lần lượt các
file theo từng chặng. Hiểu xong 1 luồng, các file khác tự sáng.

**Hỏi & đáp nhanh:**
- *"Người không sở hữu app sao bị chặn?"* → `runtime.py` bước (1): không có entitlement active → 403, app cũng không hiện ở `/me/library`.
- *"Sửa file app thì sao?"* → đổi byte trong `payload.enc` → SHA-256 lệch → launcher thoát mã 3; sửa manifest → chữ ký sai → mã 2.
- *"Copy sang máy khác chạy được không?"* → không: hardware binding (`device_hash` trong vé) + `.session.json` mã hóa DPAPI + launcher bắt buộc vé hợp lệ.
- *"Chạy offline thế nào?"* → vé có `offline_until`; mất mạng thì client dùng vé cache, launcher cho chạy tới khi quá hạn.
- *"Vì sao mã hóa AES nhưng ký Ed25519?"* → AES để giấu nội dung (đối xứng, nhanh); Ed25519 để chứng thực nguồn gốc/không giả (bất đối xứng).

---

## 10. Tự kiểm tra hiểu (bài tập nhỏ)

1. Mở [runtime.py](../server/app/routes/runtime.py), chỉ ra **4 bước** server làm trước khi cấp vé.
2. Trong [launcher/src/main.c](../launcher/src/main.c), tìm chỗ trả về **mã 7** và giải thích mỗi chỗ ứng với lỗi gì.
3. Giải thích vì sao **xóa product** ở Dashboard thì app biến mất khỏi thư viện user (gợi ý: `library.py` join bảng nào).
4. Mở [tokens.py](../server/app/services/tokens.py) và [entitlement.c](../launcher/src/entitlement.c): chỉ ra chỗ **ký** (Python) và chỗ **verify** (C) — vì sao khớp nhau.

Làm được 4 câu này là bạn đã hiểu phần lõi của đồ án.

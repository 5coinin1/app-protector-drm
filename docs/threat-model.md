# Threat Model — Mô hình mối đe dọa

Tài liệu cho báo cáo/thuyết trình (bám đề bài §11). Gồm: (1) mối đe dọa ↔ cách xử lý, (2) tổng hợp
phòng thủ đã triển khai, (3) **rủi ro còn lại / giới hạn — trình bày trung thực**, (4) ranh giới tin cậy.

> Tinh thần: đề bài **không** yêu cầu chống crack tuyệt đối. Trọng tâm là **DRM/entitlement đúng đắn**
> (server-side verification) + phòng thủ chiều sâu hợp lý. Phần "giới hạn" bên dưới được nêu thẳng — đó là
> điều một mô hình mối đe dọa nghiêm túc phải làm.

---

## 1. Mối đe dọa ↔ Cách xử lý

| Mối đe dọa | Cách xử lý | Đã làm |
|---|---|---|
| Chạy app khi **chưa sở hữu** | Server-side entitlement check; client/launcher không tự quyết | ✅ `runtime.py` `issue_token` |
| **Copy app sang máy khác** | Hardware binding (`device_hash` trong token) + bắt buộc entitlement token hợp lệ | ✅ `entitlement.c`, `main.c` |
| **Copy `.session.json`** (token + payload key) sang máy khác | Mã hóa **DPAPI** (trói vào tài khoản Windows máy đó) → file vô dụng ở máy khác | ✅ `desktop/dpapi.py`, `session.py` |
| Dùng **payload key lẻ** chạy ở máy khác (offline-local) | Launcher **bắt buộc `--entitlement`** ở production; offline-local chỉ mở sau cờ `--dev` | ✅ `main.c` (gate) |
| Sửa `manifest.signed.json` | Chữ ký **Ed25519** trên manifest → verify sai → chặn (exit 2) | ✅ |
| Sửa `payload.enc` | **SHA-256** `payload_hash` + tag xác thực **AES-256-GCM** → exit 3/4 | ✅ |
| **Giả entitlement token** (tự ký bằng key khác) | Launcher verify bằng **public key GHIM sẵn** (không tin key client truyền) → exit 7 | ✅ `pk_server_key.h` |
| Sửa token local (vd `offline_until` → 2099) | Token ký Ed25519; mọi sửa đổi → chữ ký sai → exit 7 | ✅ |
| Dùng **offline mãi mãi** | `offline_until` trong token có hạn (offline grace) | ✅ |
| **Share tài khoản** nhiều máy | Device limit + đăng ký thiết bị (`devices`) | ✅ `device_limit` |
| Quyền/thiết bị **đã thu hồi** | Revoke entitlement/device → lần `issue_token` sau bị từ chối | ✅ |
| Copy thư mục **temp lúc đang chạy** | Bung ra temp + cleanup sau khi thoát; key chỉ cấp khi có quyền | ⚠️ giảm thiểu (xem §3) |
| **Brute-force** đăng nhập | Argon2id (băm mật khẩu) + **rate-limit theo IP** | ✅ `ratelimit.py` |
| **JWT secret lộ/đoán** | Không hardcode: lấy từ `.env` hoặc tự sinh `data/jwt_secret.key` | ✅ `config.py` |
| Admin lạm quyền / khó truy vết | **Audit log** mọi hành động nhạy cảm | ✅ `audit.py` |
| Replay token | Ràng buộc `device_hash` + thời hạn + (JWT phiên) refresh rotation | ✅ |
| **Nghe lén đường truyền** (sniff mật khẩu / JWT / **payload key**) | **HTTPS/TLS** server + **pin cert** ở client (chỉ tin cert tự ký của server) | ✅ `server/run.py`, `desktop/config.py` |
| **MITM** giả server để lừa client | Client pin đúng `certs/server.crt` → cert lạ bị từ chối bắt tay TLS | ✅ |
| Reverse engineer **nội dung app** (DemoApp) | Nhiều tầng anti-RE *trong app* (xem §2.3) | ✅ giáo dục |

---

## 2. Tổng hợp phòng thủ đã triển khai

### 2.1 Crypto & DRM lõi
- **AES-256-GCM** (OpenSSL EVP) mã hóa payload — bảo mật nội dung + tag chống sửa.
- **Ed25519** (libsodium ↔ PyNaCl, khớp byte) ký & verify manifest + entitlement token.
- **SHA-256** kiểm tra toàn vẹn payload. **Argon2id** băm mật khẩu.
- **Server-side verification** (bất biến #1): quyền chạy do server cấp qua token đã ký.

### 2.2 Hardening (GĐ7)
- **HTTPS/TLS + cert pinning**: server chạy qua TLS (`server/run.py`); desktop client & `tools/publish.py`
  **chỉ tin** cert tự ký `certs/server.crt` (`verify=`) → bí mật quan trọng nhất là **payload key** không
  còn đi qua dây dạng rõ, đồng thời chống MITM giả server.
- **Pin public key server** trong launcher → chặn token giả + key client tự đưa.
- **DPAPI** mã hóa `.session.json` → chống copy bí mật sang máy khác.
- **Gate offline-local**: production bắt buộc entitlement token (hardware binding luôn áp).
- **Rate-limit đăng nhập** theo IP + **JWT secret không hardcode**.

### 2.3 Anti-RE trong DemoApp (tầng nội dung — độc lập với crypto DRM)
String obfuscation (XOR) · API hiding (resolve động) · 5 lớp anti-debug · **silent poison** (đầu độc khóa
thay vì báo lỗi) · control-flow flattening · **phát hiện tool RE đang chạy** · **self-checksum (.text)** ·
**quét software breakpoint (0xCC)**. Tất cả nối vào cơ chế *poison* (sai môi trường → FLAG ra rác).

---

## 3. Rủi ro còn lại / Giới hạn (trình bày trung thực)

Không hệ DRM client-side nào triệt tiêu được các điểm sau; nêu rõ để hội đồng thấy ta hiểu giới hạn:

1. **Giải mã phía client là điểm yếu cố hữu.** Khi chạy hợp lệ, payload được giải mã ra thư mục tạm →
   về lý thuyết có thể **dump/copy** app gốc trong lúc chạy. Giảm thiểu: cleanup sau thoát + chỉ lấy được
   key khi có entitlement hợp lệ; **không loại bỏ hoàn toàn**. (Đề bài chấp nhận điều này.)
2. **Tin tưởng binary launcher.** Launcher là exe thường; kẻ tấn công có thể *vá chính launcher* để bỏ qua
   verify. Hiện chưa có self-integrity cho launcher (chỉ DemoApp có) → để ngỏ có chủ đích (ngoài phạm vi).
3. **Lộ mật khẩu tài khoản.** Nếu user tự để lộ mật khẩu, người khác đăng nhập được; device limit chỉ giới
   hạn *số máy đồng thời*, không bảo vệ bản thân mật khẩu.
4. **DPAPI = phạm vi máy/người dùng.** Chống copy sang máy/người dùng khác, **không** chống malware chạy
   *cùng tài khoản trên cùng máy* (nó vẫn gọi được `unprotect`).
5. **Rate-limit trong bộ nhớ, theo IP.** Reset khi restart server; kẻ tấn công nhiều IP có thể né. Production
   nên chuyển Redis + khóa theo tài khoản.
6. **Anti-RE của DemoApp cố tình yếu/dạy học.** Mọi tầng đều defeat được; mục đích minh họa loud vs silent,
   không phải bảo vệ tuyệt đối. KDF trong DemoApp (FNV-1a/xorshift) **không** phải crypto thật của hệ DRM.
7. **Cùng máy + còn hạn:** token offline đã cache dùng lại được trên *đúng máy đó* tới `offline_until` —
   đây là hành vi mong muốn (offline grace), không phải lỗ hổng.
8. **Chưa có xác thực 2 yếu tố (2FA).** Steam có Steam Guard (email + authenticator) và cảnh báo khi đăng
   nhập từ thiết bị mới. Hệ này mới có password (Argon2id) + rate-limit; lộ mật khẩu là đủ để đăng nhập.
   `device_limit` chỉ giới hạn *số máy đồng thời*, không phải bước xác thực thiết bị mới. → Hướng nâng cấp:
   TOTP và/hoặc email-alert khi có thiết bị lạ.
9. **Payload key lưu dạng rõ trong DB server (`product_keys`).** Đây là điểm tập trung rủi ro: DB bị lộ =
   *toàn bộ* key của mọi app lộ một lần. Hiện chấp nhận trong phạm vi demo. → Production nên mã hóa
   key-at-rest bằng master key/KMS, không để plaintext trong SQLite.
10. **TLS dùng cert tự ký (self-signed).** Đủ để mã hóa đường truyền và pin ở client trong demo, nhưng
    *không* có chuỗi tin cậy CA công khai: trình duyệt vào Dashboard sẽ cảnh báo cert, và việc cập nhật/
    xoay cert phải làm thủ công. → Production dùng cert do CA cấp (Let's Encrypt) hoặc CA nội bộ.

---

## 4. Ranh giới tin cậy (trust boundaries)

- **Không tin client/launcher** cho quyết định quyền sở hữu — chỉ tin server (hoặc token server đã ký còn hạn cho offline).
- Khóa **private** (ký manifest ở dev, ký token ở server) không bao giờ rời máy chủ/dev, không đóng vào package.
- **Public key server được GHIM** trong launcher (không tin key client truyền). Public key verify manifest đi kèm package chỉ để tiện `protector verify`.
- **Payload key do server cấp** sau khi kiểm tra entitlement (server-side key), không nằm trong bản phát hành.
- Bí mật phía client (`.session.json`) mã hóa DPAPI; secret server (`jwt_secret`, seed Ed25519) để ngoài repo (gitignore).

---

## 5. Ngoài phạm vi (đề bài §"Không nên làm")
Không làm: manual PE loader, process hollowing, kernel driver, anti-debug cực đoan, virtualization kiểu
VMProtect, self-integrity cho launcher, chống crack tuyệt đối. Trọng tâm là **DRM/entitlement đúng đắn**.

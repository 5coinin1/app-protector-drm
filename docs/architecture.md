# Kiến trúc hệ thống

## Sơ đồ tổng thể

```
Developer ──> [Protector CLI (C)] ──> protected package (payload.enc, manifest.signed.json, public_key.pem)
                                              │
Admin ──> [Admin Dashboard (FastAPI/Jinja)] ─┤
                                              ▼
User ──> [Mini Client (CustomTkinter)] ──> [License Server (FastAPI + SQLite)]
                  │  bấm Play (truyền token)        ▲   verify entitlement / device / issue token
                  ▼                                 │
            [Launcher.exe (C)] ───────────────────-┘
                  │ verify manifest+hash, check server, decrypt payload
                  ▼
            App gốc chạy trong thư mục tạm ──> thoát ──> cleanup
```

## Định dạng dữ liệu

### Protected package (output của Protector)
```
DemoAppProtected/
├── launcher.exe            # copy launcher chuẩn
├── payload.enc             # app gốc (zip) đã mã hóa AES-256-GCM
├── manifest.signed.json    # manifest + chữ ký Ed25519
└── public_key.pem          # public key để verify manifest
```

### manifest (trước khi ký) — `shared/manifest.example.json`
```json
{
  "product_id": "demo_app",
  "version": "1.0.0",
  "entry": "DemoApp.exe",
  "payload_file": "payload.enc",
  "payload_hash": "<sha256 hex của payload.enc>",
  "cipher": "AES-256-GCM",
  "nonce": "<base64 12 byte>",
  "created_at": "2026-06-10T00:00:00Z"
}
```
File ký: `{ "manifest": {...}, "signature": "<base64 Ed25519>", "alg": "Ed25519" }`.

### Entitlement token (server cấp, Ed25519)
Payload token gồm: `user_id, product_id, device_hash, issued_at, offline_until, nonce`.
Launcher verify chữ ký bằng public key của server (nhúng sẵn / tải về) và kiểm tra `offline_until` cho offline mode.

## API (xem đề bài §7)

```
# Auth
POST /auth/register      POST /auth/login      POST /auth/refresh      POST /auth/logout
# User
GET  /me/library
# Runtime (cho launcher/client)
POST /runtime/check-entitlement   POST /runtime/register-device
POST /runtime/issue-token         POST /runtime/verify
# Admin
POST/GET /admin/products    POST/GET /admin/users
POST /admin/entitlements/grant    POST /admin/entitlements/revoke
GET  /admin/devices    POST /admin/devices/{id}/revoke    GET /admin/audit-logs
```

## Database (SQLAlchemy, SQLite) — tối thiểu

- `users(id, email, password_hash, role, status, created_at)`
- `products(id, product_id, name, version, status, created_at)`
- `entitlements(id, user_id, product_id, status, granted_at, expires_at)`
- `devices(id, user_id, hardware_hash, device_name, status, first_seen_at, last_seen_at)`
- `product_devices(id, user_id, product_id, device_id, status, activated_at, last_verified_at)`
- `audit_logs(id, user_id, product_id, event_type, result, ip_address, message, created_at)`
- (tùy chọn) `product_keys(id, product_id, key_version, encrypted_payload_key, status, created_at)`

## Luồng chạy app (Play)
1. Client gửi `device_hash` + product_id + access token → server.
2. Server check entitlement + device limit → cấp **signed entitlement token** (+ payload key nếu dùng server-side key).
3. Client gọi `launcher.exe` với token.
4. Launcher: verify chữ ký manifest → so `payload_hash` → verify token (chữ ký + offline_until + device_hash khớp máy) → decrypt `payload.enc` → giải nén ra temp → chạy `entry` → app thoát → xóa temp.

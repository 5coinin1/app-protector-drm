# Protector CLI (C)

Công cụ dành cho developer: đóng gói một thư mục app thành **protected package** (nén → mã hóa
AES-256-GCM → ký manifest Ed25519). Đây là Khối 1 "App Protector Wrapper" của hệ thống.

## Phụ thuộc
- **libsodium** (Ed25519, SHA-256, random, base64) — `pacman -S mingw-w64-x86_64-libsodium`
- **OpenSSL/libcrypto** (AES-256-GCM) — `pacman -S mingw-w64-x86_64-openssl`
- **miniz** (ZIP) và **cJSON** (JSON) — đã vendor sẵn trong `vendor/`
- Build: CMake + MinGW gcc (MSYS2). PATH cần có `C:\msys64\mingw64\bin`.

## Build
```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
cmake -B build -G "MinGW Makefiles"
cmake --build build
# -> build/protector.exe
```

## Lệnh

### keygen — sinh khóa ký manifest (Ed25519)
```bash
protector keygen --keys ./keys
```
Tạo `keys/manifest_ed25519.sk` (BÍ MẬT, không commit) và `.pk`. `pack` cũng tự sinh nếu chưa có.

### pack — đóng gói app
```bash
protector pack \
  --input ../sample-app/DemoApp \
  --entry DemoApp.exe \
  --product-id demo_app \
  --output ./dist/DemoAppProtected \
  [--version 1.0.0] [--keys ./keys]
```
Output trong thư mục `--output`:
| File | Mô tả | Phát hành cho user? |
|---|---|---|
| `payload.enc` | app gốc (zip) đã mã hóa AES-256-GCM (ciphertext‖tag) | ✅ |
| `manifest.signed.json` | manifest + chữ ký Ed25519 | ✅ |
| `public_key.pem` | public key verify manifest | ✅ |
| `SECRET_payload_key.b64` | **khóa giải mã payload** | ❌ đăng ký lên server, KHÔNG ship |

### verify — kiểm tra package (dùng public_key.pem trong package)
```bash
protector verify --package ./dist/DemoAppProtected
```
Kiểm tra: (1) chữ ký manifest hợp lệ, (2) SHA-256 của `payload.enc` khớp `payload_hash`.
Phát hiện giả mạo:
- Sửa `payload.enc` → báo **HASH SAI**.
- Sửa `manifest.signed.json` → báo **CHU KY SAI**.

## Định dạng manifest đã ký
```json
{
  "manifest": {
    "product_id": "...", "version": "...", "entry": "...",
    "payload_file": "payload.enc", "payload_hash": "<sha256 hex>",
    "cipher": "AES-256-GCM", "nonce": "<base64 12B>", "created_at": "<ISO8601>"
  },
  "signature": "<base64 Ed25519 64B>",
  "alg": "Ed25519"
}
```
Chuỗi được ký = `manifest` in unformatted (cJSON), thứ tự field cố định để verify tái tạo đúng byte.

## Lưu ý bảo mật / trust
- **Khóa private `.sk`** chỉ ở máy developer, không bao giờ đóng vào package.
- `public_key.pem` đi kèm package chỉ tiện cho `verify`. Trong thực tế **launcher nên pin public key**
  (nhúng sẵn) thay vì tin key trong package — sẽ làm ở Giai đoạn 3/5.
- Payload key do **server** cấp sau khi kiểm tra entitlement (Giai đoạn 5), không nằm trong bản phát hành.

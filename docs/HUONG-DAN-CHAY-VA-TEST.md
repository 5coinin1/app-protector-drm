# Hướng dẫn chạy & test toàn bộ chức năng

> Tài liệu thực hành: cách khởi động hệ thống và test từng chức năng (server, admin dashboard,
> protector, launcher, desktop client, và các kịch bản bảo mật). Bám theo [demo-script.md](demo-script.md).

Đường dẫn gốc dự án: `c:\Users\lenovo\Desktop\temp2\DoAnCoSo\license_app`

---

## 0. Chuẩn bị (đã có sẵn trong repo)

| Thành phần | Trạng thái | Vị trí |
|---|---|---|
| Server venv | đã tạo | `server\.venv` |
| Desktop venv | đã tạo | `desktop\.venv` |
| `protector.exe` | đã build | `protector\build\protector.exe` |
| `launcher.exe` | đã build | `launcher\build\launcher.exe` |
| Package demo đã đóng gói | đã có | `protector\dist\DemoAppProtected\` |
| App mẫu (chưa protect) | đã có | `sample-app\DemoApp\DemoApp.exe` |

> Chỉ cần **build lại C** (protector/launcher) nếu sửa code C — xem [§6](#6-build-lại-c-khi-cần). Còn lại
> dùng được ngay.

**Tài khoản admin mặc định** (server tự seed lần chạy đầu): `admin@example.com` / `admin12345`.

---

## 1. Khởi động hệ thống — 2 terminal

### Terminal 1 — Server (License Server + Admin Dashboard)

```powershell
cd c:\Users\lenovo\Desktop\temp2\DoAnCoSo\license_app\server
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

- Admin Dashboard (UI): **http://127.0.0.1:8000/dashboard** (mở `/` cũng tự chuyển vào đây)
- API docs (Swagger, thử API trực tiếp): **http://127.0.0.1:8000/docs**
- Health check: **http://127.0.0.1:8000/health** → `{"status":"ok"}`

> Gọi thẳng `.venv\Scripts\python.exe` để khỏi phụ thuộc bước activate. Nếu muốn dùng `uvicorn` trực tiếp
> thì activate trước: `.\.venv\Scripts\Activate.ps1`. Không thấy `(.venv)` ở prompt **không có nghĩa là chưa
> activate** — kiểm tra bằng `$env:VIRTUAL_ENV`.

### Terminal 2 — Desktop Client (mini Steam)

```powershell
cd c:\Users\lenovo\Desktop\temp2\DoAnCoSo\license_app\desktop
.\.venv\Scripts\python.exe main.py
```

> Client cần **server đang chạy trước**. URL server mặc định `http://127.0.0.1:8000` (đổi qua biến môi
> trường `DRM_SERVER` nếu cần).

---

## 2. Test nhanh "đường hạnh phúc" (5 phút)

Thứ tự tối thiểu để thấy toàn bộ luồng hoạt động:

1. Mở **Terminal 1** chạy server → vào http://127.0.0.1:8000/dashboard, đăng nhập `admin@example.com` / `admin12345`.
2. Trong dashboard: tạo **product** `demo_app`, đăng ký **payload key**, tạo **user** thường, **grant** quyền `demo_app` cho user đó.
3. "Cài" app demo cho client (copy package — xem [§5.2](#52-cài-app-cho-client)).
4. Mở **Terminal 2** chạy desktop client → đăng nhập bằng user thường → thấy app trong Library → bấm **Play** → app chạy.
5. Quay lại dashboard → **Audit logs** thấy chuỗi sự kiện login/run.

Chi tiết từng phần ở dưới.

---

## 3. Test Server & API (qua Swagger `/docs`)

Mở http://127.0.0.1:8000/docs. Test theo nhóm:

### 3.1 Auth
- `POST /auth/register` — tạo user mới (`email`, `password`).
- `POST /auth/login` — trả `access_token` + `refresh_token`. **Copy `access_token`.**
- Bấm nút **Authorize** (góc trên), dán `access_token` → mới gọi được các API cần đăng nhập.
- `POST /auth/refresh` — lấy access token mới từ refresh token.
- `POST /auth/logout`.

### 3.2 User
- `GET /me/library` — danh sách app user đang sở hữu (entitlement active).

### 3.3 Runtime (luồng launcher/client dùng)
- `POST /runtime/register-device` — đăng ký thiết bị bằng `hardware_hash`.
- `POST /runtime/check-entitlement` — hỏi server user có quyền product không.
- `POST /runtime/issue-token` — server check quyền + device limit + revoke → trả **entitlement token (Ed25519)** + **payload key** + server public key.
- `POST /runtime/verify` — verify token.

> Mỗi lần gọi runtime/auth thành công hay thất bại đều ghi **audit log** — kiểm tra ở dashboard để chứng minh "server-side verification".

---

## 4. Test Admin Dashboard (UI web)

Vào http://127.0.0.1:8000/dashboard, đăng nhập admin. Test lần lượt:

| Chức năng | Đường dẫn | Cách test |
|---|---|---|
| Đăng nhập / đăng xuất | `/dashboard/login`, `/dashboard/logout` | Login admin; logout rồi thử mở `/dashboard` → bị đẩy về login |
| **Đóng gói & xuất bản app (1 bước)** | form trên cùng trang Products | Chọn file app (`.exe`) hoặc `.zip` thư mục app → server **tự** mã hóa + ký + sinh key + tạo product + lưu package. Không cần chạy protector/publish thủ công. Với `.zip` phải nhập `entry` (tên exe bên trong) |
| Tạo Product (chỉ metadata) | `/dashboard/products` | Tạo `product_id=demo_app`, name, version → xuất hiện trong danh sách (chưa có file/key) |
| **Xóa Product** | nút 🗑 Xóa trên trang Products | Xóa hẳn product + entitlement + payload key + file package. Bảng hiện sẵn **số user sở hữu** và trạng thái **Package/Key** để biết tác động. Sau khi xóa: user mất quyền, app biến mất khỏi thư viện |
| Đăng ký Payload Key | nút trên trang Products | Dán nội dung file `protector\dist\DemoAppProtected\SECRET_payload_key.b64` → server lưu để cấp khi issue-token (chỉ cần khi đóng gói thủ công bằng CLI) |
| Tạo User | `/dashboard/users` | Tạo user thường (vd `user01@example.com`) |
| Grant entitlement | nút trên trang Users | Cấp `demo_app` cho user01 → entitlement active |
| Revoke entitlement | nút trên trang Users | Thu hồi → user01 mất quyền (Play sẽ bị chặn lần verify sau) |
| Devices | `/dashboard/devices` | Xem thiết bị đã đăng ký; **revoke** 1 device |
| Audit logs | `/dashboard/audit` | Xem toàn bộ sự kiện: login ok/fail, run ok/fail, grant/revoke, device |

---

## 5. Test Desktop Client

### 5.1 Đăng nhập & Library
1. Chạy client ([§1 Terminal 2](#terminal-2--desktop-client-mini-steam)).
2. Đăng nhập bằng user **đã được grant** `demo_app`.
3. Thấy app trong **My Library**. (User chưa sở hữu → app không hiện.)
4. Session được lưu (`desktop\.session.json`) → lần sau tự đăng nhập lại.
5. **Tự cập nhật**: client poll server mỗi 8s. Thử ở dashboard **grant/revoke/xóa** product →
   trong vài giây app tự xuất hiện/biến mất trong client (hoặc bấm **🔄 Làm mới** để cập nhật ngay).

### 5.2 Cài app cho client
Client tìm app tại `desktop\apps\<product_id>\` và yêu cầu có `launcher.exe`. Copy package demo vào:

```powershell
cd c:\Users\lenovo\Desktop\temp2\DoAnCoSo\license_app
New-Item -ItemType Directory -Force desktop\apps\demo_app | Out-Null
Copy-Item protector\dist\DemoAppProtected\* desktop\apps\demo_app\ -Force
Copy-Item launcher\build\launcher.exe         desktop\apps\demo_app\ -Force
```

- Đã sở hữu **+ đã cài** → nút **Play** + nút **🗑** (gỡ khỏi máy, vẫn giữ quyền → quay lại nút Cài đặt).
- Đã sở hữu **chưa cài** → nút **Cài đặt** (tải từ server).

### 5.3 Bấm Play (luồng đầy đủ GĐ5)
Khi bấm Play, client tự động:
1. Chạy `launcher.exe --print-hwid` lấy hardware id.
2. Gọi `POST /runtime/issue-token` (kèm token + hwid) → nhận entitlement token + payload key.
3. Cache bundle vào `.session.json` (để chạy offline).
4. Chạy `launcher.exe --entitlement ... --server-pubkey ... --key-b64 ...` → app demo chạy.
5. Popup hiện output + exit code (0 = OK).

---

## 6. Build lại C (khi cần)

Chỉ cần khi bạn sửa code trong `protector/src` hoặc `launcher/src`. Chạy trong **MSYS2 MinGW64 shell**
(hoặc PowerShell có sẵn `C:\msys64\mingw64\bin` trong PATH):

```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
cd /c/Users/lenovo/Desktop/temp2/DoAnCoSo/license_app/protector   # hoặc .../launcher
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

Output: `protector\build\protector.exe`, `launcher\build\launcher.exe`.

---

## 7. Test Protector CLI

Chạy trong shell có gcc/MinGW (vì `.exe` link tới DLL trong `C:\msys64\mingw64\bin`). Dùng MSYS2 shell
hoặc PowerShell sau khi thêm PATH: `$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"`.

### 7.1 keygen — sinh khóa ký manifest
```bash
cd protector
./build/protector.exe keygen --keys ./keys
# -> keys/manifest_ed25519.sk (BÍ MẬT) + .pk
```

### 7.2 pack — đóng gói app gốc thành protected package
```bash
./build/protector.exe pack \
  --input ../sample-app/DemoApp \
  --entry DemoApp.exe \
  --product-id demo_app \
  --output ./dist/DemoAppProtected \
  --version 1.0.0 --keys ./keys
```
Sinh ra trong `dist/DemoAppProtected/`:
- `payload.enc` (app mã hóa AES-256-GCM), `manifest.signed.json`, `public_key.pem` → **ship cho user**.
- `SECRET_payload_key.b64` → **đăng ký lên server, KHÔNG ship**.

### 7.3 verify — kiểm tra tính toàn vẹn package
```bash
./build/protector.exe verify --package ./dist/DemoAppProtected
```
- Package nguyên vẹn → báo **OK**.
- **Test giả mạo:** sửa 1 byte trong `payload.enc` → báo **HASH SAI**; sửa `manifest.signed.json` → báo **CHU KY SAI**.

---

## 8. Test Launcher trực tiếp (kiểm tra exit code)

`launcher.exe` cũng cần PATH tới `C:\msys64\mingw64\bin`.

```bash
cd launcher
./build/launcher.exe --print-hwid     # in hardware id của máy
```

Chạy package ở chế độ offline-local (GĐ3, key từ file — tiện test crypto nhanh):
```bash
./build/launcher.exe --package ../protector/dist/DemoAppProtected --key-file ../protector/dist/DemoAppProtected/SECRET_payload_key.b64
```

**Bảng exit code để test** (xem `echo $?` ở bash hoặc `$LASTEXITCODE` ở PowerShell):

| Code | Ý nghĩa | Cách tạo để test |
|---|---|---|
| 0 | OK (app chạy) | package nguyên vẹn + key đúng |
| 2 | Chữ ký manifest sai | sửa `manifest.signed.json` |
| 3 | Hash payload sai | sửa `payload.enc` |
| 4 | Giải mã thất bại | dùng sai key |
| 5 | Lỗi giải nén | payload hỏng |
| 6 | Không chạy được app | entry sai |
| 7 | Token/hardware binding sai / hết hạn offline | token cấp cho máy khác, hoặc `offline_until` quá khứ |

> **Lưu ý:** sửa file để test xong nhớ `protector pack` lại hoặc copy lại package gốc, kẻo client/launcher báo lỗi ở lần chạy thật.

---

## 9. Test các kịch bản BẢO MẬT (điểm nhấn của đề bài)

Mapping với [demo-script.md](demo-script.md):

| # | Kịch bản | Cách test | Kết quả mong đợi |
|---|---|---|---|
| 1 | Đóng gói app | `protector pack` ([§7.2](#72-pack--đóng-gói-app-gốc-thành-protected-package)) | sinh `payload.enc` + manifest ký + public key |
| 2 | User **không sở hữu** bấm Play | login client bằng user chưa grant | app không hiện trong library / bị chặn + audit log fail |
| 3 | Admin **grant** quyền | dashboard → Users → Grant | entitlement active |
| 4 | User sở hữu login client | login user01 | thấy app trong My Library |
| 5 | Bấm Play | nút Play | app chạy qua launcher, exit 0 |
| 6 | **Tamper** manifest/payload | sửa file rồi chạy launcher | exit 2 (chữ ký) / exit 3 (hash) |
| 7 | **Hardware binding** | dùng token của máy khác / đổi hwid | exit 7 |
| 8 | Admin **revoke** | dashboard → revoke entitlement | lần issue-token/verify sau bị chặn |
| 9 | **Offline grace** | tắt server rồi Play lại | còn hạn `offline_until` → chạy; hết hạn → yêu cầu online |
| 10 | **Audit trail** | dashboard → Audit logs | thấy toàn bộ chuỗi sự kiện trên |

**Test offline (kịch bản 9):** sau khi đã Play online thành công ít nhất 1 lần (đã cache bundle), **tắt
server** (Ctrl+C ở Terminal 1) rồi bấm Play lại trong client → vẫn chạy nếu offline token còn hạn.

---

## 10. Chạy test tự động (pytest)

```powershell
cd c:\Users\lenovo\Desktop\temp2\DoAnCoSo\license_app\server
.\.venv\Scripts\python.exe -m pytest -q
```
Bao gồm test auth, entitlement, runtime, admin dashboard.

---

## 11. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| `Permission denied ...\.venv\Scripts\python.exe` khi tạo venv | venv đã tồn tại — **đừng tạo lại**, activate thẳng. Muốn tạo lại: `Remove-Item -Recurse -Force .venv` trước rồi `python -m venv .venv` |
| Activate xong không thấy `(.venv)` | Custom prompt che tiền tố. Venv vẫn bật — kiểm tra `$env:VIRTUAL_ENV`. Hoặc bỏ qua activate, gọi thẳng `.\.venv\Scripts\python.exe` |
| `Activate.ps1` bị chặn (ExecutionPolicy) | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` rồi activate lại |
| Client báo không kết nối server | Chưa chạy server, hoặc sai `DRM_SERVER`. Mở http://127.0.0.1:8000/health kiểm tra |
| `protector.exe`/`launcher.exe` không chạy (thiếu DLL) | Thêm `C:\msys64\mingw64\bin` vào PATH trước khi chạy |
| Client báo app "Chưa cài" | Chưa copy package vào `desktop\apps\<product_id>\` (kèm `launcher.exe`) — xem [§5.2](#52-cài-app-cho-client) |
| Play bị chặn dù đã grant | Kiểm tra đã **đăng ký payload key** cho product chưa; xem Audit logs để biết lý do |

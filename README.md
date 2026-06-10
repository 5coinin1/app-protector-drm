# App Protector & Mini Client — Account-based DRM (Steam-like)

Đồ án: hệ thống bảo vệ bản quyền phần mềm theo mô hình "tài khoản sở hữu ứng dụng".
Developer đóng gói app thành bản mã hóa + ký số; người dùng đăng nhập, thấy thư viện app đã sở hữu,
bấm **Play** để chạy app qua launcher kiểm tra quyền ở server. Không sở hữu → không chạy được.

## Thành phần
| Thư mục | Vai trò | Công nghệ |
|---|---|---|
| `protector/` | Đóng gói + mã hóa + ký app | C (libsodium) |
| `launcher/` | `launcher.exe`: verify → decrypt → chạy app | C (libsodium, libcurl) |
| `server/` | License server + Admin dashboard | Python FastAPI + SQLite |
| `desktop/` | Mini client (login, library, Play) | Python CustomTkinter |
| `sample-app/` | App mẫu để demo | C/Python |
| `docs/` | architecture / threat-model / demo-script | — |

## Chạy nhanh (server)
```powershell
cd server
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```
- **Admin Dashboard (giao diện web):** http://127.0.0.1:8000/dashboard
  (đăng nhập `admin@example.com` / `admin12345`). Mở `/` sẽ tự chuyển sang đây.
- **API docs (Swagger):** http://127.0.0.1:8000/docs — thử trực tiếp mọi API.

### Dùng Admin Dashboard
Đăng nhập → tạo product, đăng ký payload key (dán nội dung `SECRET_payload_key.b64`),
tạo user, cấp/thu hồi quyền, xem thiết bị (thu hồi), xem audit log.

### Hoặc thử qua /docs (API)
1. `POST /auth/login` → copy `access_token`.
2. Bấm **Authorize**, dán token → gọi được `/admin/*`, `/runtime/*`.

## Tài liệu
- Kiến trúc & API & DB: [`docs/architecture.md`](docs/architecture.md)
- Mô hình mối đe dọa: [`docs/threat-model.md`](docs/threat-model.md)
- Kịch bản demo: [`docs/demo-script.md`](docs/demo-script.md)
- Yêu cầu gốc: `BMUDHT.docx`

> Chi tiết tech stack, quy ước & lộ trình: xem [`CLAUDE.md`](CLAUDE.md).

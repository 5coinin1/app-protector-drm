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
python ..\tools\gen_cert.py     # sinh cert TLS tự ký (chạy 1 lần)
python run.py                   # chạy server qua HTTPS
```
- **Admin Dashboard (giao diện web):** https://127.0.0.1:8000/dashboard
  (đăng nhập `admin@example.com` / `admin12345`). Mở `/` sẽ tự chuyển sang đây.
  *Trình duyệt sẽ cảnh báo cert tự ký — bấm "tiếp tục" là vào được (xem giải thích ở threat-model §3.10).*
- **API docs (Swagger):** https://127.0.0.1:8000/docs — thử trực tiếp mọi API.

> **Vì sao HTTPS:** client xin *payload key* (khóa giải mã app) qua server. Chạy HTTP trần thì key đi qua
> mạng dạng rõ → mất hết tác dụng mã hóa. Server bật TLS (`run.py`), còn desktop client + `tools/publish.py`
> **pin** đúng cert `certs/server.crt` để chống MITM. Chưa sinh cert? `run.py` tự lùi về HTTP kèm cảnh báo.

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

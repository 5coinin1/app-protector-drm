# Mini Desktop Client (Python + CustomTkinter)

Client kiểu Steam: đăng nhập tài khoản → xem thư viện app đã sở hữu → bấm **Play** để chạy app
qua Protected Launcher.

## Cài & chạy
```powershell
cd desktop
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```
Cần **server đang chạy** (xem `../server`). URL server mặc định `http://127.0.0.1:8000`
(đổi bằng biến môi trường `DRM_SERVER`).

## "Cài" app cho client
Client tìm package đã cài tại `desktop/apps/<product_id>/` (phải có `launcher.exe`).
Để cài app demo:
```powershell
# copy protected package (gồm launcher.exe) vào apps/<product_id>/
mkdir desktop/apps/demo_app
copy protector/dist/DemoAppProtected/* desktop/apps/demo_app/
copy launcher/build/launcher.exe desktop/apps/demo_app/
```
- App **đã sở hữu + đã cài** → nút **Play**.
- Đã sở hữu nhưng chưa cài → nút **Chưa cài** (disabled).
- Không sở hữu → không xuất hiện trong thư viện.

## Cấu trúc
| File | Vai trò |
|---|---|
| `main.py` | GUI (CustomTkinter): màn Login + Library, xử lý Play |
| `api.py` | gọi REST server (`/auth/login`, `/me/library`) |
| `session.py` | lưu/đọc token + cache library (`.session.json`) |
| `launcher_bridge.py` | tìm package & chạy `launcher.exe` cho 1 product |
| `config.py` | URL server, thư mục apps, file session |

## Tính năng
- Đăng nhập, lưu session (tự đăng nhập lại lần sau).
- Hiển thị thư viện app sở hữu (đồng bộ từ server).
- **Offline mode cơ bản**: mất mạng → dùng cache library đã lưu, hiện cảnh báo OFFLINE.
- Bấm Play → chạy launcher, hiện output + exit code (popup).
- Truyền `--token`/`--server` cho launcher (GĐ5 sẽ dùng để check entitlement ở server).

## Luồng Play (GĐ5)
1. Client chạy `launcher.exe --print-hwid` lấy hardware id máy.
2. Gọi `POST /runtime/issue-token` (kèm access token + hwid) → server check quyền sở hữu + device limit
   + revocation → trả **entitlement token đã ký (Ed25519)** + **payload key** + server public key.
3. Cache bundle vào `.session.json` (để chạy offline).
4. Chạy `launcher.exe --entitlement <token> --server-pubkey <b64> --key-b64 <key>` → launcher verify
   token + hardware binding + `offline_until`, rồi giải mã & chạy.
- Mất mạng → dùng bundle đã cache (chạy được tới hạn `offline_until`).

## Bảo mật / để lại sau
- `.session.json` lưu token + payload key (cache offline) dạng thường — **GĐ7** sẽ bảo vệ bằng DPAPI.

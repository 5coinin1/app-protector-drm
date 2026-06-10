# Protected Launcher (C)

File chạy thay app gốc trong protected package. Verify chữ ký + hash → giải mã `payload.enc`
→ giải nén ra thư mục tạm → chạy `entry` → dọn thư mục tạm khi app thoát.

## Trạng thái
- **Giai đoạn 3 (xong):** pipeline crypto + chạy app, payload key đọc từ file local.
- **Giai đoạn 5 (xong):** verify **entitlement token server ký (Ed25519)** + **hardware binding** +
  **offline grace** (`offline_until`); client lấy token + payload key từ server (sau khi server check
  quyền sở hữu / device limit / revocation) rồi truyền vào launcher.

## Chế độ chạy
- `launcher.exe --print-hwid` — in hardware id của máy (client gửi server đăng ký thiết bị).
- `launcher.exe --package <dir> --entitlement <file> --server-pubkey <b64> --key-b64 <key>` — chạy GĐ5
  (verify token + hardware binding + offline_until, key từ server).
- `launcher.exe --package <dir> --key-file <path>` — chế độ offline-local GĐ3 (bỏ qua check server).

## Kiến trúc code
Launcher **dùng chung** các module C với protector (một nguồn duy nhất), biên dịch trực tiếp từ
`../protector/src/{crypto,archive,manifest,util}.c` + `vendor/`. Phần riêng của launcher:
- `src/runner.c` — tạo thư mục tạm, `CreateProcess` chạy app, xóa đệ quy (cleanup).
- `src/main.c` — luồng chính.

## Build
```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
cmake -B build -G "MinGW Makefiles"
cmake --build build      # -> build/launcher.exe
```

## Mã thoát (exit code) — tiện cho test/demo
| Code | Ý nghĩa |
|---|---|
| 0 | OK (trả về đúng exit code của app gốc) |
| 2 | Chữ ký manifest sai (manifest bị sửa) |
| 3 | Hash payload sai (payload.enc bị sửa) |
| 4 | Giải mã thất bại (sai key hoặc payload bị sửa — GCM tag fail) |
| 5 | Lỗi giải nén |
| 6 | Không chạy được app |
| 7 | Entitlement token sai / hardware binding sai / hết hạn offline |

## Kiểm thử đã qua
- Chạy bình thường (online: token từ server) → app chạy, exit 0.
- Offline (token đã cache còn hạn) → app chạy, exit 0.
- Sửa `payload.enc` → exit 3 (HASH SAI). · Sai key → exit 4. · Sửa `manifest` → exit 2.
- Token cấp cho máy khác (device_hash khác) → exit 7 (HARDWARE BINDING SAI).
- Token hết hạn offline (`offline_until` quá khứ) → exit 7 (HẾT HẠN OFFLINE).

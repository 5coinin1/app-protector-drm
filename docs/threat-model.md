# Threat Model

Bảng mối đe dọa ↔ cách xử lý (bám đề bài §11). Dùng cho báo cáo/thuyết trình.

| Mối đe dọa | Cách xử lý trong hệ thống |
|---|---|
| Copy app sang máy khác | Account entitlement + hardware binding (device_hash) |
| Sửa `manifest.signed.json` | Chữ ký Ed25519 trên manifest → verify sai → launcher chặn |
| Sửa `payload.enc` | SHA-256 `payload_hash` trong manifest + AES-GCM auth tag |
| Sửa token local (vd. offline_until → 2099) | Token ký Ed25519 bởi server → chữ ký sai → chặn |
| Chạy khi chưa mua app | Server-side entitlement check (client không tự quyết) |
| Dùng offline mãi mãi | Offline grace period: `offline_until` trong token đã ký, có hạn |
| Share tài khoản nhiều máy | Device limit + product_devices |
| Quyền đã bị thu hồi | Revocation + đồng bộ trạng thái lần verify sau |
| Copy thư mục temp lúc đang chạy | Cleanup sau thoát + không để app gốc lộ sẵn + giá trị thật ở server |
| Brute force login | Password hash (Argon2id/bcrypt) + rate limit |
| Admin lạm quyền / khó truy vết | Audit log mọi hành động nhạy cảm |
| Replay token | Nonce + ràng buộc device_hash + thời hạn ngắn + refresh rotation |

## Ranh giới tin cậy (trust boundaries)
- **Không tin client/launcher** cho quyết định quyền sở hữu — chỉ tin server (hoặc token đã ký server còn hạn cho offline).
- Khóa **private** (ký manifest, ký token) chỉ ở server/máy developer, không bao giờ đóng vào package gửi user.
- Public key được nhúng/phân phối để verify; payload key có thể cấp từ server (server-side key) để tăng kiểm soát.

## Ngoài phạm vi (đề bài §"Không nên làm")
Không làm: manual PE loader, process hollowing, kernel driver, anti-debug phức tạp, virtualization kiểu VMProtect,
chống crack tuyệt đối. Trọng tâm là DRM/entitlement đúng đắn, không phải anti-reverse.

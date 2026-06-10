# Kịch bản Demo (bám đề bài §12)

Chuẩn bị: server đang chạy, đã có 1 sample app, 2 user (user01 sở hữu app, user02 không).

| # | Bước demo | Kết quả mong đợi |
|---|---|---|
| 1 | Pack app gốc bằng Protector | Sinh ra `payload.enc`, `manifest.signed.json`, `public_key.pem` |
| 2 | user02 (chưa sở hữu) bấm Play | Bị chặn: "not owned", có audit log fail |
| 3 | Admin cấp quyền app cho user01 | Entitlement active trong dashboard |
| 4 | user01 đăng nhập desktop client | Thấy app trong My Library |
| 5 | user01 bấm Play | App gốc chạy bình thường qua launcher |
| 6 | Sửa manifest hoặc payload rồi chạy lại | Launcher phát hiện sai chữ ký/hash → chặn |
| 7 | Đổi hardware_hash / copy sang máy khác | Bị chặn do hardware binding |
| 8 | Admin revoke entitlement | Lần sync/verify sau app bị khóa |
| 9 | Tắt server, user01 chạy lại | Vẫn chạy nếu offline token còn hạn; hết hạn → yêu cầu online |
| 10 | Mở Admin → Audit logs | Thấy toàn bộ chuỗi sự kiện ở trên |

## Mẹo trình bày
- Mỗi demo nên soi kèm **audit log** tương ứng để chứng minh server-side verification.
- Demo 6 & 7 là điểm nhấn bảo mật (integrity + hardware binding) — chuẩn bị sẵn file đã chỉnh để show nhanh.

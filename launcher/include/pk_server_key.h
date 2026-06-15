/* Public key của License Server (Ed25519), GHIM SẴN trong launcher lúc build.
 *
 * Vì sao pin: launcher KHÔNG được tin public key do client truyền vào (client là phía
 * không tin được — kẻ tấn công có thể đưa key giả + entitlement token tự ký). Token chỉ
 * hợp lệ nếu verify được bằng đúng key này.
 *
 * Đây là KHÓA CÔNG KHAI -> an toàn để commit. Lấy bằng:
 *   python -c "from app.services.tokens import server_public_key_b64; print(server_public_key_b64())"
 * Nếu đổi seed server (server/data/server_ed25519.seed) thì phải cập nhật lại đây & build lại.
 */
#ifndef PK_SERVER_KEY_H
#define PK_SERVER_KEY_H

#define PK_SERVER_PUBKEY_B64 "6Tun7esiIAVRWZM8u1wIh2aTnmJBIawOOmjnXT8Bidc="

#endif /* PK_SERVER_KEY_H */

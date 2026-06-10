/* Crypto wrapper trên libsodium: AES-256-GCM, Ed25519, SHA-256, base64, PEM. */
#ifndef PK_CRYPTO_H
#define PK_CRYPTO_H

#include <stddef.h>
#include <sodium.h>

#define PK_KEYBYTES   crypto_aead_aes256gcm_KEYBYTES   /* 32 */
#define PK_NONCEBYTES crypto_aead_aes256gcm_NPUBBYTES  /* 12 */
#define PK_ABYTES     crypto_aead_aes256gcm_ABYTES     /* 16 (auth tag) */
#define PK_SIG_PK     crypto_sign_PUBLICKEYBYTES       /* 32 */
#define PK_SIG_SK     crypto_sign_SECRETKEYBYTES       /* 64 */
#define PK_SIGBYTES   crypto_sign_BYTES                /* 64 */
#define PK_SHA256     crypto_hash_sha256_BYTES         /* 32 */

/* Khởi tạo libsodium + kiểm tra AES-256-GCM khả dụng. Trả 0 nếu OK, -1 nếu lỗi. */
int pk_crypto_init(void);

/* Sinh ngẫu nhiên. */
void pk_random_bytes(unsigned char *buf, size_t len);

/* Mã hóa AES-256-GCM (combined mode: ciphertext kèm 16 byte tag ở cuối).
 * out cần (plen + PK_ABYTES) byte. Trả 0 nếu OK. */
int pk_aes_encrypt(const unsigned char *plain, size_t plen,
                   const unsigned char key[PK_KEYBYTES],
                   const unsigned char nonce[PK_NONCEBYTES],
                   unsigned char *out, size_t *out_len);

/* Giải mã AES-256-GCM. enc = ciphertext ‖ tag(16B), enc_len >= PK_ABYTES.
 * out cần (enc_len - PK_ABYTES) byte. Trả 0 nếu OK & tag hợp lệ;
 * -1 nếu tag sai (payload bị sửa) hoặc lỗi. */
int pk_aes_decrypt(const unsigned char *enc, size_t enc_len,
                   const unsigned char key[PK_KEYBYTES],
                   const unsigned char nonce[PK_NONCEBYTES],
                   unsigned char *out, size_t *out_len);

/* SHA-256 -> chuỗi hex (cần buf >= 65 byte). */
void pk_sha256_hex(const unsigned char *data, size_t len, char *hex_out);

/* Ed25519 keypair. */
void pk_sign_keypair(unsigned char pk[PK_SIG_PK], unsigned char sk[PK_SIG_SK]);

/* Ký detached. sig cần PK_SIGBYTES. Trả 0 nếu OK. */
int pk_sign(const unsigned char *msg, size_t mlen,
            const unsigned char sk[PK_SIG_SK], unsigned char sig[PK_SIGBYTES]);

/* Verify detached. Trả 0 nếu hợp lệ, -1 nếu sai. */
int pk_sign_verify(const unsigned char *msg, size_t mlen,
                   const unsigned char sig[PK_SIGBYTES],
                   const unsigned char pk[PK_SIG_PK]);

/* base64 (variant ORIGINAL, có padding). Trả con trỏ malloc, caller free. */
char *pk_b64_encode(const unsigned char *bin, size_t bin_len);
/* Giải base64 vào out (đã cấp sẵn out_cap). Trả số byte, hoặc -1 nếu lỗi. */
long pk_b64_decode(const char *b64, unsigned char *out, size_t out_cap);

/* Ghi/đọc public key dạng PEM-wrapped (markers ED25519). */
int pk_write_pubkey_pem(const char *path, const unsigned char pk[PK_SIG_PK]);
int pk_read_pubkey_pem(const char *path, unsigned char pk[PK_SIG_PK]);

#endif /* PK_CRYPTO_H */

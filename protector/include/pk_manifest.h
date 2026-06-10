/* Tạo manifest đã ký (manifest.signed.json) và verify nó. */
#ifndef PK_MANIFEST_H
#define PK_MANIFEST_H

#include "pk_crypto.h"

/* Tạo manifest, ký Ed25519, ghi ra path dạng:
 *   { "manifest": {...}, "signature": "<b64>", "alg": "Ed25519" }
 * Trả 0 nếu OK. */
int pk_manifest_write_signed(const char *path,
                             const char *product_id,
                             const char *version,
                             const char *entry,
                             const char *payload_file,
                             const char *payload_hash_hex,
                             const char *nonce_b64,
                             const char *created_at,
                             const unsigned char sk[PK_SIG_SK]);

/* Đọc file đã ký, verify chữ ký bằng pk.
 * In ra các trường chính. Trả 0 nếu hợp lệ, -1 nếu sai/chữ ký hỏng. */
int pk_manifest_verify_file(const char *path, const unsigned char pk[PK_SIG_PK]);

/* Các trường manifest mà launcher cần. */
typedef struct {
    char product_id[128];
    char version[64];
    char entry[260];
    char payload_file[128];
    char payload_hash[80];   /* SHA-256 hex (64) */
    char nonce_b64[64];      /* base64 12 byte */
} pk_manifest_info;

/* Verify chữ ký rồi nạp các trường vào out.
 * Trả 0 nếu hợp lệ, -1 nếu chữ ký sai/thiếu trường. */
int pk_manifest_verify_and_load(const char *path, const unsigned char pk[PK_SIG_PK],
                                pk_manifest_info *out);

#endif /* PK_MANIFEST_H */

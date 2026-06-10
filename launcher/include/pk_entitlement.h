/* Verify entitlement token do server ký (Ed25519). */
#ifndef PK_ENTITLEMENT_H
#define PK_ENTITLEMENT_H

#include "pk_crypto.h"

typedef struct {
    char product_id[128];
    char device_hash[128];
    char issued_at[32];
    char offline_until[32];
} pk_entitlement;

/* Đọc file token {claims_b64, signature, alg}, verify chữ ký bằng server_pub,
 * rồi nạp các claim vào out. Trả 0 nếu chữ ký hợp lệ, -1 nếu sai/hỏng. */
int pk_entitlement_verify(const char *token_file, const unsigned char server_pub[PK_SIG_PK],
                          pk_entitlement *out);

#endif /* PK_ENTITLEMENT_H */

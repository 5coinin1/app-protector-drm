#include "pk_entitlement.h"
#include "pk_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

static void copy_field(const cJSON *m, const char *key, char *dst, size_t cap) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(m, key);
    if (cJSON_IsString(it) && it->valuestring)
        snprintf(dst, cap, "%s", it->valuestring);
    else
        dst[0] = '\0';
}

int pk_entitlement_verify(const char *token_file, const unsigned char server_pub[PK_SIG_PK],
                          pk_entitlement *out) {
    unsigned char *raw = NULL;
    size_t len = 0;
    if (pk_read_file(token_file, &raw, &len) != 0) {
        fprintf(stderr, "loi: khong doc duoc entitlement token %s\n", token_file);
        return -1;
    }
    cJSON *root = cJSON_Parse((const char *)raw);
    free(raw);
    if (!root) { fprintf(stderr, "loi: entitlement token JSON khong hop le\n"); return -1; }

    int rc = -1;
    unsigned char *claims = NULL;
    cJSON *claims_b64 = cJSON_GetObjectItemCaseSensitive(root, "claims_b64");
    cJSON *sig_b64 = cJSON_GetObjectItemCaseSensitive(root, "signature");
    if (!cJSON_IsString(claims_b64) || !cJSON_IsString(sig_b64)) {
        fprintf(stderr, "loi: token thieu claims_b64/signature\n");
        goto done;
    }

    /* decode claims (bytes ĐÚNG như server đã ký — không serialize lại) */
    size_t cap = strlen(claims_b64->valuestring);
    claims = malloc(cap + 1);
    if (!claims) goto done;
    long clen = pk_b64_decode(claims_b64->valuestring, claims, cap);
    if (clen < 0) { fprintf(stderr, "loi: claims_b64 sai\n"); goto done; }

    unsigned char sig[PK_SIGBYTES];
    if (pk_b64_decode(sig_b64->valuestring, sig, sizeof(sig)) != PK_SIGBYTES) {
        fprintf(stderr, "loi: signature token sai\n");
        goto done;
    }

    if (pk_sign_verify(claims, (size_t)clen, sig, server_pub) != 0) {
        fprintf(stderr, "ENTITLEMENT TOKEN SAI: chu ky khong khop server (bi sua hoac gia mao)\n");
        goto done;
    }

    /* chữ ký OK -> parse claims để đọc field */
    cJSON *cj = cJSON_ParseWithLength((const char *)claims, (size_t)clen);
    if (!cj) { fprintf(stderr, "loi: claims JSON hong\n"); goto done; }
    copy_field(cj, "product_id", out->product_id, sizeof(out->product_id));
    copy_field(cj, "device_hash", out->device_hash, sizeof(out->device_hash));
    copy_field(cj, "issued_at", out->issued_at, sizeof(out->issued_at));
    copy_field(cj, "offline_until", out->offline_until, sizeof(out->offline_until));
    cJSON_Delete(cj);
    rc = 0;

done:
    free(claims);
    cJSON_Delete(root);
    return rc;
}

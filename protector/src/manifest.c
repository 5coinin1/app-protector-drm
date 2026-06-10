#include "pk_manifest.h"
#include "pk_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

/* Tạo object manifest theo thứ tự field cố định (để in ra ổn định khi verify). */
static cJSON *build_manifest_obj(const char *product_id, const char *version,
                                 const char *entry, const char *payload_file,
                                 const char *payload_hash_hex, const char *nonce_b64,
                                 const char *created_at) {
    cJSON *m = cJSON_CreateObject();
    if (!m) return NULL;
    cJSON_AddStringToObject(m, "product_id", product_id);
    cJSON_AddStringToObject(m, "version", version);
    cJSON_AddStringToObject(m, "entry", entry);
    cJSON_AddStringToObject(m, "payload_file", payload_file);
    cJSON_AddStringToObject(m, "payload_hash", payload_hash_hex);
    cJSON_AddStringToObject(m, "cipher", "AES-256-GCM");
    cJSON_AddStringToObject(m, "nonce", nonce_b64);
    cJSON_AddStringToObject(m, "created_at", created_at);
    return m;
}

int pk_manifest_write_signed(const char *path,
                             const char *product_id, const char *version,
                             const char *entry, const char *payload_file,
                             const char *payload_hash_hex, const char *nonce_b64,
                             const char *created_at,
                             const unsigned char sk[PK_SIG_SK]) {
    int rc = -1;
    char *man_str = NULL, *signed_str = NULL, *sig_b64 = NULL;
    cJSON *manifest = NULL, *wrapper = NULL;
    unsigned char sig[PK_SIGBYTES];

    manifest = build_manifest_obj(product_id, version, entry, payload_file,
                                  payload_hash_hex, nonce_b64, created_at);
    if (!manifest) goto done;

    /* Chuỗi được ký = manifest in unformatted (deterministic vì toàn string, giữ thứ tự). */
    man_str = cJSON_PrintUnformatted(manifest);
    if (!man_str) goto done;

    if (pk_sign((const unsigned char *)man_str, strlen(man_str), sk, sig) != 0) goto done;
    sig_b64 = pk_b64_encode(sig, PK_SIGBYTES);
    if (!sig_b64) goto done;

    wrapper = cJSON_CreateObject();
    if (!wrapper) goto done;
    /* gắn chính object manifest vào wrapper -> in lại sẽ trùng man_str khi verify */
    cJSON_AddItemToObject(wrapper, "manifest", manifest);
    manifest = NULL;  /* quyền sở hữu đã chuyển cho wrapper */
    cJSON_AddStringToObject(wrapper, "signature", sig_b64);
    cJSON_AddStringToObject(wrapper, "alg", "Ed25519");

    signed_str = cJSON_Print(wrapper);  /* in đẹp cho file lưu */
    if (!signed_str) goto done;

    rc = pk_write_file(path, (const unsigned char *)signed_str, strlen(signed_str));

done:
    if (manifest) cJSON_Delete(manifest);
    if (wrapper) cJSON_Delete(wrapper);
    free(man_str);
    free(signed_str);
    free(sig_b64);
    return rc;
}

static void copy_field(const cJSON *m, const char *key, char *dst, size_t cap) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(m, key);
    if (cJSON_IsString(it) && it->valuestring) {
        snprintf(dst, cap, "%s", it->valuestring);
    } else {
        dst[0] = '\0';
    }
}

int pk_manifest_verify_and_load(const char *path, const unsigned char pk[PK_SIG_PK],
                                pk_manifest_info *out) {
    unsigned char *raw = NULL;
    size_t len = 0;
    if (pk_read_file(path, &raw, &len) != 0) {
        fprintf(stderr, "loi: khong doc duoc %s\n", path);
        return -1;
    }
    cJSON *root = cJSON_Parse((const char *)raw);
    free(raw);
    if (!root) { fprintf(stderr, "loi: manifest JSON khong hop le\n"); return -1; }

    int rc = -1;
    char *man_str = NULL;
    cJSON *manifest = cJSON_GetObjectItemCaseSensitive(root, "manifest");
    cJSON *sig_item = cJSON_GetObjectItemCaseSensitive(root, "signature");
    if (!manifest || !cJSON_IsString(sig_item)) {
        fprintf(stderr, "loi: thieu manifest/signature\n");
        goto done;
    }

    man_str = cJSON_PrintUnformatted(manifest);
    if (!man_str) goto done;

    unsigned char sig[PK_SIGBYTES];
    if (pk_b64_decode(sig_item->valuestring, sig, sizeof(sig)) != PK_SIGBYTES) {
        fprintf(stderr, "loi: signature base64 sai\n");
        goto done;
    }
    if (pk_sign_verify((const unsigned char *)man_str, strlen(man_str), sig, pk) != 0) {
        fprintf(stderr, "CHU KY SAI: manifest da bi sua hoac khong khop public key\n");
        goto done;
    }

    copy_field(manifest, "product_id", out->product_id, sizeof(out->product_id));
    copy_field(manifest, "version", out->version, sizeof(out->version));
    copy_field(manifest, "entry", out->entry, sizeof(out->entry));
    copy_field(manifest, "payload_file", out->payload_file, sizeof(out->payload_file));
    copy_field(manifest, "payload_hash", out->payload_hash, sizeof(out->payload_hash));
    copy_field(manifest, "nonce", out->nonce_b64, sizeof(out->nonce_b64));

    if (out->entry[0] == '\0' || out->payload_file[0] == '\0' ||
        out->payload_hash[0] == '\0' || out->nonce_b64[0] == '\0') {
        fprintf(stderr, "loi: manifest thieu truong bat buoc\n");
        goto done;
    }
    rc = 0;

done:
    free(man_str);
    cJSON_Delete(root);
    return rc;
}

int pk_manifest_verify_file(const char *path, const unsigned char pk[PK_SIG_PK]) {
    unsigned char *raw = NULL;
    size_t len = 0;
    if (pk_read_file(path, &raw, &len) != 0) {
        fprintf(stderr, "loi: khong doc duoc %s\n", path);
        return -1;
    }

    cJSON *root = cJSON_Parse((const char *)raw);
    free(raw);
    if (!root) { fprintf(stderr, "loi: JSON khong hop le\n"); return -1; }

    int rc = -1;
    char *man_str = NULL;
    cJSON *manifest = cJSON_GetObjectItemCaseSensitive(root, "manifest");
    cJSON *sig_item = cJSON_GetObjectItemCaseSensitive(root, "signature");
    if (!manifest || !cJSON_IsString(sig_item)) {
        fprintf(stderr, "loi: thieu manifest/signature\n");
        goto done;
    }

    man_str = cJSON_PrintUnformatted(manifest);
    if (!man_str) goto done;

    unsigned char sig[PK_SIGBYTES];
    if (pk_b64_decode(sig_item->valuestring, sig, sizeof(sig)) != PK_SIGBYTES) {
        fprintf(stderr, "loi: signature base64 sai\n");
        goto done;
    }

    if (pk_sign_verify((const unsigned char *)man_str, strlen(man_str), sig, pk) != 0) {
        fprintf(stderr, "CHU KY SAI: manifest da bi sua hoac khong khop public key\n");
        goto done;
    }

    cJSON *pid = cJSON_GetObjectItemCaseSensitive(manifest, "product_id");
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(manifest, "entry");
    cJSON *phash = cJSON_GetObjectItemCaseSensitive(manifest, "payload_hash");
    printf("  product_id   : %s\n", cJSON_IsString(pid) ? pid->valuestring : "?");
    printf("  entry        : %s\n", cJSON_IsString(entry) ? entry->valuestring : "?");
    printf("  payload_hash : %s\n", cJSON_IsString(phash) ? phash->valuestring : "?");
    rc = 0;

done:
    free(man_str);
    cJSON_Delete(root);
    return rc;
}

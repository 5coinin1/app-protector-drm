/* Protector CLI — đóng gói app thành protected package.
 *
 *   protector keygen --keys ./keys
 *   protector pack --input ./DemoApp --entry DemoApp.exe --product-id demo_app \
 *                  --output ./dist/DemoAppProtected [--version 1.0.0] [--keys ./keys]
 *   protector verify --package ./dist/DemoAppProtected
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "pk_archive.h"
#include "pk_crypto.h"
#include "pk_manifest.h"
#include "pk_util.h"

#define SK_NAME "manifest_ed25519.sk"
#define PK_NAME "manifest_ed25519.pk"

/* Lấy giá trị theo cờ --name từ argv. Trả NULL nếu không có. */
static const char *arg(int argc, char **argv, const char *name) {
    for (int i = 2; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return NULL;
}

static int join(char *dst, size_t cap, const char *a, const char *b) {
    return snprintf(dst, cap, "%s/%s", a, b) > 0 ? 0 : -1;
}

/* Nạp keypair ký từ keys_dir; nếu chưa có thì sinh mới và lưu lại. */
static int load_or_create_keys(const char *keys_dir,
                               unsigned char pk[PK_SIG_PK], unsigned char sk[PK_SIG_SK]) {
    char sk_path[1024], pk_path[1024];
    join(sk_path, sizeof(sk_path), keys_dir, SK_NAME);
    join(pk_path, sizeof(pk_path), keys_dir, PK_NAME);

    if (pk_exists(sk_path) && pk_exists(pk_path)) {
        unsigned char *b = NULL; size_t n = 0;
        if (pk_read_file(sk_path, &b, &n) != 0 || n != PK_SIG_SK) { free(b); return -1; }
        memcpy(sk, b, PK_SIG_SK); free(b);
        if (pk_read_file(pk_path, &b, &n) != 0 || n != PK_SIG_PK) { free(b); return -1; }
        memcpy(pk, b, PK_SIG_PK); free(b);
        printf("  dung keypair ky san co: %s\n", keys_dir);
        return 0;
    }

    if (pk_mkdir_p(keys_dir) != 0) { fprintf(stderr, "loi: khong tao duoc %s\n", keys_dir); return -1; }
    pk_sign_keypair(pk, sk);
    if (pk_write_file(sk_path, sk, PK_SIG_SK) != 0) return -1;
    if (pk_write_file(pk_path, pk, PK_SIG_PK) != 0) return -1;
    printf("  da sinh keypair ky moi -> %s (GIU BI MAT file .sk!)\n", keys_dir);
    return 0;
}

static int cmd_keygen(int argc, char **argv) {
    const char *keys_dir = arg(argc, argv, "--keys");
    if (!keys_dir) keys_dir = "keys";
    unsigned char pk[PK_SIG_PK], sk[PK_SIG_SK];
    if (load_or_create_keys(keys_dir, pk, sk) != 0) return 1;
    printf("OK: keypair ky o %s\n", keys_dir);
    return 0;
}

static int cmd_pack(int argc, char **argv) {
    const char *input   = arg(argc, argv, "--input");
    const char *entry   = arg(argc, argv, "--entry");
    const char *prod    = arg(argc, argv, "--product-id");
    const char *output  = arg(argc, argv, "--output");
    const char *version = arg(argc, argv, "--version");
    const char *keys    = arg(argc, argv, "--keys");
    if (!version) version = "1.0.0";
    if (!keys) keys = "keys";

    if (!input || !entry || !prod || !output) {
        fprintf(stderr, "thieu tham so. can: --input --entry --product-id --output\n");
        return 1;
    }
    if (!pk_exists(input)) { fprintf(stderr, "loi: khong thay input %s\n", input); return 1; }

    unsigned char sign_pk[PK_SIG_PK], sign_sk[PK_SIG_SK];
    if (load_or_create_keys(keys, sign_pk, sign_sk) != 0) return 1;

    /* 1. Nén app gốc */
    unsigned char *zip = NULL; size_t zip_len = 0;
    if (pk_zip_directory(input, &zip, &zip_len) != 0) return 1;
    printf("  nen app: %zu byte\n", zip_len);

    /* 2. Mã hóa AES-256-GCM */
    unsigned char key[PK_KEYBYTES], nonce[PK_NONCEBYTES];
    pk_random_bytes(key, sizeof(key));
    pk_random_bytes(nonce, sizeof(nonce));
    unsigned char *enc = malloc(zip_len + PK_ABYTES);
    size_t enc_len = 0;
    if (!enc || pk_aes_encrypt(zip, zip_len, key, nonce, enc, &enc_len) != 0) {
        fprintf(stderr, "loi: ma hoa that bai\n"); free(zip); free(enc); return 1;
    }
    free(zip);
    printf("  ma hoa: %zu byte payload.enc\n", enc_len);

    /* 3. Ghi output */
    if (pk_mkdir_p(output) != 0) { fprintf(stderr, "loi: khong tao duoc %s\n", output); free(enc); return 1; }

    char path[1024], hash_hex[PK_SHA256 * 2 + 1];
    join(path, sizeof(path), output, "payload.enc");
    if (pk_write_file(path, enc, enc_len) != 0) { free(enc); return 1; }

    /* 4. Hash payload.enc */
    pk_sha256_hex(enc, enc_len, hash_hex);
    free(enc);

    /* 5. Manifest + ký */
    char *nonce_b64 = pk_b64_encode(nonce, sizeof(nonce));
    char created_at[32];
    pk_iso8601_utc(created_at, sizeof(created_at));
    join(path, sizeof(path), output, "manifest.signed.json");
    int mrc = pk_manifest_write_signed(path, prod, version, entry, "payload.enc",
                                       hash_hex, nonce_b64, created_at, sign_sk);
    free(nonce_b64);
    if (mrc != 0) { fprintf(stderr, "loi: ghi manifest that bai\n"); return 1; }

    /* 6. public_key.pem */
    join(path, sizeof(path), output, "public_key.pem");
    if (pk_write_pubkey_pem(path, sign_pk) != 0) { fprintf(stderr, "loi: ghi public key\n"); return 1; }

    /* 7. payload key (BI MAT) -> de developer dang ky voi server, KHONG phat hanh */
    char *key_b64 = pk_b64_encode(key, sizeof(key));
    sodium_memzero(key, sizeof(key));
    join(path, sizeof(path), output, "SECRET_payload_key.b64");
    pk_write_file(path, (const unsigned char *)key_b64, strlen(key_b64));
    free(key_b64);

    printf("\nOK: da tao protected package tai %s\n", output);
    printf("  - payload.enc, manifest.signed.json, public_key.pem\n");
    printf("  - SECRET_payload_key.b64  (dang ky len server, KHONG dong vao ban phat hanh)\n");
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    const char *pkg = arg(argc, argv, "--package");
    if (!pkg) { fprintf(stderr, "can --package <thu muc>\n"); return 1; }

    char pub_path[1024], man_path[1024], enc_path[1024];
    join(pub_path, sizeof(pub_path), pkg, "public_key.pem");
    join(man_path, sizeof(man_path), pkg, "manifest.signed.json");
    join(enc_path, sizeof(enc_path), pkg, "payload.enc");

    unsigned char pub[PK_SIG_PK];
    if (pk_read_pubkey_pem(pub_path, pub) != 0) { fprintf(stderr, "loi: doc public_key.pem\n"); return 1; }

    printf("Kiem tra chu ky manifest...\n");
    if (pk_manifest_verify_file(man_path, pub) != 0) return 1;
    printf("  -> chu ky HOP LE\n");

    /* Kiem tra hash payload */
    unsigned char *raw = NULL; size_t rlen = 0;
    if (pk_read_file(man_path, &raw, &rlen) != 0) return 1;
    cJSON *root = cJSON_Parse((const char *)raw);
    free(raw);
    cJSON *manifest = root ? cJSON_GetObjectItemCaseSensitive(root, "manifest") : NULL;
    cJSON *phash = manifest ? cJSON_GetObjectItemCaseSensitive(manifest, "payload_hash") : NULL;
    if (!cJSON_IsString(phash)) { fprintf(stderr, "loi: thieu payload_hash\n"); cJSON_Delete(root); return 1; }

    unsigned char *enc = NULL; size_t enc_len = 0;
    if (pk_read_file(enc_path, &enc, &enc_len) != 0) { fprintf(stderr, "loi: doc payload.enc\n"); cJSON_Delete(root); return 1; }
    char actual[PK_SHA256 * 2 + 1];
    pk_sha256_hex(enc, enc_len, actual);
    free(enc);

    printf("Kiem tra hash payload...\n");
    int ok = strcmp(actual, phash->valuestring) == 0;
    cJSON_Delete(root);
    if (!ok) { fprintf(stderr, "  -> HASH SAI: payload.enc da bi sua!\n"); return 1; }
    printf("  -> hash KHOP\n\nOK: package hop le.\n");
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "Protector CLI\n"
        "  protector keygen --keys ./keys\n"
        "  protector pack --input <dir> --entry <file> --product-id <id> --output <dir> [--version v] [--keys d]\n"
        "  protector verify --package <dir>\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    if (pk_crypto_init() != 0) return 1;

    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "pack") == 0)   return cmd_pack(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);

    usage();
    return 1;
}

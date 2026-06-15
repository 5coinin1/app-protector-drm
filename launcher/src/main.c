/* Protected Launcher — chạy thay app gốc.
 *
 *   launcher [--package <dir>] [--key-file <path> | --key-b64 <base64>]
 *
 * Giai đoạn 3 (offline crypto + run):
 *   1. đọc manifest  2. verify chữ ký  3. verify hash payload
 *   4. lấy payload key (tạm: file local; GĐ5 lấy từ server sau khi check entitlement)
 *   5. giải mã payload.enc  6. giải nén ra thư mục tạm
 *   7. chạy entry  8. dọn thư mục tạm
 *
 * GĐ5 sẽ chèn: kiểm tra session token, entitlement (server), hardware binding, offline token.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pk_archive.h"
#include "pk_crypto.h"
#include "pk_entitlement.h"
#include "pk_fingerprint.h"
#include "pk_manifest.h"
#include "pk_runner.h"
#include "pk_server_key.h"
#include "pk_util.h"

static const char *arg(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return NULL;
}

static int has_flag(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], name) == 0) return 1;
    return 0;
}

static void rstrip(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

/* Nạp payload key 32 byte từ --key-b64, --key-file, hoặc mặc định <pkg>/SECRET_payload_key.b64. */
static int load_payload_key(int argc, char **argv, const char *pkg,
                            unsigned char key[PK_KEYBYTES]) {
    const char *kb64 = arg(argc, argv, "--key-b64");
    const char *kfile = arg(argc, argv, "--key-file");
    char b64[256];

    if (kb64) {
        snprintf(b64, sizeof(b64), "%s", kb64);
    } else {
        char path[1024];
        if (kfile) snprintf(path, sizeof(path), "%s", kfile);
        else snprintf(path, sizeof(path), "%s/SECRET_payload_key.b64", pkg);
        unsigned char *raw = NULL; size_t n = 0;
        if (pk_read_file(path, &raw, &n) != 0) {
            fprintf(stderr, "loi: khong doc duoc payload key (%s)\n", path);
            return -1;
        }
        snprintf(b64, sizeof(b64), "%s", (char *)raw);
        free(raw);
    }
    rstrip(b64);
    if (pk_b64_decode(b64, key, PK_KEYBYTES) != PK_KEYBYTES) {
        fprintf(stderr, "loi: payload key base64 sai (can 32 byte)\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (pk_crypto_init() != 0) return 1;

    /* Chế độ in hardware id (client gọi để gửi lên server đăng ký thiết bị). */
    if (has_flag(argc, argv, "--print-hwid")) {
        char hwid[PK_SHA256 * 2 + 1];
        if (pk_hardware_hash(hwid, sizeof(hwid)) != 0) return 1;
        printf("%s\n", hwid);
        return 0;
    }

    /* package = --package hoặc thư mục chứa launcher.exe */
    char pkg[1024];
    const char *parg = arg(argc, argv, "--package");
    if (parg) snprintf(pkg, sizeof(pkg), "%s", parg);
    else if (pk_exe_dir(pkg, sizeof(pkg)) != 0) { fprintf(stderr, "loi: khong xac dinh duoc thu muc\n"); return 1; }

    char pub_path[1100], man_path[1100], enc_path[1200];
    snprintf(pub_path, sizeof(pub_path), "%s/public_key.pem", pkg);
    snprintf(man_path, sizeof(man_path), "%s/manifest.signed.json", pkg);

    printf("[launcher] package: %s\n", pkg);

    /* 1-2. Manifest + verify chữ ký */
    unsigned char pub[PK_SIG_PK];
    if (pk_read_pubkey_pem(pub_path, pub) != 0) { fprintf(stderr, "loi: doc public_key.pem\n"); return 1; }
    pk_manifest_info mi;
    printf("[launcher] kiem tra chu ky manifest...\n");
    if (pk_manifest_verify_and_load(man_path, pub, &mi) != 0) return 2;
    printf("           OK  product=%s entry=%s\n", mi.product_id, mi.entry);

    /* 3. Verify hash payload */
    snprintf(enc_path, sizeof(enc_path), "%s/%s", pkg, mi.payload_file);
    unsigned char *enc = NULL; size_t enc_len = 0;
    if (pk_read_file(enc_path, &enc, &enc_len) != 0) { fprintf(stderr, "loi: doc %s\n", enc_path); return 1; }
    char actual_hash[PK_SHA256 * 2 + 1];
    pk_sha256_hex(enc, enc_len, actual_hash);
    printf("[launcher] kiem tra hash payload...\n");
    if (strcmp(actual_hash, mi.payload_hash) != 0) {
        fprintf(stderr, "           HASH SAI: payload.enc da bi sua!\n");
        free(enc); return 3;
    }
    printf("           OK  hash khop\n");

    /* GĐ5: verify entitlement token (server ký) + hardware binding + offline grace.
     * Client lấy token từ server (sau khi check quyền sở hữu) rồi truyền vào đây. */
    const char *ent_file = arg(argc, argv, "--entitlement");
    const char *srv_pub_b64 = arg(argc, argv, "--server-pubkey");
    if (ent_file) {
        /* GHIM (pin) public key server: chỉ tin key nhúng sẵn lúc build, KHÔNG tin key client
         * truyền vào. Nhờ vậy token giả do client tự ký bằng key khác sẽ verify thất bại. */
        unsigned char srv_pub[PK_SIG_PK];
        if (pk_b64_decode(PK_SERVER_PUBKEY_B64, srv_pub, sizeof(srv_pub)) != PK_SIG_PK) {
            fprintf(stderr, "loi: server pubkey nhung san khong hop le\n"); free(enc); return 1;
        }
        /* Nếu client có truyền --server-pubkey mà KHÁC key ghim -> nghi giả mạo, từ chối. */
        if (srv_pub_b64 && strcmp(srv_pub_b64, PK_SERVER_PUBKEY_B64) != 0) {
            fprintf(stderr, "           SERVER PUBKEY KHONG KHOP key ghim -> tu choi (nghi gia mao)\n");
            free(enc); return 7;
        }
        pk_entitlement ent;
        printf("[launcher] verify entitlement token (server)...\n");
        if (pk_entitlement_verify(ent_file, srv_pub, &ent) != 0) { free(enc); return 7; }

        /* a. product_id trong token phải khớp manifest */
        if (strcmp(ent.product_id, mi.product_id) != 0) {
            fprintf(stderr, "           TOKEN SAI PRODUCT: %s != %s\n", ent.product_id, mi.product_id);
            free(enc); return 7;
        }
        /* b. hardware binding: device_hash trong token phải khớp máy này */
        char hwid[PK_SHA256 * 2 + 1];
        if (pk_hardware_hash(hwid, sizeof(hwid)) != 0) { free(enc); return 1; }
        if (strcmp(ent.device_hash, hwid) != 0) {
            fprintf(stderr, "           HARDWARE BINDING SAI: token khong danh cho may nay\n");
            free(enc); return 7;
        }
        /* c. offline grace: now <= offline_until (so sánh chuỗi ISO-8601 UTC) */
        char now_iso[32];
        pk_iso8601_utc(now_iso, sizeof(now_iso));
        if (strcmp(now_iso, ent.offline_until) > 0) {
            fprintf(stderr, "           TOKEN HET HAN OFFLINE (den %s) - can online lai\n", ent.offline_until);
            free(enc); return 7;
        }
        printf("           OK  entitlement hop le (offline_until=%s)\n", ent.offline_until);
    } else if (has_flag(argc, argv, "--dev")) {
        /* Chế độ dev rõ ràng: chỉ dùng để test không cần server. */
        printf("[launcher] (--dev: BO QUA entitlement + hardware binding — chi dung de test)\n");
    } else {
        /* SẢN XUẤT: bắt buộc có entitlement token hợp lệ -> hardware binding luôn được áp.
         * Nếu không, payload key đứng một mình (vd trích từ .session.json copy sang máy khác)
         * vẫn KHÔNG chạy được app. */
        fprintf(stderr, "           THIEU --entitlement: can entitlement token hop le moi chay duoc.\n");
        free(enc); return 7;
    }

    /* 4. Payload key (tam: local) */
    unsigned char key[PK_KEYBYTES], nonce[PK_NONCEBYTES];
    if (load_payload_key(argc, argv, pkg, key) != 0) { free(enc); return 1; }
    if (pk_b64_decode(mi.nonce_b64, nonce, PK_NONCEBYTES) != PK_NONCEBYTES) {
        fprintf(stderr, "loi: nonce base64 sai\n"); free(enc); return 1;
    }

    /* 5. Giải mã */
    printf("[launcher] giai ma payload...\n");
    unsigned char *zip = malloc(enc_len);  /* plaintext <= enc_len */
    size_t zip_len = 0;
    if (!zip || pk_aes_decrypt(enc, enc_len, key, nonce, zip, &zip_len) != 0) {
        fprintf(stderr, "           GIAI MA THAT BAI (sai key hoac payload bi sua)\n");
        sodium_memzero(key, sizeof(key)); free(enc); free(zip); return 4;
    }
    sodium_memzero(key, sizeof(key));
    free(enc);
    printf("           OK  %zu byte\n", zip_len);

    /* 6. Giải nén ra thư mục tạm */
    char tmpdir[1024];
    if (pk_make_temp_dir(tmpdir, sizeof(tmpdir)) != 0) { free(zip); return 1; }
    printf("[launcher] giai nen ra: %s\n", tmpdir);
    if (pk_unzip_to_dir(zip, zip_len, tmpdir) != 0) {
        free(zip); pk_remove_dir_recursive(tmpdir); return 5;
    }
    free(zip);

    /* 7. Chạy entry */
    char entry_path[2048];
    snprintf(entry_path, sizeof(entry_path), "%s/%s", tmpdir, mi.entry);
    printf("[launcher] chay app: %s\n", mi.entry);
    printf("------------------------------------------\n");
    fflush(stdout);  /* day log launcher ra truoc khi app con in */
    int exit_code = 0;
    int run_rc = pk_run_and_wait(entry_path, tmpdir, &exit_code);
    printf("------------------------------------------\n");

    /* 8. Cleanup */
    printf("[launcher] don thu muc tam...\n");
    pk_remove_dir_recursive(tmpdir);

    if (run_rc != 0) return 6;
    printf("[launcher] app thoat voi ma %d. Xong.\n", exit_code);
    return exit_code;
}

#include "pk_crypto.h"
#include "pk_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>  /* AES-256-GCM (chay tren moi CPU, khong can AES-NI) */

static const char PEM_BEGIN[] = "-----BEGIN ED25519 PUBLIC KEY-----";
static const char PEM_END[]   = "-----END ED25519 PUBLIC KEY-----";

int pk_crypto_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "loi: khong khoi tao duoc libsodium\n");
        return -1;
    }
    /* AES-256-GCM dung OpenSSL (chay moi CPU); libsodium chi lo Ed25519/SHA-256/random. */
    return 0;
}

void pk_random_bytes(unsigned char *buf, size_t len) {
    randombytes_buf(buf, len);
}

int pk_aes_encrypt(const unsigned char *plain, size_t plen,
                   const unsigned char key[PK_KEYBYTES],
                   const unsigned char nonce[PK_NONCEBYTES],
                   unsigned char *out, size_t *out_len) {
    /* Layout out = ciphertext (plen byte) || tag (PK_ABYTES=16 byte) — combined mode. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1, len = 0;
    size_t total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PK_NONCEBYTES, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (EVP_EncryptUpdate(ctx, out, &len, plain, (int)plen) != 1) goto done;
    total = (size_t)len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) goto done;  /* GCM: len = 0 */
    total += (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PK_ABYTES, out + total) != 1) goto done;
    total += PK_ABYTES;

    *out_len = total;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int pk_aes_decrypt(const unsigned char *enc, size_t enc_len,
                   const unsigned char key[PK_KEYBYTES],
                   const unsigned char nonce[PK_NONCEBYTES],
                   unsigned char *out, size_t *out_len) {
    if (enc_len < PK_ABYTES) return -1;
    size_t clen = enc_len - PK_ABYTES;
    const unsigned char *tag = enc + clen;  /* 16 byte tag o cuoi */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1, len = 0;
    size_t total = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PK_NONCEBYTES, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (EVP_DecryptUpdate(ctx, out, &len, enc, (int)clen) != 1) goto done;
    total = (size_t)len;
    /* nap tag ky vong truoc khi finalize */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PK_ABYTES, (void *)tag) != 1) goto done;
    /* Final != 1 nghia la tag KHONG khop -> payload bi sua */
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1) goto done;
    total += (size_t)len;

    *out_len = total;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

void pk_sha256_hex(const unsigned char *data, size_t len, char *hex_out) {
    unsigned char digest[PK_SHA256];
    crypto_hash_sha256(digest, data, (unsigned long long)len);
    sodium_bin2hex(hex_out, PK_SHA256 * 2 + 1, digest, PK_SHA256);
}

void pk_sign_keypair(unsigned char pk[PK_SIG_PK], unsigned char sk[PK_SIG_SK]) {
    crypto_sign_keypair(pk, sk);
}

int pk_sign(const unsigned char *msg, size_t mlen,
            const unsigned char sk[PK_SIG_SK], unsigned char sig[PK_SIGBYTES]) {
    unsigned long long siglen = 0;
    if (crypto_sign_detached(sig, &siglen, msg, (unsigned long long)mlen, sk) != 0)
        return -1;
    return 0;
}

int pk_sign_verify(const unsigned char *msg, size_t mlen,
                   const unsigned char sig[PK_SIGBYTES],
                   const unsigned char pk[PK_SIG_PK]) {
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)mlen, pk) == 0 ? 0 : -1;
}

char *pk_b64_encode(const unsigned char *bin, size_t bin_len) {
    size_t cap = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char *out = malloc(cap);
    if (!out) return NULL;
    sodium_bin2base64(out, cap, bin, bin_len, sodium_base64_VARIANT_ORIGINAL);
    return out;
}

long pk_b64_decode(const char *b64, unsigned char *out, size_t out_cap) {
    size_t out_len = 0;
    if (sodium_base642bin(out, out_cap, b64, strlen(b64), NULL, &out_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return -1;
    return (long)out_len;
}

int pk_write_pubkey_pem(const char *path, const unsigned char pk[PK_SIG_PK]) {
    char *b64 = pk_b64_encode(pk, PK_SIG_PK);
    if (!b64) return -1;
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "%s\n%s\n%s\n", PEM_BEGIN, b64, PEM_END);
    free(b64);
    if (n <= 0) return -1;
    return pk_write_file(path, (const unsigned char *)buf, (size_t)n);
}

int pk_read_pubkey_pem(const char *path, unsigned char pk[PK_SIG_PK]) {
    unsigned char *raw = NULL;
    size_t len = 0;
    if (pk_read_file(path, &raw, &len) != 0) return -1;

    char *s = (char *)raw;
    char *start = strstr(s, PEM_BEGIN);
    char *end = strstr(s, PEM_END);
    if (!start || !end || end <= start) { free(raw); return -1; }
    start += strlen(PEM_BEGIN);

    /* gom base64 giữa 2 marker, bỏ khoảng trắng/xuống dòng */
    char b64[512];
    size_t j = 0;
    for (char *p = start; p < end && j < sizeof(b64) - 1; p++) {
        if (*p != '\n' && *p != '\r' && *p != ' ' && *p != '\t')
            b64[j++] = *p;
    }
    b64[j] = '\0';
    free(raw);

    long got = pk_b64_decode(b64, pk, PK_SIG_PK);
    return (got == PK_SIG_PK) ? 0 : -1;
}

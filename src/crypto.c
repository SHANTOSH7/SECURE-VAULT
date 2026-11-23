#include "sv.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SV_FILE_MAGIC "SVLT0001"
#define SV_HEADER_LEN (8 + SV_NONCE_LEN + 4)
#define SV_MAX_PLAINTEXT (4u * 1024u * 1024u)

static void put_u32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}
static uint32_t get_u32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
int crypto_random(unsigned char *out, size_t len) {
    return out && len <= INT_MAX && RAND_bytes(out, (int)len) == 1;
}
int crypto_derive(const char *password, const unsigned char *salt, uint32_t iterations,
                  unsigned char enc_key[32], unsigned char verify_key[32]) {
    unsigned char derived[SV_DERIVED_LEN];
    if (!password || !salt || iterations < 100000 || iterations > 5000000) return 0;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SV_SALT_LEN,
                          (int)iterations, EVP_sha256(), sizeof derived, derived) != 1) {
        platform_secure_zero(derived, sizeof derived); return 0;
    }
    memcpy(enc_key, derived, 32); memcpy(verify_key, derived + 32, 32);
    platform_secure_zero(derived, sizeof derived);
    return 1;
}
int crypto_make_verifier(const char *username, const unsigned char verify_key[32], unsigned char out[32]) {
    unsigned int len = 0;
    char msg[96];
    int n = snprintf(msg, sizeof msg, "SecureVault master verifier v1:%s", username);
    if (n < 0 || (size_t)n >= sizeof msg) return 0;
    return HMAC(EVP_sha256(), verify_key, 32, (const unsigned char *)msg, (size_t)n, out, &len) != NULL && len == 32;
}
int crypto_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    return a && b && CRYPTO_memcmp(a, b, n) == 0;
}
int crypto_encrypt(const char *username, const unsigned char key[32],
                   const unsigned char *plain, size_t plain_len,
                   unsigned char **file_data, size_t *file_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    unsigned char nonce[SV_NONCE_LEN], tag[SV_TAG_LEN];
    int out1 = 0, out2 = 0, aad_len = 0;
    size_t total;
    if (!username || !key || (!plain && plain_len) || !file_data || !file_len || plain_len > SV_MAX_PLAINTEXT || plain_len > INT_MAX) return 0;
    if (!crypto_random(nonce, sizeof nonce)) return 0;
    total = SV_HEADER_LEN + plain_len + SV_TAG_LEN;
    buf = (unsigned char *)malloc(total);
    if (!buf) return 0;
    memcpy(buf, SV_FILE_MAGIC, 8);
    memcpy(buf + 8, nonce, SV_NONCE_LEN);
    put_u32(buf + 8 + SV_NONCE_LEN, (uint32_t)plain_len);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto fail;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SV_NONCE_LEN, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, NULL, &aad_len, buf, SV_HEADER_LEN) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, NULL, &aad_len, (const unsigned char *)username, (int)strlen(username)) != 1) goto fail;
    if (plain_len && EVP_EncryptUpdate(ctx, buf + SV_HEADER_LEN, &out1, plain, (int)plain_len) != 1) goto fail;
    if (EVP_EncryptFinal_ex(ctx, buf + SV_HEADER_LEN + out1, &out2) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SV_TAG_LEN, tag) != 1) goto fail;
    memcpy(buf + SV_HEADER_LEN + (size_t)out1 + (size_t)out2, tag, SV_TAG_LEN);
    *file_data = buf; *file_len = SV_HEADER_LEN + (size_t)out1 + (size_t)out2 + SV_TAG_LEN;
    EVP_CIPHER_CTX_free(ctx); platform_secure_zero(nonce, sizeof nonce); platform_secure_zero(tag, sizeof tag);
    return 1;
fail:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    platform_secure_zero(nonce, sizeof nonce); platform_secure_zero(tag, sizeof tag);
    if (buf) { platform_secure_zero(buf, total); free(buf); }
    return 0;
}
int crypto_decrypt(const char *username, const unsigned char key[32],
                   const unsigned char *file_data, size_t file_len,
                   unsigned char **plain, size_t *plain_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *out = NULL;
    uint32_t clen;
    int n1 = 0, n2 = 0, aad_len = 0;
    const unsigned char *nonce, *cipher, *tag;
    if (!username || !key || !file_data || !plain || !plain_len || file_len < SV_HEADER_LEN + SV_TAG_LEN) return 0;
    if (memcmp(file_data, SV_FILE_MAGIC, 8) != 0) return 0;
    nonce = file_data + 8;
    clen = get_u32(file_data + 8 + SV_NONCE_LEN);
    if (clen > SV_MAX_PLAINTEXT || file_len != SV_HEADER_LEN + (size_t)clen + SV_TAG_LEN) return 0;
    cipher = file_data + SV_HEADER_LEN;
    tag = cipher + clen;
    out = (unsigned char *)malloc((size_t)clen + 1);
    if (!out) return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto fail;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SV_NONCE_LEN, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, NULL, &aad_len, file_data, SV_HEADER_LEN) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, NULL, &aad_len, (const unsigned char *)username, (int)strlen(username)) != 1) goto fail;
    if (clen && EVP_DecryptUpdate(ctx, out, &n1, cipher, (int)clen) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SV_TAG_LEN, (void *)tag) != 1) goto fail;
    if (EVP_DecryptFinal_ex(ctx, out + n1, &n2) != 1) goto fail;
    out[(size_t)n1 + (size_t)n2] = 0;
    *plain = out; *plain_len = (size_t)n1 + (size_t)n2;
    EVP_CIPHER_CTX_free(ctx); return 1;
fail:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (out) { platform_secure_zero(out, (size_t)clen + 1); free(out); }
    return 0;
}

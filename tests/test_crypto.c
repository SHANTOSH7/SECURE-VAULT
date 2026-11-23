#include "sv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *user = "crypto_test_user";
    const unsigned char message[] = "SecureVault authenticated encryption test";
    unsigned char key[32];
    unsigned char *encrypted = NULL, *decrypted = NULL;
    size_t encrypted_len = 0, decrypted_len = 0;
    int ok = 1;

    if (!crypto_random(key, sizeof key)) {
        fprintf(stderr, "FAIL: secure random generation\n"); return 1;
    }
    if (!crypto_encrypt(user, key, message, sizeof message, &encrypted, &encrypted_len)) {
        fprintf(stderr, "FAIL: AES-GCM encryption\n"); return 1;
    }
    if (!crypto_decrypt(user, key, encrypted, encrypted_len, &decrypted, &decrypted_len)) {
        fprintf(stderr, "FAIL: AES-GCM decryption\n"); ok = 0;
    } else if (decrypted_len != sizeof message || memcmp(decrypted, message, sizeof message) != 0) {
        fprintf(stderr, "FAIL: round-trip plaintext mismatch\n"); ok = 0;
    }
    if (decrypted) { platform_secure_zero(decrypted, decrypted_len); free(decrypted); decrypted = NULL; }

    if (ok) {
        encrypted[encrypted_len - 1] ^= 0x01;
        if (crypto_decrypt(user, key, encrypted, encrypted_len, &decrypted, &decrypted_len)) {
            fprintf(stderr, "FAIL: modified authentication tag was accepted\n"); ok = 0;
            platform_secure_zero(decrypted, decrypted_len); free(decrypted);
        }
    }
    if (encrypted) { platform_secure_zero(encrypted, encrypted_len); free(encrypted); }
    platform_secure_zero(key, sizeof key);
    if (!ok) return 1;
    puts("PASS: AES-256-GCM round trip and tamper detection");
    return 0;
}

#ifndef SV_H
#define SV_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SV_VERSION "1.0.0"
#define SV_MAX_USERS 128
#define SV_MAX_CREDS 500
#define SV_USER_MAX 32
#define SV_WEBSITE_MAX 127
#define SV_USERNAME_MAX 127
#define SV_PASSWORD_MAX 255
#define SV_CATEGORY_MAX 63
#define SV_NOTES_MAX 255
#define SV_SALT_LEN 16
#define SV_KEY_LEN 32
#define SV_DERIVED_LEN 64
#define SV_NONCE_LEN 12
#define SV_TAG_LEN 16
#define SV_PBKDF2_ITERATIONS 600000

#define SV_REGISTRY "data/users.dat"
#define SV_VAULT_DIR "data/vaults"
#define SV_BACKUP_DIR "backups"

typedef struct {
    char website[SV_WEBSITE_MAX + 1];
    char username[SV_USERNAME_MAX + 1];
    char password[SV_PASSWORD_MAX + 1];
    char category[SV_CATEGORY_MAX + 1];
    char notes[SV_NOTES_MAX + 1];
    int64_t updated_at;
} Credential;

typedef struct {
    Credential items[SV_MAX_CREDS];
    size_t count;
} Vault;

typedef struct {
    char username[SV_USER_MAX + 1];
    unsigned char salt[SV_SALT_LEN];
    unsigned char verifier[32];
    uint32_t iterations;
} UserRecord;

typedef struct {
    char username[SV_USER_MAX + 1];
    unsigned char enc_key[SV_KEY_LEN];
    unsigned char verify_key[SV_KEY_LEN];
    Vault vault;
    int authenticated;
} Session;

/* ui.c */
void ui_init(void);
void ui_clear(void);
void ui_banner(void);
void ui_message(const char *msg);
void ui_error(const char *msg);
void ui_success(const char *msg);
void ui_pause(void);
int ui_read_line(const char *prompt, char *out, size_t cap, int allow_empty);
int ui_read_int(const char *prompt, int min, int max, int *out);
int ui_read_secret(const char *prompt, char *out, size_t cap);
void ui_main_menu(void);
void ui_vault_menu(const char *username);

/* platform.c */
int platform_read_secret(const char *prompt, char *out, size_t cap);
int platform_clipboard_copy(const char *text);
void platform_secure_zero(void *p, size_t n);
int platform_mkdir(const char *path);
int platform_atomic_replace(const char *tmp, const char *dest);

/* crypto.c */
int crypto_random(unsigned char *out, size_t len);
int crypto_derive(const char *password, const unsigned char *salt, uint32_t iterations,
                  unsigned char enc_key[32], unsigned char verify_key[32]);
int crypto_make_verifier(const char *username, const unsigned char verify_key[32], unsigned char out[32]);
int crypto_equal(const unsigned char *a, const unsigned char *b, size_t n);
int crypto_encrypt(const char *username, const unsigned char key[32],
                   const unsigned char *plain, size_t plain_len,
                   unsigned char **file_data, size_t *file_len);
int crypto_decrypt(const char *username, const unsigned char key[32],
                   const unsigned char *file_data, size_t file_len,
                   unsigned char **plain, size_t *plain_len);

/* storage.c */
int storage_init(void);
int storage_user_exists(const char *username);
int storage_add_user(const UserRecord *user);
int storage_update_user(const UserRecord *user);
int storage_find_user(const char *username, UserRecord *out);
int storage_vault_path(const char *username, char *out, size_t cap);
int storage_save_vault(const char *username, const unsigned char key[32], const Vault *vault);
int storage_load_vault(const char *username, const unsigned char key[32], Vault *vault);
int storage_backup(const char *username, char *out_path, size_t cap);
int storage_restore(const char *username, const unsigned char key[32], const char *backup_path);

/* auth.c */
int auth_register(Session *session);
int auth_login(Session *session);
void auth_logout(Session *session);
int auth_change_master(Session *session);

/* vault.c */
void vault_menu(Session *session);
int vault_add(Session *session);
void vault_list(const Vault *vault, int reveal_passwords);
int vault_search(const Vault *vault, const char *term);
int vault_update(Session *session);
int vault_delete(Session *session);

/* password.c */
int password_generate(char *out, size_t length, int use_upper, int use_lower,
                      int use_digits, int use_symbols);
int password_strength(const char *password);
void password_audit(const Vault *vault);
void password_dashboard(const Vault *vault);

#endif

# Security and Design Notes

- AES-256-GCM protects the serialized vault and provides authentication/integrity for the encrypted payload.
- The file magic, nonce and ciphertext-length header plus the username are supplied as GCM additional authenticated data.
- Each vault save generates a fresh 96-bit nonce using OpenSSL `RAND_bytes`.
- PBKDF2-HMAC-SHA-256 uses a per-user 16-byte random salt and 600,000 iterations. A 64-byte output is split into independent 32-byte encryption and verifier keys.
- Master-password verification uses a domain-separated HMAC-SHA-256 verifier and constant-time comparison. The master password is not stored.
- Linux data directories are set to mode 0700 and registry, temporary, vault and backup files to mode 0600 where created by the application.
- Vault and registry updates use temporary files and atomic replacement. New user registration appends a registry record after creating the encrypted empty vault.
- Backups are copies of encrypted vault files; restore authenticates and parses the backup before replacing the current vault.
- Password strength is a local heuristic and duplicate checks compare values only within the currently unlocked user's vault.
- Clipboard contents are not automatically cleared. The application tells the user to clear them manually after use.
- Login attempts are limited to five failures per application run. This is not persistent account lockout.
- This educational application has not undergone independent security review. It does not protect against a compromised OS, malware, keyloggers, privileged memory inspection, concurrent process races, or insecure backups copied elsewhere.

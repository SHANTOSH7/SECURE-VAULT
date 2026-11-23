# SecureVault Architecture

## Components

- `main.c`: application lifecycle and login-attempt cap.
- `auth.c`: registration, authentication, logout and master-password rotation.
- `crypto.c`: PBKDF2-HMAC-SHA-256, HMAC verifier, AES-256-GCM and secure random values.
- `storage.c`: private directories, registry, versioned serialization, encrypted vault I/O and encrypted backups.
- `vault.c`: credential CRUD, search, clipboard, backup/restore menu.
- `password.c`: password generation, heuristic strength, duplicate audit and dashboard.
- `ui.c`: monochrome terminal interaction and validated line input.
- `platform/platform.c`: terminal password masking, clipboard, directory creation, atomic replacement and secure zeroing.

## Key derivation

PBKDF2-HMAC-SHA-256 derives 64 bytes from the master password and a per-user 16-byte random salt. The first 32 bytes are the AES key; the second 32 bytes are used only for the HMAC password verifier. The current iteration count is 600,000 and is stored with the user's registry record.

The verifier is HMAC-SHA-256 over a domain-separated string containing the username. The master password itself is never written to disk.

## Vault file format

The encrypted vault file consists of:

1. 8-byte format magic (`SVLT0001`).
2. 12-byte fresh GCM nonce.
3. 4-byte big-endian ciphertext length.
4. Ciphertext.
5. 16-byte GCM authentication tag.

The complete header and username are supplied as GCM additional authenticated data. A modified header, username, ciphertext or tag causes decryption to fail.

The plaintext payload is a versioned binary serialization. Strings are length-prefixed; raw C structs are not written to disk, avoiding compiler padding and ABI differences.

## Persistence

Each save serializes the in-memory vault, encrypts it, writes a temporary file, flushes it, and atomically replaces the previous vault where the platform supports that operation. Backups are copies of the encrypted vault bytes and are validated by authenticated decryption before restore.

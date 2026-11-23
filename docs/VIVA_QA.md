# SecureVault Viva Questions and Answers

## 1. What is SecureVault?
SecureVault is a command-line password manager written in C. It allows local users to manage credentials in separate encrypted vault files.

## 2. Why did you choose this project?
It combines core C programming requirements such as structures, functions, arrays, pointers and file handling with practical cybersecurity topics such as authentication, key derivation and authenticated encryption.

## 3. Which programming language is used?
C (C11). OpenSSL is used as an external cryptographic library; the application logic is implemented in C.

## 4. How is data stored permanently?
Credential records are serialized into a binary payload, encrypted using AES-256-GCM, and saved to a per-user `.svlt` file. The application decrypts the file after successful login.

## 5. What is AES-256-GCM?
It is an authenticated encryption mode using a 256-bit AES key. It provides confidentiality and integrity/authenticity through an authentication tag.

## 6. Why use a nonce?
GCM requires a unique nonce for each encryption under the same key. SecureVault generates a fresh 96-bit nonce for every vault save using OpenSSL's random generator.

## 7. What is PBKDF2?
PBKDF2 is a password-based key derivation function. It applies repeated HMAC operations with a salt and iteration count to make password guessing more expensive.

## 8. Is the master password stored?
No. The master password is used to derive separate encryption and verification keys. Only a keyed verifier, salt and KDF parameters are stored in the user registry.

## 9. What is the difference between hashing and encryption?
Hashing is designed to be one-way. Encryption is reversible when the correct key is available. SecureVault uses a keyed HMAC verifier for master-password checking and AES-GCM encryption for credentials.

## 10. What is file handling?
File handling allows a program to create, read, write and update data stored on disk. SecureVault uses binary files for its encrypted vaults and a text registry for non-secret account metadata.

## 11. What are CRUD operations?
Create, Read, Update and Delete. SecureVault implements these operations for credential records.

## 12. How does the application detect duplicate passwords?
It compares each credential password with earlier credential passwords in the authenticated user's in-memory vault and reports reuse without printing the password.

## 13. How does backup work?
A backup is a copy of the encrypted vault file. During restore, SecureVault decrypts and validates the backup using AES-GCM before replacing the current vault.

## 14. What happens if a vault file is modified?
AES-GCM tag verification fails. SecureVault refuses to release the decrypted plaintext.

## 15. What are the limitations?
It is an educational prototype, not independently security-audited. It does not provide persistent lockout, concurrent file locking, hardware-backed keys, remote breach checks or protection against a compromised operating system.

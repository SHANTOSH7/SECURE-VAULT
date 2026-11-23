# SecureVault Demonstration Guide

Use disposable test credentials only. Do not demonstrate with personal or production passwords.

1. Start SecureVault from its project root using `./securevault`.
2. Register a new user with a strong master password.
3. Show that the master password is not echoed while typing.
4. Add two sample website credentials. Reuse a sample password once to demonstrate duplicate detection.
5. List the credentials and show that passwords are masked by default.
6. Select one credential and explicitly approve revealing its password on screen.
7. Search for a website or category.
8. Update a credential and delete a disposable record.
9. Generate a random password of a selected length.
10. Run the password-strength checker, duplicate report, dashboard and audit.
11. Create an encrypted backup.
12. Log out and exit. Restart the program and log in again to demonstrate persistence.
13. Register a second user and show that the second user's vault is separate.
14. Explain the AES-256-GCM, PBKDF2 and file-handling design using `docs/ARCHITECTURE.md`.

Suggested viva demonstration: show the source modules, explain the C structures and file serialization, then explain how the GCM authentication tag detects tampering.

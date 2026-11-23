# SecureVault Test Plan

## Automated cryptography test

Run `make test`. It verifies:

- Secure random generation.
- AES-256-GCM encrypt/decrypt round trip.
- Rejection of a modified authentication tag.

## Manual application tests

1. Register a user with a 12+ character master password containing uppercase, lowercase, digit and symbol.
2. Attempt to register the same username again; it must be rejected.
3. Log in with an incorrect master password; authentication must fail.
4. Log in correctly; the vault must open.
5. Add a credential, log out, restart the application and log in again; the credential must persist.
6. List credentials; passwords should be masked by default.
7. Search, reveal a selected password only after confirmation, and copy a password if a supported clipboard utility is installed.
8. Update and delete credentials; verify changes after relogin.
9. Generate a password and verify the selected length and character classes.
10. Run dashboard and audit; verify weak and duplicate detection.
11. Create an encrypted backup, modify the vault, restore the backup and verify the prior contents return.
12. Change the master password; old password should fail and new password should work.
13. Copy a vault file, alter a byte, and attempt to load the altered file; authentication must fail.
14. Create a second user and verify the first user's credentials are not visible in the second vault.

Do not test with real production passwords or real high-value credentials. Use disposable test accounts.

# SecureVault

SecureVault is a C11 command-line password manager with per-user encrypted vault files. It uses OpenSSL 3.x, PBKDF2-HMAC-SHA-256 for master-password key derivation, and AES-256-GCM for authenticated vault encryption.

## Features

- Multiple local user accounts with separate encrypted vault files.
- Master-password verification without storing the master password.
- AES-256-GCM authenticated encryption; each save uses a fresh random 96-bit nonce.
- Credential add, list, search, update and delete.
- Cryptographically random password generation.
- Standalone password-strength checker, duplicate-password report, dashboard and security audit.
- Encrypted vault backup and authenticated restore.
- Linux clipboard support through `wl-copy` or `xclip`; Windows clipboard through Win32 APIs.
- Monochrome terminal interface.

## Requirements

- C11 compiler (GCC recommended).
- OpenSSL 3.x development headers and library.
- `pkg-config` and GNU Make on Linux.
- Optional Linux clipboard utility: `wl-clipboard` (Wayland) or `xclip` (X11).

On Parrot OS / Debian / Ubuntu:

```sh
sudo apt update
sudo apt install build-essential gcc make pkg-config libssl-dev openssl
# Optional clipboard support:
sudo apt install wl-clipboard xclip
```

## Install on Omarchy (Arch Linux)

Omarchy is Arch-based, so install the compiler, Make, `pkg-config`, and OpenSSL development files with `pacman`. Install a clipboard helper if you want clipboard support (Wayland is the usual Omarchy setup):

```sh
sudo pacman -S --needed base-devel gcc make pkgconf openssl git wl-clipboard
```

Clone the repository, build SecureVault, and start it from its project directory:

```sh
git clone https://github.com/SHANTOSH7/SECURE-VAULT.git
cd SECURE-VAULT
make
./securevault
```

On first launch, choose **Create account**, create a username, and set a master password. SecureVault stores its `data/` directory relative to the current working directory, so launch it from `SECURE-VAULT/` each time. To update a cloned checkout later, run `git pull` from that directory and rebuild with `make`.

If you use X11 instead of Wayland, install `xclip` in place of `wl-clipboard`:

```sh
sudo pacman -S --needed xclip
```

## Build and run on other Linux distributions

Install a C11 compiler, GNU Make, `pkg-config`, and OpenSSL 3.x development files using your distribution's package manager. On Debian-based systems, for example:

```sh
sudo apt update
sudo apt install build-essential gcc make pkg-config libssl-dev openssl
# Optional clipboard support:
sudo apt install wl-clipboard xclip
```

Then, from the project root:

```sh
make
./securevault
```

## Build on Windows

Install MinGW-w64 GCC and an OpenSSL 3.x development package built for the same architecture/toolchain. Ensure `libcrypto` and its headers are discoverable by GCC. From the project root, run:

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Iinclude src/main.c src/ui.c src/auth.c src/crypto.c src/storage.c src/vault.c src/password.c src/platform.c -o securevault.exe -lcrypto -luser32 -lkernel32
.\securevault.exe
```

The OpenSSL DLLs must be available on `PATH` at runtime. The Linux Makefile's `pkg-config` discovery is not used for the Windows command above.

## Automated cryptography test

On Linux, run `make test` to verify AES-GCM round-trip behavior and tamper detection.

## First run

1. Select **Create account**.
2. Choose a username of 3–32 letters, digits, underscores or hyphens.
3. Choose a master password of at least 12 characters containing uppercase, lowercase, a digit and a symbol.
4. Log in and add credentials.

Data is stored relative to the current working directory in `data/`. Always launch the application from the project root so it uses the intended data directory.

## Storage format

- `data/users.dat` stores usernames, PBKDF2 iteration counts, random salts and HMAC-based password verifiers. It does not store master passwords or account credentials.
- `data/vaults/<username>.svlt` stores an authenticated-encrypted serialized vault.
- `backups/` stores byte-for-byte copies of encrypted vault files.

The vault uses AES-256-GCM with a new random 96-bit nonce for each save. The authenticated additional data binds the file header and username to the ciphertext. PBKDF2-HMAC-SHA-256 derives separate 32-byte encryption and verification keys from the master password using a per-user 16-byte salt and 600,000 iterations.

## Important security notes and limitations

- This is an educational local password manager, not a professionally audited password manager. Do not use it as the sole store for high-value production secrets.
- The application allows at most five failed login attempts per application run. This is a basic local safeguard, not a persistent account lockout; restarting the application resets the counter. The application cannot protect a vault while it is unlocked from malware, keyloggers, memory inspection by a privileged local user, or a compromised operating system.
- Linux clipboard integration requires `wl-copy` or `xclip`; copied values remain in the clipboard until replaced or cleared manually. Avoid copying secrets on shared systems.
- The password audit is a local heuristic. It does not query breach databases and cannot establish whether a password has been exposed.
- PBKDF2 is selected for its direct OpenSSL availability and cross-platform deployment simplicity. Argon2id is a stronger memory-hard alternative but requires an additional dependency.
- The registry is a local file. This implementation does not provide OS-account isolation, file locking for concurrent application instances, or a hardware-backed key store. Protect the project data directory with OS permissions.
- Keep encrypted backups in a separate secure location. A backup is only useful if you retain the correct master password.

## Project layout

```text
SecureVault/
├── include/sv.h
├── src/
│   ├── main.c
│   ├── ui.c
│   ├── auth.c
│   ├── crypto.c
│   ├── storage.c
│   ├── vault.c
│   ├── password.c
│   └── platform/platform.c
├── data/vaults/
├── backups/
├── tests/
├── docs/
├── Makefile
└── README.md
```

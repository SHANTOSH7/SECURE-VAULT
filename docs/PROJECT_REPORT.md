# SECUREVAULT — Mini Project Report

## Abstract

SecureVault is a command-line password manager implemented in C. It demonstrates file handling, structures, modular programming, authentication, cryptographic key derivation, authenticated encryption, credential management and password-security analysis. Each registered user receives an independent encrypted vault stored locally.

## Problem Statement

People often reuse weak passwords or store credentials in unprotected notes. SecureVault demonstrates how a local application can organize credentials and protect stored vault data with authenticated encryption.

## Objectives

- Implement a command-based application in C.
- Demonstrate add, view, search, modify, delete and analysis operations.
- Persist data using files.
- Separate users into independent vaults.
- Derive cryptographic keys from a master password.
- Encrypt vault contents and detect unauthorized modification.
- Provide password generation, strength checks, duplicate detection, dashboard, audit and encrypted backups.

## Software Requirements

- C11 compiler (GCC recommended).
- OpenSSL 3.x development library.
- GNU Make and pkg-config on Linux.
- Optional `wl-copy` or `xclip` for Linux clipboard integration.

## Concepts Demonstrated

- Structures and arrays for credential records.
- Functions and modular source files.
- Pointers and dynamic memory allocation for serialization and cryptographic buffers.
- File handling for user metadata, encrypted vaults and backups.
- Searching and duplicate detection.
- Input validation and error handling.
- OpenSSL PBKDF2, HMAC, random number generation and AES-GCM APIs.

## Conclusion

SecureVault combines core C programming concepts with practical cybersecurity ideas. It demonstrates persistent file storage, multi-user vault separation, authenticated encryption and local password analysis. It is an educational prototype and requires independent security review before any production use.

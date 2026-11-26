# QuantumVault: Post-Quantum Cryptography (PQC) Local Filesystem

## 1. Project Overview

QuantumVault is an educational project exploring a Linux-based virtual
filesystem designed to protect files using post-quantum cryptography.

The intended system will encrypt files before storing them on the physical
filesystem and transparently decrypt them when authorized users read them.

The current development provides separate working prototypes for
post-quantum cryptographic operations and a writable Rust/FUSE filesystem.
Full integration is future work.

## 2. Project Objectives

- Explore post-quantum key establishment using ML-KEM-768.
- Use AES-256-GCM for authenticated encryption.
- Explore digital signatures using ML-DSA.
- Develop a Linux virtual filesystem using Rust and FUSE.
- Integrate cryptographic operations through C and Rust FFI.
- Develop secure key handling and command-line functionality.

## 3. Technology Stack

- C
- Rust
- OpenSSL
- ML-KEM-768 (FIPS 203)
- HKDF-SHA256
- AES-256-GCM
- FUSE
- Linux / Kali Linux under WSL2

Note: OpenSSL was used for the working cryptographic demonstrations.
The planned liboqs build was not completed successfully.

## 4. Implemented Features

### Cryptographic Component

- ML-KEM-768 key generation, encapsulation and decapsulation demonstration.
- AES-256-GCM encryption and decryption demonstration.
- Integrated ML-KEM-768 shared-secret establishment.
- HKDF-SHA256 key derivation.
- AES-256-GCM authenticated encryption and decryption.
- Authentication-tag tamper detection.

### Filesystem Component

- Rust-based FUSE virtual filesystem prototype.
- Directory listing.
- Virtual file reading and writing.
- Existing file content replacement.
- File-size handling.

The current FUSE filesystem maintains file content in memory.

## 5. Features Planned for Future Development

- Transparent encryption of files through the FUSE filesystem.
- Transparent decryption during file reads.
- Persistent encrypted file storage.
- Rust-to-C integration using FFI.
- ML-DSA digital signature generation and verification.
- Persistent cryptographic key management.
- Master-password-based access control.
- Complete command-line interface.

## 6. Project Structure

```text
QuantumVault-group/
├── src/
│   ├── c_crypto/
│   └── rust_fs/
├── include/
├── tests/
├── docs/
│   ├── project_architecture.md
│   ├── development_log.md
│   ├── week_1.md
│   ├── week_2.md
│   ├── cryptography.md
│   ├── fuse_filesystem.md
│   ├── testing.md
│   ├── limitations_and_future_work.md
│   └── contributions.md
├── scripts/
└── README.md

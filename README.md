# QuantumVault: Post-Quantum Cryptography (PQC) Local Filesystem

## Project Overview

QuantumVault is a Linux-based encrypted virtual filesystem designed to protect files using post-quantum cryptographic algorithms.

Files written through the mounted filesystem will be encrypted before being stored on the physical filesystem. Authorized reads will transparently decrypt the files.

## Project Objectives

- Implement post-quantum key establishment using ML-KEM-768.
- Use AES-256-GCM for authenticated file encryption.
- Implement digital signatures using ML-DSA.
- Develop a Linux virtual filesystem using Rust and FUSE.
- Integrate cryptographic operations through C and Rust FFI.
- Implement secure key handling and a command-line interface.

## Technology Stack

- C
- Rust
- liboqs
- ML-KEM-768 (FIPS 203)
- ML-DSA (FIPS 204)
- AES-256-GCM
- FUSE
- Linux

## Project Structure

```text
QuantumVault-group/
├── src/
│   ├── c_crypto/
│   └── rust_fs/
├── include/
├── tests/
├── docs/
├── scripts/
└── README.md
```

## Development Plan

1. Set up the cryptographic library and verify ML-KEM-768.
2. Develop a basic Rust/FUSE filesystem.
3. Integrate C cryptographic functions with Rust.
4. Implement transparent authenticated file encryption and decryption.
5. Add ML-DSA digital signatures.
6. Implement secure key management and CLI functionality.
7. Test and document the complete system.

## Project Status

Initial repository structure created. Development and testing are in progress.

## Security Note

This project is intended for educational and research purposes. Security claims will depend on implementation, testing and review.

# QuantumVault – Development Log

This log records the development milestones reflected in the project's
Git history and implemented source code.

## Milestone 1 – Repository Setup

Git commit: `c7b76e3` – Initial commit

- Started the QuantumVault project repository.

## Milestone 2 – Project Structure and Documentation

Git commit: `9eb157c` – Add QuantumVault project documentation and structure

- Added the initial project README.
- Established the project directory structure.

## Milestone 3 – Rust/FUSE Filesystem Starter

Git commit: `b01cbbd` – Add Rust FUSE filesystem starter

- Added the Rust FUSE filesystem project.
- Established the initial filesystem implementation.

## Milestone 4 – Writable FUSE Filesystem

Git commit: `6a50dbc` – Implement writable FUSE filesystem with file resizing

- Implemented writable virtual file operations.
- Added file-size resizing support.
- Tested reading and writing through the mounted filesystem.

## Milestone 5 – C Cryptography Demonstrations

Git commit: `c3cc0a4` – Add ML-KEM-768 and AES-256-GCM C demonstrations

- Added an ML-KEM-768 key establishment demonstration.
- Added an AES-256-GCM encryption and decryption demonstration.
- Verified successful cryptographic operations using OpenSSL.

## Milestone 6 – Generated Binary Exclusion

Git commit: `5331ebd` – Ignore generated QuantumVault C binaries

- Updated Git ignore rules to avoid tracking generated executables.

## Milestone 7 – Integrated Cryptographic Demonstration

Git commit: `244ce8d` – Integrate ML-KEM, HKDF and AES-GCM encryption

- Combined ML-KEM-768 shared-secret establishment with HKDF-SHA256.
- Derived an AES-256 key from the shared secret.
- Demonstrated AES-256-GCM encryption and decryption.
- Verified authentication and rejection of a modified authentication tag.
- Cleaned sensitive key and shared-secret buffers.

## Current Development Status

The project currently has separate C cryptographic demonstrations and a
writable Rust/FUSE filesystem prototype.

The cryptographic engine is not yet integrated into the FUSE filesystem.
Persistent encrypted file storage, Rust-to-C FFI, ML-DSA signatures and
persistent key management remain future development tasks.

## Record-Keeping Note

This log describes milestones supported by the current Git history and
implementation. It does not assign unverified dates or claim that planned
features have been completed.

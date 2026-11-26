# Week 2 – Filesystem and Cryptography Implementation

## Objective

Develop the writable Rust/FUSE prototype and demonstrate the core
cryptographic operations required by QuantumVault.

## 1. Rust/FUSE Filesystem

Implemented a writable virtual filesystem using Rust and the `fuser` crate.

Implemented operations include:

- File lookup and attribute retrieval.
- Directory listing.
- Opening and reading a virtual file.
- Writing data to a virtual file.
- Creating the virtual file `hello.txt`.
- Resizing file content through `setattr()`.

### Testing Performed

- Mounted the filesystem in Kali Linux under WSL2.
- Created and read `hello.txt` through the mount point.
- Wrote new content and verified the updated content.
- Checked the file listing and reported file size.

### Limitation

The filesystem stores content in an in-memory `Mutex<Vec<u8>>`.
It does not currently provide persistent or encrypted storage.

## 2. ML-KEM-768 Demonstration

Created a C demonstration using OpenSSL EVP APIs.

Verified:
- ML-KEM-768 key generation.
- Encapsulation.
- Decapsulation.
- Equality of the resulting shared secrets.

Observed result: all four operations completed successfully.

## 3. AES-256-GCM Demonstration

Created a separate C demonstration using OpenSSL EVP APIs.

Verified:
- Random key and nonce generation.
- AES-256-GCM encryption.
- AES-256-GCM decryption.
- Authentication-tag verification.
- Recovery of the original plaintext.

Observed result: encryption, decryption and authentication verification
completed successfully.

## 4. Integrated Cryptographic Demonstration

Created `src/c_crypto/quantumvault_crypto.c` to demonstrate a combined
cryptographic workflow:

1. Generate an ML-KEM-768 key pair.
2. Encapsulate and decapsulate a shared secret.
3. Verify the shared secrets match.
4. Derive a 256-bit AES key using HKDF-SHA256.
5. Encrypt a test message using AES-256-GCM.
6. Decrypt and verify the original message.
7. Modify the authentication tag and confirm that tampering is rejected.

Observed result:
- ML-KEM-768 shared secret: SUCCESS
- HKDF-SHA256 AES key derivation: SUCCESS
- AES-256-GCM encryption: SUCCESS
- AES-256-GCM authentication: SUCCESS
- AES-256-GCM tamper detection: SUCCESS

## 5. Repository Evidence

- `6a50dbc` – Implement writable FUSE filesystem with file resizing
- `c3cc0a4` – Add ML-KEM-768 and AES-256-GCM C demonstrations
- `5331ebd` – Ignore generated QuantumVault C binaries
- `244ce8d` – Integrate ML-KEM, HKDF and AES-GCM encryption

## 6. Current Outcome

The writable FUSE prototype and C cryptographic demonstrations were
implemented and tested separately.

The integrated C demonstration proves the cryptographic workflow for a
test message. It is not yet connected to the FUSE filesystem.

## 7. Pending Work

- Integrate C cryptographic operations with Rust through FFI.
- Encrypt and decrypt actual files through FUSE.
- Implement persistent encrypted storage and key management.
- Implement ML-DSA digital signatures.
- Perform further security and functional testing.

# QuantumVault – Limitations and Future Work

## 1. Current Implementation

The project currently contains two separately tested components:

1. C-based cryptographic demonstrations using OpenSSL.
2. A writable Rust-based virtual filesystem using FUSE.

The integrated C cryptography demonstration combines ML-KEM-768,
HKDF-SHA256 and AES-256-GCM.

## 2. Implementation Limitations

The following features are not yet implemented:

- Transparent encryption of files written through the FUSE filesystem.
- Transparent decryption when reading files through FUSE.
- Persistent encrypted file storage.
- Integration between the Rust filesystem and C cryptographic code.
- Rust-to-C Foreign Function Interface (FFI).
- ML-DSA digital signature generation and verification.
- Persistent and secure cryptographic key management.
- Master-password-based access control.
- A complete command-line interface.

## 3. Cryptographic Limitations

The cryptographic demonstrations use OpenSSL's available ML-KEM-768
implementation.

The original liboqs build was not completed successfully in the
development environment. OpenSSL was used for the working demonstrations.

The current demonstrations are educational prototypes and have not
undergone independent security auditing.

## 4. Filesystem Limitations

The Rust/FUSE filesystem currently provides basic virtual file operations.

Its file content is maintained in memory. It does not yet encrypt data
before writing to physical storage or preserve file content after
unmounting.

Timestamp modification operations are also not fully implemented.

## 5. Future Work

The following improvements are planned:

1. Integrate the C cryptographic engine with the Rust filesystem using FFI.
2. Encrypt file contents before physical storage.
3. Decrypt file contents transparently during read operations.
4. Implement persistent encrypted storage.
5. Add ML-DSA digital signatures.
6. Improve cryptographic key generation, storage and memory protection.
7. Implement master-password-based key access.
8. Develop a user-friendly command-line interface.
9. Add automated tests for filesystem and cryptographic integration.
10. Evaluate performance and security after integration.

## 6. Conclusion

QuantumVault has established a foundation through separate cryptographic
demonstrations and a writable FUSE filesystem prototype.

The next development stage is to integrate these components into a
complete encrypted virtual filesystem.

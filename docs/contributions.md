# QuantumVault – Individual Contributions

## 1. Contributor

Name: Garima Verma

Project: QuantumVault – Post-Quantum Cryptography (PQC) Local Filesystem

## 2. Development Contributions

The following work was completed as part of the project development:

### Documentation
- Created project architecture documentation.
- Maintained the development log.
- Prepared Week 1 and Week 2 progress records.
- Documented the cryptographic design and implementation.
- Documented the Rust/FUSE filesystem.
- Recorded testing procedures and results.
- Documented implementation limitations and future work.

### Cryptographic Implementation
- Worked on C-based ML-KEM-768 demonstration using OpenSSL.
- Worked on AES-256-GCM encryption and decryption demonstration.
- Developed an integrated cryptographic demonstration combining
  ML-KEM-768, HKDF-SHA256 and AES-256-GCM.
- Tested successful encryption, decryption and authentication-tag
  tamper detection.

### Filesystem Implementation
- Worked on a Rust-based FUSE virtual filesystem.
- Implemented basic virtual file operations, including listing,
  reading, writing and replacing file content.
- Tested the writable filesystem prototype.

### Repository Management
- Worked on the project Git branch.
- Maintained project files and documentation.
- Created and pushed project commits.
- Configured SSH-based Git commit signing.

## 3. Work Not Yet Completed

The following tasks remain future development work:
- Integration of the Rust filesystem with the C cryptographic engine.
- Transparent encryption and decryption of filesystem data.
- Persistent encrypted storage.
- ML-DSA digital signature implementation.
- Complete secure key management.

## 4. Contribution Summary

The contributions establish separate working prototypes for
post-quantum cryptographic operations and a writable FUSE filesystem,
along with project documentation and repository maintenance.

A complete encrypted virtual filesystem remains a future development goal.

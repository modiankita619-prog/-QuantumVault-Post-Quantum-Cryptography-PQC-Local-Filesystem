# QuantumVault – Cryptography Implementation

## 1. Overview

QuantumVault uses C demonstrations built with OpenSSL to explore
post-quantum key establishment and authenticated encryption.

The current implementation consists of separate demonstrations and an
integrated fixed-message proof of concept.

## 2. ML-KEM-768

Standard: FIPS 203

Purpose: Establish a shared secret between two parties using a
post-quantum key encapsulation mechanism.

Implemented operations:
- Key-pair generation.
- Encapsulation.
- Decapsulation.
- Shared-secret comparison.

Test result:
ML-KEM-768 key generation, encapsulation, decapsulation and shared-secret
verification completed successfully.

## 3. HKDF-SHA256

Purpose: Derive a symmetric encryption key from the ML-KEM shared secret.

The integrated demonstration uses HKDF with SHA-256 to derive a
32-byte key suitable for AES-256.

Test result:
HKDF-SHA256 AES key derivation completed successfully.

## 4. AES-256-GCM

Purpose: Provide authenticated symmetric encryption.

The demonstration uses:
- A 256-bit encryption key.
- A 12-byte nonce.
- A 16-byte authentication tag.

Implemented operations:
- Encryption of a test message.
- Decryption of the encrypted message.
- Authentication-tag verification.
- Rejection of a modified authentication tag.

Test result:
AES-256-GCM encryption, decryption and authentication completed
successfully. A modified authentication tag was rejected.

## 5. Integrated Cryptographic Workflow

Source file: `src/c_crypto/quantumvault_crypto.c`

The integrated demonstration performs these steps:

1. Generate an ML-KEM-768 key pair.
2. Encapsulate a shared secret.
3. Decapsulate the shared secret.
4. Compare the two shared-secret values.
5. Derive a 32-byte AES key using HKDF-SHA256.
6. Generate a fresh nonce.
7. Encrypt a fixed test message using AES-256-GCM.
8. Decrypt and compare the original message.
9. Modify the authentication tag and verify that decryption fails.
10. Clean sensitive buffers.

## 6. Recorded Test Output

The integrated program produced the following successful results:

- ML-KEM-768 shared secret: SUCCESS
- HKDF-SHA256 AES key derivation: SUCCESS
- AES-256-GCM encryption: SUCCESS
- AES-256-GCM authentication: SUCCESS
- AES-256-GCM tamper detection: SUCCESS (modified tag rejected)

## 7. Compilation

From the repository root:

```bash
gcc -Wall -Wextra -O0 src/c_crypto/mlkem_demo.c -o src/c_crypto/mlkem_demo -lcrypto

gcc -Wall -Wextra -O0 src/c_crypto/aes_gcm_demo.c -o src/c_crypto/aes_gcm_demo -lcrypto

gcc -Wall -Wextra -O0 src/c_crypto/quantumvault_crypto.c -o src/c_crypto/quantumvault_crypto -lcrypto

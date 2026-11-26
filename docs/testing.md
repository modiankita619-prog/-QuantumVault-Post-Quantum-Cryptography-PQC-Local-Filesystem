# QuantumVault – Testing and Results

## 1. Testing Environment

- Operating system: Kali Linux under WSL2
- Compiler: GCC
- Cryptographic library: OpenSSL
- Programming languages: C and Rust
- Filesystem interface: FUSE

## 2. ML-KEM-768 Test

Test objective: Verify post-quantum shared-secret establishment.

Operations tested:
- Key generation
- Encapsulation
- Decapsulation
- Shared-secret comparison

Recorded result: All operations completed successfully.

## 3. AES-256-GCM Test

Test objective: Verify authenticated encryption and decryption.

Operations tested:
- Random key generation
- Random nonce generation
- Encryption
- Decryption
- Authentication verification

Recorded result: Encryption and decryption succeeded, and the original
message was recovered.

## 4. Integrated Cryptography Test

Test objective: Verify the combined ML-KEM, HKDF and AES-GCM workflow.

Operations tested:
- ML-KEM shared-secret establishment
- HKDF-SHA256 key derivation
- AES-256-GCM encryption
- AES-256-GCM decryption
- Authentication-tag tamper detection

Recorded output:

- ML-KEM-768 shared secret: SUCCESS
- HKDF-SHA256 AES key derivation: SUCCESS
- AES-256-GCM encryption: SUCCESS
- AES-256-GCM authentication: SUCCESS
- AES-256-GCM tamper detection: SUCCESS (modified tag rejected)

## 5. FUSE Filesystem Test

Test objective: Verify basic virtual file operations.

Operations tested:
- Mounting the filesystem
- Listing the mounted directory
- Writing to `hello.txt`
- Reading file content
- Replacing existing content
- Checking file size

Recorded test messages:

`QuantumVault writable filesystem test`

`Second QuantumVault test`

The expected content was successfully read from the mounted virtual file.

## 6. Test Scope and Limitations

These tests demonstrate individual cryptographic operations and basic
filesystem functionality.

They do not demonstrate:
- Encryption of files through the mounted FUSE filesystem.
- Persistence of encrypted files after unmounting.
- Rust-to-C integration.
- Persistent key management.
- ML-DSA signature generation and verification.
- Production-level security or performance.

## 7. Overall Result

The C cryptographic demonstrations and writable Rust/FUSE prototype
were tested separately.

The results establish a working foundation for further development.
A complete encrypted virtual filesystem remains future work.

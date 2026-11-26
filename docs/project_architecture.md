# QuantumVault – Project Architecture

## 1. Project Overview

QuantumVault is an educational project exploring a Linux virtual filesystem
that aims to protect stored files using post-quantum key establishment and
authenticated encryption.

The intended design is to encrypt data before it is stored and decrypt it
when an authorized user reads it.

The current repository contains separate cryptographic demonstrations and
a writable Rust/FUSE filesystem prototype. These components have not yet
been integrated into a complete encrypted filesystem.

## 2. Intended Architecture

The planned data flow is:

1. A user accesses a file through the mounted QuantumVault filesystem.
2. The filesystem receives a write request.
3. A cryptographic layer encrypts the file data.
4. Encrypted data and the required metadata are stored on disk.
5. On a read request, the filesystem retrieves the stored data.
6. The cryptographic layer authenticates and decrypts the data.
7. The plaintext is returned to the user.

This is the target architecture, not the current completed behaviour.

## 3. Current Components

### 3.1 C Cryptography Demonstrations

Location: `src/c_crypto/`

The C programs use OpenSSL EVP APIs to demonstrate:

- ML-KEM-768 key generation, encapsulation and decapsulation.
- AES-256-GCM authenticated encryption and decryption.
- HKDF-SHA256 derivation of an AES key from an ML-KEM shared secret.
- Authentication-tag verification and tamper detection.
- Cleanup of sensitive buffers using OpenSSL cleansing functions.

The integrated demonstration is a fixed-message proof of concept. It does
not yet encrypt files through FUSE or persist cryptographic keys.

### 3.2 Rust/FUSE Filesystem Prototype

Location: `src/rust_fs/quantumvault_fs/`

The Rust application uses:

- `fuser` for the FUSE interface.
- `libc` for Linux system functions.
- `Mutex<Vec<u8>>` for in-memory file content.

The prototype exposes a virtual file named `hello.txt` and implements
operations for lookup, attributes, directory listing, opening, reading,
writing, creation and file-size changes.

The current implementation stores file content in memory only.

### 3.3 Current Component Relationship

The C cryptography demonstrations and Rust/FUSE prototype currently run
as separate components.

Rust-to-C FFI integration has not yet been implemented. The FUSE filesystem
does not currently call the C cryptography functions.

## 4. Cryptographic Design

### ML-KEM-768

ML-KEM-768, standardized in FIPS 203, is used in the demonstration to
establish a shared secret.

### HKDF-SHA256

HKDF-SHA256 derives a 256-bit AES key from the shared secret in the
integrated demonstration.

### AES-256-GCM

AES-256-GCM provides authenticated encryption for the demonstration
message. The program checks the authentication tag and rejects a
modified tag.

### ML-DSA

ML-DSA (FIPS 204) is part of the planned design. A working ML-DSA
implementation is not currently recorded in this repository.

## 5. Technology Stack

- Language: C and Rust
- Cryptographic API: OpenSSL EVP and EVP_KDF
- Key establishment: ML-KEM-768
- Key derivation: HKDF-SHA256
- Authenticated encryption: AES-256-GCM
- Filesystem interface: FUSE through the Rust `fuser` crate
- Operating environment: Kali Linux under WSL2

## 6. Current Limitations

- FUSE file content is held in memory and is not persistent.
- FUSE writes are not encrypted.
- The C cryptography engine is not connected to the FUSE filesystem.
- Rust-to-C FFI is not implemented.
- Cryptographic keys are generated for the demonstration and are not
  persistently managed.
- ML-DSA signatures are not implemented.
- The project is a prototype and has not undergone a security audit.

# QuantumVault: Post-Quantum Cryptography Local Filesystem

A quantum-resistant encrypted filesystem for Linux, built with CRYSTALS-Kyber (standardized by NIST as ML-KEM) and Rust FUSE.

## Week 1 status: complete

- **Crypto engine (C, liboqs):** generates an ML-KEM-768 keypair, then encrypts and decrypts a message using the Kyber shared secret with AES-256-GCM. Tampered data is rejected.
- **Filesystem (Rust, FUSE):** a minimal FUSE filesystem that mounts a virtual folder and returns "Hello World" when a file is read.

## Project structure

- `c_demo/`: Kyber keygen + encrypt/decrypt demo in C
- `hello-fuse/`: Rust FUSE "Hello World" filesystem
- `scripts/`: setup and run helpers

## Tested on

Ubuntu, liboqs 0.16, Rust 1.100, libfuse3 3.18

## How to run (Ubuntu)

    bash scripts/01_install_deps.sh
    source ~/.cargo/env
    bash scripts/02_build_liboqs.sh
    bash scripts/03_run_c_demo.sh
    bash scripts/04_run_hello_fuse.sh

## Expected output

C demo:

    Algorithm : ML-KEM-768
    Shared secrets match: YES
    Decrypted : Project Phoenix blueprint - TOP SECRET
    Tampered blob decrypt: REJECTED (good)

FUSE demo: `ls` shows `hello.txt`, and `cat` prints `Hello World from QuantumVault!`.

## Troubleshooting

- `OQS_KEM_alg_ml_kem_768` undeclared: your liboqs is older than 0.11. Use `OQS_KEM_alg_kyber_768` in `c_demo/qv_crypto.c` and `c_demo/kem_demo.c`.
- `liboqs.so` not found at runtime: run `sudo ldconfig`.
- FUSE mount error: make sure `fuse3` is installed and `fusermount3` works for your user.

## Roadmap

- Week 2: Rust/C FFI bridge and transparent encryption/decryption in FUSE
- Week 3: CRYSTALS-Dilithium (ML-DSA) signatures for tamper evidence
- Week 4: memory wiping (mlock, explicit_bzero), master password and CLI

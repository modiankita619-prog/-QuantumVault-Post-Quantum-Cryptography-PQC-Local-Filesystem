# QuantumVault: Post-Quantum Cryptography Local Filesystem

A quantum-resistant encrypted filesystem for Linux, built with CRYSTALS-Kyber (standardized by NIST as ML-KEM) and Rust FUSE. Files saved in the mounted vault are encrypted with ML-KEM-768 + AES-256-GCM before they reach the disk, and decrypted in memory when read.

## Status

- **Week 1: complete.** C crypto demo (ML-KEM-768 keypair, encrypt/decrypt, tamper rejection) and a Rust FUSE "Hello World" filesystem.
- **Week 2: complete.** Rust/C FFI bridge, encrypting FUSE filesystem, key generation CLI and an automated test script. All 11 checks pass.

## How it works

1. The C engine (liboqs + OpenSSL) generates an ML-KEM-768 keypair.
2. For every file save, a fresh encapsulation produces a shared secret, which is used as an AES-256-GCM key.
3. The Rust FUSE layer intercepts writes, encrypts the data and stores it as `<name>.qv` in a backing directory. On read, it decrypts in memory and wipes the plaintext when the file is closed.

Stored file format:

    [ KEM ciphertext (1088 B) | nonce (12 B) | GCM tag (16 B) | encrypted data ]

## Project structure

- `c_demo/`: C crypto engine (`qv_crypto.c/.h`) and the Kyber demo (`kem_demo.c`)
- `hello-fuse/`: Week 1 Rust FUSE "Hello World" filesystem
- `quantumvault/`: Week 2 Rust project (FFI bridge, encrypting FUSE filesystem, CLI)
  - `build.rs`: compiles the C engine and links liboqs and OpenSSL
  - `src/ffi.rs`: safe Rust wrapper around the C functions (the only file with `unsafe`)
  - `src/vaultfs.rs`: the encrypting FUSE filesystem
  - `src/main.rs`: CLI (`keygen`, `mount`)
- `scripts/`: setup, run and test helpers
- `docs/`: weekly documentation

## Tested on

Ubuntu, GCC 15.2, liboqs 0.16, Rust 1.100, libfuse3 3.18, fuser 0.14

## How to run (Ubuntu)

Setup (Week 1):

    bash scripts/01_install_deps.sh
    source ~/.cargo/env
    bash scripts/02_build_liboqs.sh
    bash scripts/03_run_c_demo.sh
    bash scripts/04_run_hello_fuse.sh

Encrypting vault (Week 2):

    bash scripts/05_build_week2.sh     # unit tests + release build
    bash scripts/06_test_vault.sh      # automated vault checks

Manual use:

    cd quantumvault
    ./target/release/quantumvault keygen ~/.qv-keys
    ./target/release/quantumvault mount ~/.qv-keys ~/vault-data ~/vault-mnt

In a second terminal:

    echo "TOP SECRET BLUEPRINT v1" > ~/vault-mnt/blueprint.txt
    cat ~/vault-mnt/blueprint.txt
    ls -l ~/vault-mnt ~/vault-data
    fusermount3 -u ~/vault-mnt

## Results

Week 1 C demo:

    Algorithm : ML-KEM-768
    Shared secrets match: YES
    Decrypted : Project Phoenix blueprint - TOP SECRET
    Tampered blob decrypt: REJECTED (good)

Week 2 vault test (`06_test_vault.sh`), all passing:

- keypair generated and vault mounted
- plaintext reads back correctly through the vault
- the stored file `blueprint.txt.qv` is 1140 bytes for a 24-byte message
- no plaintext in the stored file
- OpenSSL cannot decrypt the stored file
- data decrypts correctly after unmount and remount
- a file with one byte changed on disk is rejected, and the failure is logged

## Troubleshooting

- `OQS_KEM_alg_ml_kem_768` undeclared: your liboqs is older than 0.11. Use `OQS_KEM_alg_kyber_768` in `c_demo/qv_crypto.c` and `c_demo/kem_demo.c`.
- `liboqs.so` not found at runtime: run `sudo ldconfig`.
- Linker error `unable to find library -loqs`: `quantumvault/build.rs` adds `/usr/local/lib` to the search path. If liboqs is installed elsewhere, set `OQS_LIB_DIR=/path/to/lib`.
- `Transport endpoint is not connected`: a stale mount is left over. Run `fusermount3 -u <mountpoint>`.
- FUSE mount error: make sure `fuse3` is installed and `fusermount3` works for your user.

## Known limitations

- Flat namespace: no subdirectories yet.
- File names are visible in the backing directory.
- Each file is encrypted as one piece and held in RAM while open.
- The secret key is stored unprotected in `sk.bin` for now.

## Roadmap

- Week 3: CRYSTALS-Dilithium (ML-DSA) signatures for tamper evidence, and verification on read
- Week 4: memory wiping (mlock, explicit_bzero), master password and a polished CLI

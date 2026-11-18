# Week 2: Rust/C FFI bridge and transparent encryption

## What was built

- `quantumvault/build.rs` compiles the C engine (`c_demo/qv_crypto.c`) and links liboqs and OpenSSL into the Rust binary.
- `quantumvault/src/ffi.rs` wraps the C functions in a safe Rust API. It is the only file with `unsafe` code. Secret keys and decrypted data use `Zeroizing` buffers that are wiped when dropped.
- `quantumvault/src/vaultfs.rs` is a FUSE filesystem. Writes are encrypted before they reach disk, and reads are decrypted in memory.
- `quantumvault/src/main.rs` is a minimal CLI with `keygen` and `mount`.

## Storage format

Each file is stored as `<name>.qv` in the backing directory:

    [ KEM ciphertext (1088 B) | nonce (12 B) | GCM tag (16 B) | encrypted data ]

Every save uses a fresh ML-KEM-768 encapsulation and a random nonce.

## Build and test

    bash scripts/05_build_week2.sh    # cargo test + release build
    bash scripts/06_test_vault.sh     # automated mount / encrypt / tamper checks

## Manual use

    cd quantumvault
    ./target/release/quantumvault keygen ~/.qv-keys
    mkdir -p ~/vault-data ~/vault-mnt
    ./target/release/quantumvault mount ~/.qv-keys ~/vault-data ~/vault-mnt

In a second terminal:

    echo "TOP SECRET BLUEPRINT v1" > ~/vault-mnt/blueprint.txt
    cat ~/vault-mnt/blueprint.txt
    ls -l ~/vault-mnt ~/vault-data
    fusermount3 -u ~/vault-mnt

## Mid-project evidence

    xxd ~/vault-data/blueprint.txt.qv | head
    strings ~/vault-data/blueprint.txt.qv | grep -i secret     # no output
    openssl enc -d -aes-256-cbc -pbkdf2 -in ~/vault-data/blueprint.txt.qv -pass pass:test   # fails
    mount | grep quantumvault

## Known limitations

- Flat namespace: no subdirectories yet.
- File names are visible in the backing directory.
- Each file is encrypted as one piece and held in RAM while open.
- The secret key is stored unprotected in `sk.bin`. Week 4 adds a master password, `mlock` and `explicit_bzero`.
- Digital signatures (ML-DSA / Dilithium) arrive in Week 3.

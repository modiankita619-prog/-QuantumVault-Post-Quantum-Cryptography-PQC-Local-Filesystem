# QuantumVault – Rust/FUSE Filesystem

## 1. Overview

QuantumVault includes a writable virtual filesystem prototype developed
in Rust using the `fuser` crate.

Source directory:

`src/rust_fs/quantumvault_fs/`

Main source file:

`src/rust_fs/quantumvault_fs/src/main.rs`

## 2. Dependencies

- Rust edition 2024
- fuser 0.18.0
- libc 0.2.191

## 3. Implementation

The filesystem defines:
- Root directory inode: 1
- Virtual file inode: 2
- Virtual filename: `hello.txt`

It uses `Mutex<Vec<u8>>` to store file content in memory.

Implemented FUSE operations include:
- lookup()
- getattr()
- readdir()
- setattr()
- open()
- read()
- write()
- create()

The implementation supports reading, writing and resizing the virtual file.

## 4. Mounting

The application accepts the mount-point path as a command-line argument.

Example mount point:

`/home/garima/quantumvault-mount`

The filesystem is mounted with the FUSE filesystem name `quantumvault`.

## 5. Testing Performed

The following behaviour was tested:

1. Mounted the QuantumVault filesystem.
2. Listed the mounted directory.
3. Created and accessed `hello.txt`.
4. Wrote test content to the virtual file.
5. Read the file and verified its content.
6. Replaced the file content and verified the updated result.
7. Checked the file size and directory listing.

Observed examples included successful reading of:

`QuantumVault writable filesystem test`

and later:

`Second QuantumVault test`

## 6. Current Limitations

- File contents are held in memory.
- Data is not persisted to physical storage.
- File writes are not encrypted.
- The C cryptography engine is not connected to this filesystem.
- The implementation currently exposes only one virtual file.
- File timestamps use UNIX_EPOCH.
- Timestamp updates such as those requested by `touch` are not fully implemented.

## 7. Future Improvements

- Implement persistent backing storage.
- Connect the C cryptographic engine through Rust FFI.
- Encrypt data before writing it to storage.
- Authenticate and decrypt data during reads.
- Support multiple files and directories.
- Implement correct file timestamps and metadata handling.
- Add filesystem error handling and broader tests.

## 8. Security Status

This is a functional learning prototype, not a completed secure encrypted
filesystem. It should not be used to protect sensitive production data.

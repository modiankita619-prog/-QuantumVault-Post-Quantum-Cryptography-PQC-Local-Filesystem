use std::{ffi::CString, os::raw::c_char, path::Path, ptr, slice};

unsafe extern "C" {
    fn qv_generate_keypair(key_directory: *const c_char) -> i32;

    fn qv_encrypt_file(
        key_directory: *const c_char,
        plaintext: *const u8,
        plaintext_len: usize,
        encrypted: *mut *mut u8,
        encrypted_len: *mut usize,
    ) -> i32;

    fn qv_decrypt_file(
        key_directory: *const c_char,
        encrypted: *const u8,
        encrypted_len: usize,
        plaintext: *mut *mut u8,
        plaintext_len: *mut usize,
    ) -> i32;

    fn qv_free_buffer(buffer: *mut u8, buffer_len: usize);
}

fn key_directory_cstring(path: &Path) -> Result<CString, String> {
    CString::new(
        path.to_str()
            .ok_or("Key directory path is not valid UTF-8")?,
    )
    .map_err(|_| "Key directory path contains a null byte".to_string())
}

pub fn generate_keypair(key_directory: &Path) -> Result<(), String> {
    let directory = key_directory_cstring(key_directory)?;

    let result = unsafe { qv_generate_keypair(directory.as_ptr()) };

    if result == 1 {
        Ok(())
    } else {
        Err("ML-KEM key generation failed".to_string())
    }
}

pub fn encrypt(key_directory: &Path, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let directory = key_directory_cstring(key_directory)?;
    let mut output = ptr::null_mut();
    let mut output_len = 0usize;

    let result = unsafe {
        qv_encrypt_file(
            directory.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            &mut output,
            &mut output_len,
        )
    };

    if result != 1 || output.is_null() {
        return Err("File encryption failed".to_string());
    }

    let encrypted = unsafe {
        let data = slice::from_raw_parts(output, output_len).to_vec();
        qv_free_buffer(output, output_len);
        data
    };

    Ok(encrypted)
}

pub fn decrypt(key_directory: &Path, encrypted: &[u8]) -> Result<Vec<u8>, String> {
    let directory = key_directory_cstring(key_directory)?;
    let mut output = ptr::null_mut();
    let mut output_len = 0usize;

    let result = unsafe {
        qv_decrypt_file(
            directory.as_ptr(),
            encrypted.as_ptr(),
            encrypted.len(),
            &mut output,
            &mut output_len,
        )
    };

    if result != 1 || output.is_null() {
        return Err("File decryption or authentication failed".to_string());
    }

    let plaintext = unsafe {
        let data = slice::from_raw_parts(output, output_len).to_vec();
        qv_free_buffer(output, output_len);
        data
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rust_c_encryption_roundtrip() {
        let key_directory =
            PathBuf::from(std::env::var("HOME").unwrap()).join(".quantumvault/keys");

        let original = b"QuantumVault Rust-C FFI integration test";

        let encrypted = encrypt(&key_directory, original).expect("Encryption through C failed");

        assert_ne!(encrypted, original);

        let decrypted = decrypt(&key_directory, &encrypted).expect("Decryption through C failed");

        assert_eq!(decrypted, original);

        println!("Rust-C encryption and decryption: SUCCESS");
    }
}

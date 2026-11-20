//! Safe Rust wrapper around the C crypto engine (ML-KEM-768 + AES-256-GCM).
//! This is the only file in the project that contains `unsafe` code.

use std::os::raw::c_int;
use zeroize::Zeroizing;

extern "C" {
    fn qv_pk_len() -> usize;
    fn qv_sk_len() -> usize;
    fn qv_overhead() -> usize;
    fn qv_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn qv_encrypt(pk: *const u8, pt: *const u8, pt_len: usize,
                  out: *mut u8, out_cap: usize, out_len: *mut usize) -> c_int;
    fn qv_decrypt(sk: *const u8, blob: *const u8, blob_len: usize,
                  out: *mut u8, out_cap: usize, out_len: *mut usize) -> c_int;
}

pub fn pk_len() -> usize { unsafe { qv_pk_len() } }
pub fn sk_len() -> usize { unsafe { qv_sk_len() } }
pub fn overhead() -> usize { unsafe { qv_overhead() } }

/// Returns (public key, secret key). The secret key is wiped from memory on drop.
pub fn keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    let mut pk = vec![0u8; pk_len()];
    let mut sk = Zeroizing::new(vec![0u8; sk_len()]);
    let rc = unsafe { qv_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err("keypair generation failed".into());
    }
    Ok((pk, sk))
}

/// Encrypt `plaintext` for the owner of `pk`.
pub fn encrypt(pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if pk.len() != pk_len() {
        return Err("bad public key length".into());
    }
    let mut out = vec![0u8; plaintext.len() + overhead()];
    let mut n = 0usize;
    let rc = unsafe {
        qv_encrypt(pk.as_ptr(), plaintext.as_ptr(), plaintext.len(),
                   out.as_mut_ptr(), out.len(), &mut n)
    };
    if rc != 0 {
        return Err("encryption failed".into());
    }
    out.truncate(n);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt`. The result is wiped from memory on drop.
pub fn decrypt(sk: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if sk.len() != sk_len() {
        return Err("bad secret key length".into());
    }
    if blob.len() < overhead() {
        return Err("blob too short".into());
    }
    let mut out = Zeroizing::new(vec![0u8; blob.len() - overhead()]);
    let mut n = 0usize;
    let rc = unsafe {
        qv_decrypt(sk.as_ptr(), blob.as_ptr(), blob.len(),
                   out.as_mut_ptr(), out.len(), &mut n)
    };
    if rc != 0 {
        return Err("decryption failed (wrong key or tampered data)".into());
    }
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let (pk, sk) = keypair().unwrap();
        let msg = b"blueprint data";
        let blob = encrypt(&pk, msg).unwrap();
        assert_eq!(&decrypt(&sk, &blob).unwrap()[..], &msg[..]);

        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt(&sk, &bad).is_err());
    }

    #[test]
    fn empty_file() {
        let (pk, sk) = keypair().unwrap();
        let blob = encrypt(&pk, b"").unwrap();
        assert_eq!(decrypt(&sk, &blob).unwrap().len(), 0);
    }

    #[test]
    fn wrong_key_rejected() {
        let (pk, _sk) = keypair().unwrap();
        let (_pk2, sk2) = keypair().unwrap();
        let blob = encrypt(&pk, b"secret").unwrap();
        assert!(decrypt(&sk2, &blob).is_err());
    }
}

mod ffi;
mod vaultfs;

use fuser::MountOption;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::{env, process};
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!(
        "QuantumVault (Week 2)\n\nusage:\n  quantumvault keygen <keydir>\n  quantumvault mount  <keydir> <backing_dir> <mountpoint>\n\nUnmount with: fusermount3 -u <mountpoint>"
    );
    process::exit(2)
}

fn write_new(path: &PathBuf, data: &[u8], mode: u32) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap_or_else(|e| {
            eprintln!("{}: {e}", path.display());
            process::exit(1)
        });
    f.write_all(data).expect("write failed");
}

fn keygen(dir: &str) {
    let dir = PathBuf::from(dir);
    fs::create_dir_all(&dir).expect("cannot create key dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    let (pk, sk) = ffi::keypair().expect("keygen failed");
    write_new(&dir.join("pk.bin"), &pk, 0o644);
    write_new(&dir.join("sk.bin"), &sk, 0o600); // Week 4: protect with a master password
    println!("Generated ML-KEM-768 keypair in {}", dir.display());
}

fn mount(keydir: &str, backing: &str, mountpoint: &str) {
    let kd = PathBuf::from(keydir);
    let pk = fs::read(kd.join("pk.bin")).unwrap_or_else(|e| {
        eprintln!("cannot read pk.bin: {e}");
        process::exit(1)
    });
    let sk = Zeroizing::new(fs::read(kd.join("sk.bin")).unwrap_or_else(|e| {
        eprintln!("cannot read sk.bin: {e}");
        process::exit(1)
    }));
    if pk.len() != ffi::pk_len() || sk.len() != ffi::sk_len() {
        eprintln!("key files have the wrong size for ML-KEM-768");
        process::exit(1);
    }
    fs::create_dir_all(backing).expect("cannot create backing dir");
    fs::create_dir_all(mountpoint).expect("cannot create mountpoint");

    let vault = vaultfs::VaultFs::new(PathBuf::from(backing), pk, sk);
    let opts = [
        MountOption::FSName("quantumvault".into()),
        MountOption::DefaultPermissions,
    ];
    println!("Mounted at {mountpoint}. Unmount with: fusermount3 -u {mountpoint}");
    fuser::mount2(vault, mountpoint, &opts).unwrap_or_else(|e| {
        eprintln!("mount failed: {e}");
        process::exit(1)
    });
}

fn main() {
    let a: Vec<String> = env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") if a.len() == 3 => keygen(&a[2]),
        Some("mount") if a.len() == 5 => mount(&a[2], &a[3], &a[4]),
        _ => usage(),
    }
}

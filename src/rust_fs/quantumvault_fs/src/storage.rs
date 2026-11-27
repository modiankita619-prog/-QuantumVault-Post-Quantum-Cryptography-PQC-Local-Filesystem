use crate::ffi;
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

pub struct EncryptedStorage {
    data_path: PathBuf,
    key_path: PathBuf,
}

impl EncryptedStorage {
    pub fn new() -> Result<Self, String> {
        let home = PathBuf::from(std::env::var("HOME").map_err(|e| e.to_string())?);

        let base = home.join(".quantumvault");

        Ok(Self {
            data_path: base.join("data/hello.txt.qvlt"),
            key_path: base.join("keys"),
        })
    }

    pub fn load(&self) -> Result<Vec<u8>, String> {
        if !self.data_path.exists() {
            return Ok(Vec::new());
        }

        let encrypted = fs::read(&self.data_path).map_err(|e| e.to_string())?;

        ffi::decrypt(&self.key_path, &encrypted)
    }

    pub fn ensure_initialized(&self) -> Result<(), String> {
        if !self.data_path.exists() {
            self.save(&[])?;
        }
        Ok(())
    }

    pub fn save(&self, plaintext: &[u8]) -> Result<(), String> {
        let encrypted = ffi::encrypt(&self.key_path, plaintext)?;

        let parent = self.data_path.parent().ok_or("Invalid storage path")?;

        let temporary = parent.join(format!("hello.txt.qvlt.{}.tmp", std::process::id()));

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;

        let result = (|| {
            file.write_all(&encrypted)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.data_path)?;
            Ok::<(), std::io::Error>(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }

        result.map_err(|e| e.to_string())
    }
}

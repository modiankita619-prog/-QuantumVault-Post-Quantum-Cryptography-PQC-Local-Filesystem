//! Encrypting FUSE filesystem.
//!
//! * The mount point shows plaintext files.
//! * The backing directory stores each file as `<name>.qv` (ML-KEM-768 + AES-256-GCM).
//! * Plaintext is kept in RAM only while a file is open, then wiped.

use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData,
            ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
            TimeOrNow};
use libc::{EEXIST, EINVAL, EIO, ENOENT};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

use crate::ffi;

const TTL: Duration = Duration::from_secs(1);
const ROOT: u64 = 1;
const EXT: &str = ".qv";

struct Node {
    name: String,
    data: Zeroizing<Vec<u8>>, // plaintext, valid only while `loaded`
    loaded: bool,
    dirty: bool,
    opens: u32,
}

pub struct VaultFs {
    backing: PathBuf,
    pk: Vec<u8>,
    sk: Zeroizing<Vec<u8>>,
    nodes: HashMap<u64, Node>,
    by_name: HashMap<String, u64>,
    next_ino: u64,
    uid: u32,
    gid: u32,
}

impl VaultFs {
    pub fn new(backing: PathBuf, pk: Vec<u8>, sk: Zeroizing<Vec<u8>>) -> Self {
        let (uid, gid) = fs::metadata(&backing)
            .map(|m| (m.uid(), m.gid()))
            .unwrap_or((0, 0));
        let mut vault = VaultFs {
            backing,
            pk,
            sk,
            nodes: HashMap::new(),
            by_name: HashMap::new(),
            next_ino: 2,
            uid,
            gid,
        };
        if let Ok(rd) = fs::read_dir(&vault.backing) {
            for e in rd.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                if let Some(base) = fname.strip_suffix(EXT) {
                    if !base.is_empty() {
                        vault.register(base, false);
                    }
                }
            }
        }
        vault
    }

    fn path(&self, name: &str) -> PathBuf {
        self.backing.join(format!("{name}{EXT}"))
    }

    fn register(&mut self, name: &str, new_file: bool) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(
            ino,
            Node {
                name: name.to_string(),
                data: Zeroizing::new(Vec::new()),
                loaded: new_file,
                dirty: new_file,
                opens: 0,
            },
        );
        self.by_name.insert(name.to_string(), ino);
        ino
    }

    fn make_attr(&self, ino: u64, kind: FileType, size: u64) -> FileAttr {
        let now = SystemTime::now();
        let dir = kind == FileType::Directory;
        FileAttr {
            ino,
            size,
            blocks: (size + 511) / 512,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm: if dir { 0o700 } else { 0o600 },
            nlink: if dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: u64) -> Option<FileAttr> {
        let n = self.nodes.get(&ino)?;
        let size = if n.loaded {
            n.data.len() as u64
        } else {
            fs::metadata(self.path(&n.name))
                .map(|m| m.len())
                .unwrap_or(0)
                .saturating_sub(ffi::overhead() as u64)
        };
        Some(self.make_attr(ino, FileType::RegularFile, size))
    }

    /// Decrypt the file from the backing store into memory.
    fn load(&mut self, ino: u64) -> Result<(), i32> {
        let node = self.nodes.get(&ino).ok_or(ENOENT)?;
        if node.loaded {
            return Ok(());
        }
        let blob = fs::read(self.path(&node.name)).map_err(|_| EIO)?;
        let pt = ffi::decrypt(&self.sk, &blob).map_err(|e| {
            eprintln!("[vault] {e}");
            EIO
        })?;
        let node = self.nodes.get_mut(&ino).unwrap();
        node.data = pt;
        node.loaded = true;
        Ok(())
    }

    /// Encrypt in-memory plaintext and write it atomically to the backing store.
    fn flush_node(&mut self, ino: u64) -> Result<(), i32> {
        let node = self.nodes.get(&ino).ok_or(ENOENT)?;
        if !node.dirty {
            return Ok(());
        }
        let blob = ffi::encrypt(&self.pk, &node.data).map_err(|e| {
            eprintln!("[vault] {e}");
            EIO
        })?;
        let path = self.path(&node.name);
        let tmp = path.with_extension("qv.tmp");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| EIO)?;
        f.write_all(&blob).map_err(|_| EIO)?;
        f.sync_all().map_err(|_| EIO)?;
        fs::rename(&tmp, &path).map_err(|_| EIO)?;
        self.nodes.get_mut(&ino).unwrap().dirty = false;
        Ok(())
    }
}

impl Filesystem for VaultFs {
    fn lookup(&mut self, _r: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent != ROOT {
            reply.error(ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(EINVAL);
            return;
        };
        match self.by_name.get(name).and_then(|&i| self.file_attr(i)) {
            Some(a) => reply.entry(&TTL, &a, 0),
            None => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _r: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if ino == ROOT {
            reply.attr(&TTL, &self.make_attr(ROOT, FileType::Directory, 0));
        } else if let Some(a) = self.file_attr(ino) {
            reply.attr(&TTL, &a);
        } else {
            reply.error(ENOENT);
        }
    }

    fn setattr(
        &mut self,
        _r: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if ino == ROOT {
            reply.attr(&TTL, &self.make_attr(ROOT, FileType::Directory, 0));
            return;
        }
        if let Some(sz) = size {
            if sz == 0 {
                match self.nodes.get_mut(&ino) {
                    Some(n) => {
                        n.data = Zeroizing::new(Vec::new());
                        n.loaded = true;
                        n.dirty = true;
                    }
                    None => {
                        reply.error(ENOENT);
                        return;
                    }
                }
            } else {
                if let Err(e) = self.load(ino) {
                    reply.error(e);
                    return;
                }
                let n = self.nodes.get_mut(&ino).unwrap();
                n.data.resize(sz as usize, 0);
                n.dirty = true;
            }
        }
        match self.file_attr(ino) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(ENOENT),
        }
    }

    fn create(
        &mut self,
        _r: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if parent != ROOT {
            reply.error(ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(EINVAL);
            return;
        };
        if self.by_name.contains_key(name) {
            reply.error(EEXIST);
            return;
        }
        let ino = self.register(name, true);
        self.nodes.get_mut(&ino).unwrap().opens = 1;
        let a = self.file_attr(ino).unwrap();
        reply.created(&TTL, &a, 0, 0, 0);
    }

    fn open(&mut self, _r: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if let Err(e) = self.load(ino) {
            reply.error(e);
            return;
        }
        self.nodes.get_mut(&ino).unwrap().opens += 1;
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _r: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if let Err(e) = self.load(ino) {
            reply.error(e);
            return;
        }
        let d = &self.nodes[&ino].data;
        let s = (offset.max(0) as usize).min(d.len());
        let e = (s + size as usize).min(d.len());
        reply.data(&d[s..e]);
    }

    fn write(
        &mut self,
        _r: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _wflags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        if let Err(e) = self.load(ino) {
            reply.error(e);
            return;
        }
        let n = self.nodes.get_mut(&ino).unwrap();
        let off = offset.max(0) as usize;
        let end = off + data.len();
        if n.data.len() < end {
            n.data.resize(end, 0);
        }
        n.data[off..end].copy_from_slice(data);
        n.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(&mut self, _r: &Request<'_>, ino: u64, _fh: u64, _lock: u64, reply: ReplyEmpty) {
        match self.flush_node(ino) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &mut self,
        _r: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if !self.nodes.contains_key(&ino) {
            reply.ok(); // file was deleted while open
            return;
        }
        if let Err(e) = self.flush_node(ino) {
            reply.error(e);
            return;
        }
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.opens = n.opens.saturating_sub(1);
            if n.opens == 0 && !n.dirty {
                n.data = Zeroizing::new(Vec::new()); // wipes plaintext from RAM
                n.loaded = false;
            }
        }
        reply.ok();
    }

    fn unlink(&mut self, _r: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if parent != ROOT {
            reply.error(ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(EINVAL);
            return;
        };
        match self.by_name.remove(name) {
            Some(ino) => {
                self.nodes.remove(&ino);
                let _ = fs::remove_file(self.path(name));
                reply.ok();
            }
            None => reply.error(ENOENT),
        }
    }

    fn rename(
        &mut self,
        _r: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if parent != ROOT || newparent != ROOT {
            reply.error(ENOENT);
            return;
        }
        let (Some(old), Some(new)) = (name.to_str(), newname.to_str()) else {
            reply.error(EINVAL);
            return;
        };
        let Some(&ino) = self.by_name.get(old) else {
            reply.error(ENOENT);
            return;
        };
        if let Err(e) = self.flush_node(ino) {
            reply.error(e);
            return;
        }
        if let Some(&victim) = self.by_name.get(new) {
            if victim != ino {
                self.nodes.remove(&victim);
            }
        }
        let (op, np) = (self.path(old), self.path(new));
        if op.exists() && fs::rename(&op, &np).is_err() {
            reply.error(EIO);
            return;
        }
        self.by_name.remove(old);
        self.by_name.insert(new.to_string(), ino);
        self.nodes.get_mut(&ino).unwrap().name = new.to_string();
        reply.ok();
    }

    fn readdir(
        &mut self,
        _r: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT {
            reply.error(ENOENT);
            return;
        }
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ROOT, FileType::Directory, ".".into()),
            (ROOT, FileType::Directory, "..".into()),
        ];
        let mut files: Vec<(u64, String)> =
            self.nodes.iter().map(|(i, n)| (*i, n.name.clone())).collect();
        files.sort();
        for (i, n) in files {
            entries.push((i, FileType::RegularFile, n));
        }
        for (idx, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (idx + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

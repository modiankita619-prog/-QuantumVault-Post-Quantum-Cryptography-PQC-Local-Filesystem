mod ffi;
mod storage;
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, WriteFlags,
};
use std::{
    ffi::OsStr,
    sync::Mutex,
    time::{Duration, UNIX_EPOCH},
};

const TTL: Duration = Duration::from_secs(1);
const ROOT: u64 = 1;
const FILE: u64 = 2;

struct QuantumVaultFS {
    content: Mutex<Vec<u8>>,
    storage: storage::EncryptedStorage,
}

impl QuantumVaultFS {
    fn new() -> Result<Self, String> {
        let storage = storage::EncryptedStorage::new()?;
        let content = storage.load()?;

        Ok(Self {
            content: Mutex::new(content),
            storage,
        })
    }
}

impl Filesystem for QuantumVaultFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == INodeNo(ROOT) && name == OsStr::new("hello.txt") {
            let content = self.content.lock().unwrap();
            reply.entry(&TTL, &file_attr(content.len() as u64), Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino.0 {
            ROOT => reply.attr(&TTL, &directory_attr()),
            FILE => {
                let content = self.content.lock().unwrap();
                reply.attr(&TTL, &file_attr(content.len() as u64));
            }
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino.0 != ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries = [
            (ROOT, FileType::Directory, "."),
            (ROOT, FileType::Directory, ".."),
            (FILE, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(entry.0), (i + 1) as u64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if ino.0 == FILE {
            let mut content = self.content.lock().unwrap();

            if let Some(new_size) = size {
                let Ok(new_size) = usize::try_from(new_size) else {
                    reply.error(Errno::EIO);
                    return;
                };

                let mut updated = content.clone();
                updated.resize(new_size, 0);

                if self.storage.save(&updated).is_err() {
                    reply.error(Errno::EIO);
                    return;
                }

                *content = updated;
            }

            reply.attr(&TTL, &file_attr(content.len() as u64));
        } else if ino.0 == ROOT {
            reply.attr(&TTL, &directory_attr());
        } else {
            reply.error(Errno::ENOENT);
        }
    }
    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 == FILE {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino.0 != FILE {
            reply.error(Errno::ENOENT);
            return;
        }

        let content = match self.storage.load() {
            Ok(data) => data,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let start = offset as usize;

        if start >= content.len() {
            reply.data(&[]);
        } else {
            let Some(requested_end) = start.checked_add(size as usize) else {
                reply.error(Errno::EIO);
                return;
            };

            let end = requested_end.min(content.len());
            reply.data(&content[start..end]);
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if ino.0 != FILE {
            reply.error(Errno::ENOENT);
            return;
        }

        let mut content = self.content.lock().unwrap();
        let start = offset as usize;

        let Some(end) = start.checked_add(data.len()) else {
            reply.error(Errno::EIO);
            return;
        };

        let mut updated = content.clone();

        if updated.len() < start {
            updated.resize(start, 0);
        }
        if updated.len() < end {
            updated.resize(end, 0);
        }

        updated[start..end].copy_from_slice(data);

        if self.storage.save(&updated).is_err() {
            reply.error(Errno::EIO);
            return;
        }

        *content = updated;
        reply.written(data.len() as u32);
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if parent == INodeNo(ROOT) && name == OsStr::new("hello.txt") {
            if self.storage.ensure_initialized().is_err() {
                reply.error(Errno::EIO);
                return;
            }

            let content = self.content.lock().unwrap();
            reply.created(
                &TTL,
                &file_attr(content.len() as u64),
                Generation(0),
                FileHandle(0),
                FopenFlags::empty(),
            );
        } else {
            reply.error(Errno::EEXIST);
        }
    }
}

fn directory_attr() -> FileAttr {
    FileAttr {
        ino: INodeNo(ROOT),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
        blksize: 512,
    }
}

fn file_attr(size: u64) -> FileAttr {
    FileAttr {
        ino: INodeNo(FILE),
        size,
        blocks: size.div_ceil(512),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
        blksize: 512,
    }
}

fn main() {
    let mountpoint = std::env::args_os()
        .nth(1)
        .expect("Usage: quantumvault_fs <mountpoint>");

    let mut config = Config::default();
    config
        .mount_options
        .extend([MountOption::FSName("quantumvault".to_string())]);

    let filesystem =
        QuantumVaultFS::new().expect("Failed to initialize encrypted QuantumVault storage");

    fuser::mount(filesystem, mountpoint, &config).expect("Failed to mount QuantumVault filesystem");
}

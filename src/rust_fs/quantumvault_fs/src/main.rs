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
}

impl QuantumVaultFS {
    fn new() -> Self {
        Self {
            content: Mutex::new(Vec::new()),
        }
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
                content.resize(new_size as usize, 0);
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

        let content = self.content.lock().unwrap();
        let start = offset as usize;
        if start >= content.len() {
            reply.data(&[]);
        } else {
            let end = (start + size as usize).min(content.len());
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
        if content.len() < start {
            content.resize(start, 0);
        }
        let end = start + data.len();
        if content.len() < end {
            content.resize(end, 0);
        }
        content[start..end].copy_from_slice(data);
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

    fuser::mount(QuantumVaultFS::new(), mountpoint, &config)
        .expect("Failed to mount QuantumVault filesystem");
}

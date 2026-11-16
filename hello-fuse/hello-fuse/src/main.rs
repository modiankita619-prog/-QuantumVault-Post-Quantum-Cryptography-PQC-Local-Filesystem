use fuser::{FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
            ReplyDirectory, ReplyEntry, Request};
use libc::ENOENT;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const CONTENT: &str = "Hello World from QuantumVault!\n";

fn attr(ino: u64, kind: FileType, size: u64) -> FileAttr {
    let is_dir = kind == FileType::Directory;
    FileAttr {
        ino, size, blocks: 1,
        atime: UNIX_EPOCH, mtime: UNIX_EPOCH, ctime: UNIX_EPOCH, crtime: UNIX_EPOCH,
        kind,
        perm: if is_dir { 0o755 } else { 0o444 },
        nlink: if is_dir { 2 } else { 1 },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0, blksize: 512, flags: 0,
    }
}

struct HelloFs;

impl Filesystem for HelloFs {
    fn lookup(&mut self, _r: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &attr(2, FileType::RegularFile, CONTENT.len() as u64), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _r: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &attr(1, FileType::Directory, 0)),
            2 => reply.attr(&TTL, &attr(2, FileType::RegularFile, CONTENT.len() as u64)),
            _ => reply.error(ENOENT),
        }
    }

    fn read(&mut self, _r: &Request<'_>, ino: u64, _fh: u64, offset: i64, size: u32,
            _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        if ino == 2 {
            let d = CONTENT.as_bytes();
            let s = (offset.max(0) as usize).min(d.len());
            let e = (s + size as usize).min(d.len());
            reply.data(&d[s..e]);
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(&mut self, _r: &Request<'_>, ino: u64, _fh: u64, offset: i64,
               mut reply: ReplyDirectory) {
        if ino != 1 { reply.error(ENOENT); return; }
        let entries = [
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) { break; }
        }
        reply.ok();
    }
}

fn main() {
    let mp = std::env::args().nth(1).expect("usage: hello-fuse <mountpoint>");
    let opts = [MountOption::RO, MountOption::FSName("hello".into())];
    fuser::mount2(HelloFs, mp, &opts).expect("mount failed");
}

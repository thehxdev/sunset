use std::ffi::OsStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};

use crate::fs_engine::SunsetEngine;
use crate::inode::{Inode, InodeKind};

const TTL: Duration = Duration::from_secs(1);
static NEXT_FH: AtomicU64 = AtomicU64::new(1);

fn next_file_handle() -> FileHandle {
    FileHandle(NEXT_FH.fetch_add(1, Ordering::Relaxed))
}

fn inode_to_fileattr(node: &Inode) -> FileAttr {
    let kind = match node.kind {
        InodeKind::File => FileType::RegularFile,
        InodeKind::Directory => FileType::Directory,
        InodeKind::Symlink => FileType::Symlink,
    };

    let atime = UNIX_EPOCH + Duration::new(node.atime_secs.max(0) as u64, node.atime_nanos);
    let mtime = UNIX_EPOCH + Duration::new(node.mtime_secs.max(0) as u64, node.mtime_nanos);
    let ctime = UNIX_EPOCH + Duration::new(node.ctime_secs.max(0) as u64, node.ctime_nanos);

    let blocks = (node.size + 511) / 512;

    FileAttr {
        ino: INodeNo(node.ino),
        size: node.size,
        blocks,
        atime,
        mtime,
        ctime,
        crtime: ctime,
        kind,
        perm: (node.mode & 0o7777) as u16,
        nlink: node.nlink,
        uid: node.uid,
        gid: node.gid,
        rdev: 0,
        flags: 0,
        blksize: 4096,
    }
}

pub struct SunsetFuseFs {
    engine: Mutex<SunsetEngine>,
    read_only: bool,
}

impl SunsetFuseFs {
    pub fn new(engine: SunsetEngine, read_only: bool) -> Self {
        Self {
            engine: Mutex::new(engine),
            read_only,
        }
    }
}

impl Filesystem for SunsetFuseFs {
    fn destroy(&mut self) {
        if let Ok(mut engine) = self.engine.lock() {
            let _ = engine.flush();
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.lookup(parent.0, name_str) {
            Ok(inode) => reply.entry(&TTL, &inode_to_fileattr(&inode), Generation(0)),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.get_inode(ino.0) {
            Ok(inode) => reply.attr(&TTL, &inode_to_fileattr(inode)),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        if let Some(sz) = size {
            if let Err(e) = engine.truncate(ino.0, sz) {
                reply.error(e.to_errno());
                return;
            }
        }

        let node = match engine.get_inode_mut(ino.0) {
            Ok(n) => n,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        if let Some(m) = mode {
            node.mode = (node.mode & !0o7777) | (m & 0o7777);
        }
        if let Some(u) = uid {
            node.uid = u;
        }
        if let Some(g) = gid {
            node.gid = g;
        }
        if let Some(at) = atime {
            match at {
                TimeOrNow::SpecificTime(t) => {
                    if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                        node.atime_secs = d.as_secs() as i64;
                        node.atime_nanos = d.subsec_nanos();
                    }
                }
                TimeOrNow::Now => node.update_atime(),
            }
        }
        if let Some(mt) = mtime {
            match mt {
                TimeOrNow::SpecificTime(t) => {
                    if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                        node.mtime_secs = d.as_secs() as i64;
                        node.mtime_nanos = d.subsec_nanos();
                    }
                }
                TimeOrNow::Now => node.update_mtime(),
            }
        }

        let attr = inode_to_fileattr(node);
        reply.attr(&TTL, &attr);
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
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.read_bytes(ino.0, offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e.to_errno()),
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
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.write_bytes(ino.0, offset, data) {
            Ok(bytes_written) => reply.written(bytes_written as u32),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.flush() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.flush() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.get_inode(ino.0) {
            Ok(node) => {
                if node.kind == InodeKind::Directory {
                    reply.opened(next_file_handle(), FopenFlags::empty());
                } else {
                    reply.error(Errno::ENOTDIR);
                }
            }
            Err(e) => reply.error(e.to_errno()),
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
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let parent_ino = match engine.get_inode(ino.0) {
            Ok(node) => node.parent_ino,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        let dir_data = match engine.read_dir_data(ino.0) {
            Ok(d) => d,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        let mut entries = Vec::new();
        entries.push((INodeNo(ino.0), FileType::Directory, ".".to_string()));
        entries.push((INodeNo(parent_ino), FileType::Directory, "..".to_string()));
        for e in &dir_data.entries {
            let ftype = match e.kind {
                InodeKind::File => FileType::RegularFile,
                InodeKind::Directory => FileType::Directory,
                InodeKind::Symlink => FileType::Symlink,
            };
            entries.push((INodeNo(e.ino), ftype, e.name.clone()));
        }

        for (i, (entry_ino, ftype, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry_ino, (i + 1) as u64, ftype, &name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.get_inode(ino.0) {
            Ok(node) => {
                if node.kind == InodeKind::File {
                    engine.on_file_open(ino.0);
                    reply.opened(next_file_handle(), FopenFlags::empty());
                } else {
                    reply.error(Errno::EISDIR);
                }
            }
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut engine) = self.engine.lock() {
            let _ = engine.on_file_release(ino.0);
        }
        reply.ok();
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let effective_mode = mode & !umask;
        match engine.mkdir(parent.0, name_str, effective_mode, req.uid(), req.gid()) {
            Ok(inode) => reply.entry(&TTL, &inode_to_fileattr(&inode), Generation(0)),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let effective_mode = mode & !umask;
        match engine.create_file(parent.0, name_str, effective_mode, req.uid(), req.gid()) {
            Ok(inode) => reply.entry(&TTL, &inode_to_fileattr(&inode), Generation(0)),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let effective_mode = mode & !umask;
        match engine.create_file(parent.0, name_str, effective_mode, req.uid(), req.gid()) {
            Ok(inode) => {
                engine.on_file_open(inode.ino);
                reply.created(
                    &TTL,
                    &inode_to_fileattr(&inode),
                    Generation(0),
                    next_file_handle(),
                    FopenFlags::empty(),
                );
            }
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.unlink(parent.0, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.rmdir(parent.0, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            reply.error(Errno::from_i32(libc::EROFS));
            return;
        }

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let newname_str = match newname.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        match engine.rename(parent.0, name_str, newparent.0, newname_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };

        let total = engine.total_blocks();
        let free = engine.free_blocks_count();
        let inodes = engine.inodes_count();
        reply.statfs(
            total.max(1024),
            free,
            free,
            inodes.max(1024),
            1024,
            4096,
            255,
            4096,
        );
    }
}

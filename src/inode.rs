use crate::format::PLAINTEXT_BLOCK_SIZE;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const DIRECT_BLOCKS: usize = 12;
pub const PTRS_PER_BLOCK: usize = PLAINTEXT_BLOCK_SIZE / 8; // 512 pointers

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InodeKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub ino: u64,
    pub parent_ino: u64,
    pub kind: InodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub atime_secs: i64,
    pub atime_nanos: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub ctime_secs: i64,
    pub ctime_nanos: u32,
    pub direct_blocks: [u64; DIRECT_BLOCKS],
    pub indirect_block: u64,
    pub double_indirect_block: u64,
    pub triple_indirect_block: u64,
    pub symlink_target: Option<String>,
}

impl Inode {
    pub fn current_time() -> (i64, u32) {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(_) => (0, 0),
        }
    }

    pub fn new_directory(ino: u64, parent_ino: u64, mode: u32, uid: u32, gid: u32) -> Self {
        let (now_secs, now_nanos) = Self::current_time();
        Self {
            ino,
            parent_ino,
            kind: InodeKind::Directory,
            mode: mode | libc::S_IFDIR,
            uid,
            gid,
            size: 0,
            nlink: 2, // . and parent
            atime_secs: now_secs,
            atime_nanos: now_nanos,
            mtime_secs: now_secs,
            mtime_nanos: now_nanos,
            ctime_secs: now_secs,
            ctime_nanos: now_nanos,
            direct_blocks: [0; DIRECT_BLOCKS],
            indirect_block: 0,
            double_indirect_block: 0,
            triple_indirect_block: 0,
            symlink_target: None,
        }
    }

    pub fn new_file(ino: u64, parent_ino: u64, mode: u32, uid: u32, gid: u32) -> Self {
        let (now_secs, now_nanos) = Self::current_time();
        Self {
            ino,
            parent_ino,
            kind: InodeKind::File,
            mode: mode | libc::S_IFREG,
            uid,
            gid,
            size: 0,
            nlink: 1,
            atime_secs: now_secs,
            atime_nanos: now_nanos,
            mtime_secs: now_secs,
            mtime_nanos: now_nanos,
            ctime_secs: now_secs,
            ctime_nanos: now_nanos,
            direct_blocks: [0; DIRECT_BLOCKS],
            indirect_block: 0,
            double_indirect_block: 0,
            triple_indirect_block: 0,
            symlink_target: None,
        }
    }

    pub fn new_symlink(
        ino: u64,
        parent_ino: u64,
        target: String,
        uid: u32,
        gid: u32,
    ) -> Self {
        let (now_secs, now_nanos) = Self::current_time();
        Self {
            ino,
            parent_ino,
            kind: InodeKind::Symlink,
            mode: 0o777 | libc::S_IFLNK,
            uid,
            gid,
            size: target.len() as u64,
            nlink: 1,
            atime_secs: now_secs,
            atime_nanos: now_nanos,
            mtime_secs: now_secs,
            mtime_nanos: now_nanos,
            ctime_secs: now_secs,
            ctime_nanos: now_nanos,
            direct_blocks: [0; DIRECT_BLOCKS],
            indirect_block: 0,
            double_indirect_block: 0,
            triple_indirect_block: 0,
            symlink_target: Some(target),
        }
    }

    pub fn update_mtime(&mut self) {
        let (now_secs, now_nanos) = Self::current_time();
        self.mtime_secs = now_secs;
        self.mtime_nanos = now_nanos;
        self.ctime_secs = now_secs;
        self.ctime_nanos = now_nanos;
    }

    pub fn update_atime(&mut self) {
        let (now_secs, now_nanos) = Self::current_time();
        self.atime_secs = now_secs;
        self.atime_nanos = now_nanos;
    }
}

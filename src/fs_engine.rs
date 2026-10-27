use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::block_io::BlockDevice;
use crate::dir::DirectoryData;
use crate::error::SunsetError;
use crate::format::{
    FIRST_ALLOCATABLE_BLOCK, PLAINTEXT_BLOCK_SIZE, ROOT_INODE_ID, SUPERBLOCK_0_ID,
    SUPERBLOCK_1_ID, SuperblockPayload,
};
use crate::inode::{
    DIRECT_BLOCKS, Inode, InodeKind, PTRS_PER_BLOCK,
};

fn decode_ptrs(buf: &[u8]) -> [u64; PTRS_PER_BLOCK] {
    let mut ptrs = [0u64; PTRS_PER_BLOCK];
    for (i, p) in ptrs.iter_mut().enumerate() {
        let start = i * 8;
        *p = u64::from_le_bytes(buf[start..start + 8].try_into().unwrap());
    }
    ptrs
}

fn encode_ptrs(ptrs: &[u64; PTRS_PER_BLOCK]) -> [u8; PLAINTEXT_BLOCK_SIZE] {
    let mut buf = [0u8; PLAINTEXT_BLOCK_SIZE];
    for (i, &p) in ptrs.iter().enumerate() {
        let start = i * 8;
        buf[start..start + 8].copy_from_slice(&p.to_le_bytes());
    }
    buf
}

pub struct SunsetEngine {
    block_dev: BlockDevice,
    superblock: SuperblockPayload,
    active_sb_block: u64,
    inodes: HashMap<u64, Inode>,
    open_inodes: HashMap<u64, usize>,
    dirty_inodes: HashSet<u64>,
    dirty_superblock: bool,
}

impl SunsetEngine {
    pub fn init(
        path: &Path,
        passphrase: &str,
        initial_blocks: Option<u64>,
    ) -> Result<Self, SunsetError> {
        let mut block_dev = BlockDevice::create(path, passphrase, initial_blocks)?;
        let mut superblock = SuperblockPayload::new();
        superblock.total_blocks = FIRST_ALLOCATABLE_BLOCK;

        let root_inode = Inode::new_directory(ROOT_INODE_ID, ROOT_INODE_ID, 0o755, 0, 0);
        let mut inodes = HashMap::new();
        inodes.insert(ROOT_INODE_ID, root_inode);

        // Serialize root inode
        let inode_bytes = bincode::serialize(&inodes)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize initial inodes: {}", e)))?;

        // Allocate block for initial inode table
        let inode_block = superblock.total_blocks;
        superblock.total_blocks += 1;
        superblock.inode_blocks.push(inode_block);

        let mut block_data = [0u8; PLAINTEXT_BLOCK_SIZE];
        block_data[..inode_bytes.len()].copy_from_slice(&inode_bytes);
        block_dev.write_block(inode_block, &block_data)?;

        // Write both superblocks
        let sb_bytes = bincode::serialize(&superblock)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize superblock: {}", e)))?;
        block_dev.write_block(SUPERBLOCK_0_ID, &sb_bytes)?;
        block_dev.write_block(SUPERBLOCK_1_ID, &sb_bytes)?;
        block_dev.flush()?;

        Ok(Self {
            block_dev,
            superblock,
            active_sb_block: SUPERBLOCK_0_ID,
            inodes,
            open_inodes: HashMap::new(),
            dirty_inodes: HashSet::new(),
            dirty_superblock: false,
        })
    }

    pub fn open(path: &Path, passphrase: &str) -> Result<Self, SunsetError> {
        let mut block_dev = BlockDevice::open(path, passphrase)?;

        // Attempt reading Superblock 0 and Superblock 1
        let sb0: Option<SuperblockPayload> = block_dev
            .read_block(SUPERBLOCK_0_ID)
            .ok()
            .and_then(|bytes| bincode::deserialize(&bytes).ok());

        let sb1: Option<SuperblockPayload> = block_dev
            .read_block(SUPERBLOCK_1_ID)
            .ok()
            .and_then(|bytes| bincode::deserialize(&bytes).ok());

        let (superblock, active_sb_block) = match (sb0, sb1) {
            (Some(s0), Some(s1)) => {
                if s1.seq > s0.seq {
                    (s1, SUPERBLOCK_1_ID)
                } else {
                    (s0, SUPERBLOCK_0_ID)
                }
            }
            (Some(s0), None) => (s0, SUPERBLOCK_0_ID),
            (None, Some(s1)) => (s1, SUPERBLOCK_1_ID),
            (None, None) => return Err(SunsetError::CorruptedBlock(SUPERBLOCK_0_ID)),
        };

        let mut all_inode_bytes = Vec::new();
        for &b in &superblock.inode_blocks {
            let block = block_dev.read_block(b)?;
            all_inode_bytes.extend_from_slice(&block);
        }

        let inodes: HashMap<u64, Inode> = if all_inode_bytes.is_empty() {
            HashMap::new()
        } else {
            bincode::deserialize(&all_inode_bytes).map_err(|e| {
                SunsetError::Format(format!("Failed to deserialize inode table: {}", e))
            })?
        };

        Ok(Self {
            block_dev,
            superblock,
            active_sb_block,
            inodes,
            open_inodes: HashMap::new(),
            dirty_inodes: HashSet::new(),
            dirty_superblock: false,
        })
    }

    pub fn allocate_block(&mut self) -> Result<u64, SunsetError> {
        if let Some(block_id) = self.superblock.free_blocks.pop() {
            self.dirty_superblock = true;
            Ok(block_id)
        } else {
            let block_id = self.superblock.total_blocks;
            self.superblock.total_blocks += 1;
            self.dirty_superblock = true;
            Ok(block_id)
        }
    }

    pub fn free_block(&mut self, block_id: u64) -> Result<(), SunsetError> {
        if block_id == SUPERBLOCK_0_ID || block_id == SUPERBLOCK_1_ID {
            return Ok(());
        }
        let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
        let _ = self.block_dev.write_block(block_id, &zero);
        self.superblock.free_blocks.push(block_id);
        self.dirty_superblock = true;
        Ok(())
    }

    pub fn get_inode(&self, ino: u64) -> Result<&Inode, SunsetError> {
        self.inodes
            .get(&ino)
            .ok_or_else(|| SunsetError::NotFound(format!("inode #{}", ino)))
    }

    pub fn get_inode_mut(&mut self, ino: u64) -> Result<&mut Inode, SunsetError> {
        self.dirty_inodes.insert(ino);
        self.inodes
            .get_mut(&ino)
            .ok_or_else(|| SunsetError::NotFound(format!("inode #{}", ino)))
    }

    pub fn mark_inode_dirty(&mut self, ino: u64) {
        self.dirty_inodes.insert(ino);
    }

    pub fn on_file_open(&mut self, ino: u64) {
        *self.open_inodes.entry(ino).or_insert(0) += 1;
    }

    pub fn on_file_release(&mut self, ino: u64) -> Result<(), SunsetError> {
        let count = match self.open_inodes.get_mut(&ino) {
            Some(c) => {
                *c = c.saturating_sub(1);
                *c
            }
            None => 0,
        };

        if count == 0 {
            self.open_inodes.remove(&ino);
            if let Some(node) = self.inodes.get(&ino) {
                if node.nlink == 0 {
                    self.free_all_inode_blocks(ino)?;
                    self.inodes.remove(&ino);
                    self.dirty_inodes.remove(&ino);
                    self.dirty_superblock = true;
                }
            }
        }
        Ok(())
    }

    // Resolves logical block index to physical block index.
    // Returns (physical_block, was_newly_allocated).
    fn resolve_block(
        &mut self,
        ino: u64,
        logical_block: u64,
        allocate: bool,
    ) -> Result<Option<(u64, bool)>, SunsetError> {
        let inode = self.get_inode(ino)?.clone();

        // 1. Direct blocks (0..12)
        if (logical_block as usize) < DIRECT_BLOCKS {
            let idx = logical_block as usize;
            let phys = inode.direct_blocks[idx];
            if phys != 0 {
                return Ok(Some((phys, false)));
            }
            if !allocate {
                return Ok(None);
            }
            let new_phys = self.allocate_block()?;
            let node = self.get_inode_mut(ino)?;
            node.direct_blocks[idx] = new_phys;
            return Ok(Some((new_phys, true)));
        }

        // 2. Single indirect blocks (12 .. 12 + 512)
        let rel_lblock = logical_block as usize - DIRECT_BLOCKS;
        if rel_lblock < PTRS_PER_BLOCK {
            let indirect_block = if inode.indirect_block != 0 {
                inode.indirect_block
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_indir = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_indir, &zero)?;
                let node = self.get_inode_mut(ino)?;
                node.indirect_block = new_indir;
                new_indir
            };

            let block_raw = self.block_dev.read_block(indirect_block)?;
            let mut ptrs = decode_ptrs(&block_raw);
            let phys = ptrs[rel_lblock];
            if phys != 0 {
                return Ok(Some((phys, false)));
            }
            if !allocate {
                return Ok(None);
            }
            let new_phys = self.allocate_block()?;
            ptrs[rel_lblock] = new_phys;
            self.block_dev
                .write_block(indirect_block, &encode_ptrs(&ptrs))?;
            return Ok(Some((new_phys, true)));
        }

        // 3. Double indirect blocks
        let dbl_rel = rel_lblock - PTRS_PER_BLOCK;
        if dbl_rel < PTRS_PER_BLOCK * PTRS_PER_BLOCK {
            let idx1 = dbl_rel / PTRS_PER_BLOCK;
            let idx2 = dbl_rel % PTRS_PER_BLOCK;

            let dbl_indir = if inode.double_indirect_block != 0 {
                inode.double_indirect_block
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_dbl = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_dbl, &zero)?;
                let node = self.get_inode_mut(ino)?;
                node.double_indirect_block = new_dbl;
                new_dbl
            };

            let block1_raw = self.block_dev.read_block(dbl_indir)?;
            let mut ptrs1 = decode_ptrs(&block1_raw);
            let lvl2_block = if ptrs1[idx1] != 0 {
                ptrs1[idx1]
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_lvl2 = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_lvl2, &zero)?;
                ptrs1[idx1] = new_lvl2;
                self.block_dev
                    .write_block(dbl_indir, &encode_ptrs(&ptrs1))?;
                new_lvl2
            };

            let block2_raw = self.block_dev.read_block(lvl2_block)?;
            let mut ptrs2 = decode_ptrs(&block2_raw);
            let phys = ptrs2[idx2];
            if phys != 0 {
                return Ok(Some((phys, false)));
            }
            if !allocate {
                return Ok(None);
            }
            let new_phys = self.allocate_block()?;
            ptrs2[idx2] = new_phys;
            self.block_dev
                .write_block(lvl2_block, &encode_ptrs(&ptrs2))?;
            return Ok(Some((new_phys, true)));
        }

        // 4. Triple indirect blocks (up to 512 GB)
        let triple_rel = dbl_rel - (PTRS_PER_BLOCK * PTRS_PER_BLOCK);
        let ptrs_sq = PTRS_PER_BLOCK * PTRS_PER_BLOCK;
        if triple_rel < PTRS_PER_BLOCK * ptrs_sq {
            let idx1 = triple_rel / ptrs_sq;
            let rem = triple_rel % ptrs_sq;
            let idx2 = rem / PTRS_PER_BLOCK;
            let idx3 = rem % PTRS_PER_BLOCK;

            let trpl_indir = if inode.triple_indirect_block != 0 {
                inode.triple_indirect_block
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_trpl = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_trpl, &zero)?;
                let node = self.get_inode_mut(ino)?;
                node.triple_indirect_block = new_trpl;
                new_trpl
            };

            let block1_raw = self.block_dev.read_block(trpl_indir)?;
            let mut ptrs1 = decode_ptrs(&block1_raw);
            let lvl2_block = if ptrs1[idx1] != 0 {
                ptrs1[idx1]
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_lvl2 = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_lvl2, &zero)?;
                ptrs1[idx1] = new_lvl2;
                self.block_dev
                    .write_block(trpl_indir, &encode_ptrs(&ptrs1))?;
                new_lvl2
            };

            let block2_raw = self.block_dev.read_block(lvl2_block)?;
            let mut ptrs2 = decode_ptrs(&block2_raw);
            let lvl3_block = if ptrs2[idx2] != 0 {
                ptrs2[idx2]
            } else {
                if !allocate {
                    return Ok(None);
                }
                let new_lvl3 = self.allocate_block()?;
                let zero = [0u8; PLAINTEXT_BLOCK_SIZE];
                self.block_dev.write_block(new_lvl3, &zero)?;
                ptrs2[idx2] = new_lvl3;
                self.block_dev
                    .write_block(lvl2_block, &encode_ptrs(&ptrs2))?;
                new_lvl3
            };

            let block3_raw = self.block_dev.read_block(lvl3_block)?;
            let mut ptrs3 = decode_ptrs(&block3_raw);
            let phys = ptrs3[idx3];
            if phys != 0 {
                return Ok(Some((phys, false)));
            }
            if !allocate {
                return Ok(None);
            }
            let new_phys = self.allocate_block()?;
            ptrs3[idx3] = new_phys;
            self.block_dev
                .write_block(lvl3_block, &encode_ptrs(&ptrs3))?;
            return Ok(Some((new_phys, true)));
        }

        Err(SunsetError::InvalidArgument(
            "File offset exceeds maximum supported size (512 GB)".to_string(),
        ))
    }

    pub fn read_bytes(&mut self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, SunsetError> {
        let inode = self.get_inode(ino)?.clone();
        if offset >= inode.size {
            return Ok(Vec::new());
        }

        let to_read = (size as u64).min(inode.size - offset) as usize;
        let mut result = Vec::with_capacity(to_read);
        let mut curr_offset = offset;
        let mut remaining = to_read;

        while remaining > 0 {
            let lblock = curr_offset / PLAINTEXT_BLOCK_SIZE as u64;
            let block_offset = (curr_offset % PLAINTEXT_BLOCK_SIZE as u64) as usize;
            let chunk_len = remaining.min(PLAINTEXT_BLOCK_SIZE - block_offset);

            if let Some((pblock, _)) = self.resolve_block(ino, lblock, false)? {
                let decrypted = self.block_dev.read_block(pblock)?;
                result.extend_from_slice(&decrypted[block_offset..block_offset + chunk_len]);
            } else {
                // Sparse hole: return zeroes
                result.resize(result.len() + chunk_len, 0);
            }

            curr_offset += chunk_len as u64;
            remaining -= chunk_len;
        }

        if let Ok(node) = self.get_inode_mut(ino) {
            node.update_atime();
        }
        Ok(result)
    }

    pub fn write_bytes(
        &mut self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, SunsetError> {
        if data.is_empty() {
            return Ok(0);
        }

        let mut curr_offset = offset;
        let mut remaining = data.len();
        let mut data_offset = 0;

        while remaining > 0 {
            let lblock = curr_offset / PLAINTEXT_BLOCK_SIZE as u64;
            let block_offset = (curr_offset % PLAINTEXT_BLOCK_SIZE as u64) as usize;
            let chunk_len = remaining.min(PLAINTEXT_BLOCK_SIZE - block_offset);

            let (pblock, was_new) = self
                .resolve_block(ino, lblock, true)?
                .ok_or(SunsetError::NoSpace)?;

            if block_offset > 0 || chunk_len < PLAINTEXT_BLOCK_SIZE {
                let mut block_buf = if was_new {
                    vec![0u8; PLAINTEXT_BLOCK_SIZE]
                } else {
                    match self.block_dev.read_block(pblock) {
                        Ok(b) => b,
                        Err(_) => vec![0u8; PLAINTEXT_BLOCK_SIZE],
                    }
                };
                block_buf[block_offset..block_offset + chunk_len]
                    .copy_from_slice(&data[data_offset..data_offset + chunk_len]);
                self.block_dev.write_block(pblock, &block_buf)?;
            } else {
                self.block_dev.write_block(
                    pblock,
                    &data[data_offset..data_offset + PLAINTEXT_BLOCK_SIZE],
                )?;
            }

            curr_offset += chunk_len as u64;
            data_offset += chunk_len;
            remaining -= chunk_len;
        }

        let node = self.get_inode_mut(ino)?;
        if curr_offset > node.size {
            node.size = curr_offset;
        }
        node.update_mtime();
        self.mark_inode_dirty(ino);

        Ok(data.len())
    }

    pub fn truncate(&mut self, ino: u64, new_size: u64) -> Result<(), SunsetError> {
        let inode = self.get_inode(ino)?.clone();
        if new_size == inode.size {
            return Ok(());
        }

        if new_size < inode.size {
            let last_keep_lblock = new_size / PLAINTEXT_BLOCK_SIZE as u64;
            let rem = (new_size % PLAINTEXT_BLOCK_SIZE as u64) as usize;

            // Zero out trailing partial block
            if rem > 0 {
                if let Some((pblock, _)) = self.resolve_block(ino, last_keep_lblock, false)? {
                    if let Ok(mut block) = self.block_dev.read_block(pblock) {
                        for b in &mut block[rem..PLAINTEXT_BLOCK_SIZE] {
                            *b = 0;
                        }
                        self.block_dev.write_block(pblock, &block)?;
                    }
                }
            }

            // Free truncated blocks
            let start_free_lblock = if rem > 0 {
                last_keep_lblock + 1
            } else {
                last_keep_lblock
            };

            let end_lblock = (inode.size + PLAINTEXT_BLOCK_SIZE as u64 - 1)
                / PLAINTEXT_BLOCK_SIZE as u64;

            for lb in start_free_lblock..end_lblock {
                if let Some((pb, _)) = self.resolve_block(ino, lb, false)? {
                    self.free_block(pb)?;
                    self.clear_block_ref(ino, lb)?;
                }
            }
        }

        let node = self.get_inode_mut(ino)?;
        node.size = new_size;
        node.update_mtime();
        self.mark_inode_dirty(ino);
        Ok(())
    }

    fn clear_block_ref(&mut self, ino: u64, lblock: u64) -> Result<(), SunsetError> {
        let inode = self.get_inode(ino)?.clone();
        if (lblock as usize) < DIRECT_BLOCKS {
            let node = self.get_inode_mut(ino)?;
            node.direct_blocks[lblock as usize] = 0;
            return Ok(());
        }

        let rel = lblock as usize - DIRECT_BLOCKS;
        if rel < PTRS_PER_BLOCK {
            if inode.indirect_block != 0 {
                let raw = self.block_dev.read_block(inode.indirect_block)?;
                let mut ptrs = decode_ptrs(&raw);
                ptrs[rel] = 0;
                self.block_dev
                    .write_block(inode.indirect_block, &encode_ptrs(&ptrs))?;
            }
            return Ok(());
        }

        let dbl_rel = rel - PTRS_PER_BLOCK;
        if dbl_rel < PTRS_PER_BLOCK * PTRS_PER_BLOCK {
            let idx1 = dbl_rel / PTRS_PER_BLOCK;
            let idx2 = dbl_rel % PTRS_PER_BLOCK;
            if inode.double_indirect_block != 0 {
                let raw1 = self.block_dev.read_block(inode.double_indirect_block)?;
                let ptrs1 = decode_ptrs(&raw1);
                if ptrs1[idx1] != 0 {
                    let raw2 = self.block_dev.read_block(ptrs1[idx1])?;
                    let mut ptrs2 = decode_ptrs(&raw2);
                    ptrs2[idx2] = 0;
                    self.block_dev
                        .write_block(ptrs1[idx1], &encode_ptrs(&ptrs2))?;
                }
            }
            return Ok(());
        }

        let triple_rel = dbl_rel - (PTRS_PER_BLOCK * PTRS_PER_BLOCK);
        let ptrs_sq = PTRS_PER_BLOCK * PTRS_PER_BLOCK;
        if triple_rel < PTRS_PER_BLOCK * ptrs_sq {
            let idx1 = triple_rel / ptrs_sq;
            let rem = triple_rel % ptrs_sq;
            let idx2 = rem / PTRS_PER_BLOCK;
            let idx3 = rem % PTRS_PER_BLOCK;

            if inode.triple_indirect_block != 0 {
                let raw1 = self.block_dev.read_block(inode.triple_indirect_block)?;
                let ptrs1 = decode_ptrs(&raw1);
                if ptrs1[idx1] != 0 {
                    let raw2 = self.block_dev.read_block(ptrs1[idx1])?;
                    let ptrs2 = decode_ptrs(&raw2);
                    if ptrs2[idx2] != 0 {
                        let raw3 = self.block_dev.read_block(ptrs2[idx2])?;
                        let mut ptrs3 = decode_ptrs(&raw3);
                        ptrs3[idx3] = 0;
                        self.block_dev
                            .write_block(ptrs2[idx2], &encode_ptrs(&ptrs3))?;
                    }
                }
            }
            return Ok(());
        }

        Ok(())
    }

    fn free_all_inode_blocks(&mut self, ino: u64) -> Result<(), SunsetError> {
        let inode = self.get_inode(ino)?.clone();

        // Direct
        for &pb in &inode.direct_blocks {
            if pb != 0 {
                self.free_block(pb)?;
            }
        }

        // Single indirect
        if inode.indirect_block != 0 {
            if let Ok(raw) = self.block_dev.read_block(inode.indirect_block) {
                let ptrs = decode_ptrs(&raw);
                for pb in ptrs {
                    if pb != 0 {
                        self.free_block(pb)?;
                    }
                }
            }
            self.free_block(inode.indirect_block)?;
        }

        // Double indirect
        if inode.double_indirect_block != 0 {
            if let Ok(raw1) = self.block_dev.read_block(inode.double_indirect_block) {
                let ptrs1 = decode_ptrs(&raw1);
                for b1 in ptrs1 {
                    if b1 != 0 {
                        if let Ok(raw2) = self.block_dev.read_block(b1) {
                            let ptrs2 = decode_ptrs(&raw2);
                            for b2 in ptrs2 {
                                if b2 != 0 {
                                    self.free_block(b2)?;
                                }
                            }
                        }
                        self.free_block(b1)?;
                    }
                }
            }
            self.free_block(inode.double_indirect_block)?;
        }

        // Triple indirect
        if inode.triple_indirect_block != 0 {
            if let Ok(raw1) = self.block_dev.read_block(inode.triple_indirect_block) {
                let ptrs1 = decode_ptrs(&raw1);
                for b1 in ptrs1 {
                    if b1 != 0 {
                        if let Ok(raw2) = self.block_dev.read_block(b1) {
                            let ptrs2 = decode_ptrs(&raw2);
                            for b2 in ptrs2 {
                                if b2 != 0 {
                                    if let Ok(raw3) = self.block_dev.read_block(b2) {
                                        let ptrs3 = decode_ptrs(&raw3);
                                        for b3 in ptrs3 {
                                            if b3 != 0 {
                                                self.free_block(b3)?;
                                            }
                                        }
                                    }
                                    self.free_block(b2)?;
                                }
                            }
                        }
                        self.free_block(b1)?;
                    }
                }
            }
            self.free_block(inode.triple_indirect_block)?;
        }

        Ok(())
    }

    pub fn read_dir_data(&mut self, ino: u64) -> Result<DirectoryData, SunsetError> {
        let inode = self.get_inode(ino)?;
        if inode.kind != InodeKind::Directory {
            return Err(SunsetError::NotADirectory(format!("inode #{}", ino)));
        }
        let size = inode.size as usize;
        if size == 0 {
            return Ok(DirectoryData::new());
        }
        let bytes = self.read_bytes(ino, 0, size)?;
        DirectoryData::from_bytes(&bytes)
    }

    pub fn write_dir_data(&mut self, ino: u64, dir: &DirectoryData) -> Result<(), SunsetError> {
        let bytes = dir.to_bytes()?;
        self.truncate(ino, 0)?;
        self.write_bytes(ino, 0, &bytes)?;
        Ok(())
    }

    pub fn lookup(&mut self, parent_ino: u64, name: &str) -> Result<Inode, SunsetError> {
        if name == "." {
            return self.get_inode(parent_ino).cloned();
        }
        if name == ".." {
            let parent = self.get_inode(parent_ino)?.parent_ino;
            return self.get_inode(parent).cloned();
        }
        let dir = self.read_dir_data(parent_ino)?;
        let entry = dir
            .find_entry(name)
            .ok_or_else(|| SunsetError::NotFound(name.to_string()))?;
        self.get_inode(entry.ino).cloned()
    }

    pub fn create_file(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Inode, SunsetError> {
        let mut dir = self.read_dir_data(parent_ino)?;
        if dir.find_entry(name).is_some() {
            return Err(SunsetError::AlreadyExists(name.to_string()));
        }

        let new_ino = self.superblock.next_ino;
        self.superblock.next_ino += 1;
        self.dirty_superblock = true;

        let file_inode = Inode::new_file(new_ino, parent_ino, mode, uid, gid);
        self.inodes.insert(new_ino, file_inode.clone());
        self.mark_inode_dirty(new_ino);

        dir.add_entry(new_ino, name, InodeKind::File)?;
        self.write_dir_data(parent_ino, &dir)?;

        Ok(file_inode)
    }

    pub fn mkdir(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Inode, SunsetError> {
        let mut dir = self.read_dir_data(parent_ino)?;
        if dir.find_entry(name).is_some() {
            return Err(SunsetError::AlreadyExists(name.to_string()));
        }

        let new_ino = self.superblock.next_ino;
        self.superblock.next_ino += 1;
        self.dirty_superblock = true;

        let dir_inode = Inode::new_directory(new_ino, parent_ino, mode, uid, gid);
        self.inodes.insert(new_ino, dir_inode.clone());
        self.mark_inode_dirty(new_ino);

        dir.add_entry(new_ino, name, InodeKind::Directory)?;
        self.write_dir_data(parent_ino, &dir)?;

        let parent = self.get_inode_mut(parent_ino)?;
        parent.nlink += 1;
        self.mark_inode_dirty(parent_ino);

        Ok(dir_inode)
    }

    pub fn unlink(&mut self, parent_ino: u64, name: &str) -> Result<(), SunsetError> {
        let mut dir = self.read_dir_data(parent_ino)?;
        let entry = dir
            .find_entry(name)
            .cloned()
            .ok_or_else(|| SunsetError::NotFound(name.to_string()))?;
        if entry.kind == InodeKind::Directory {
            return Err(SunsetError::IsADirectory(name.to_string()));
        }

        dir.remove_entry(name)?;
        self.write_dir_data(parent_ino, &dir)?;

        let child = self.get_inode_mut(entry.ino)?;
        child.nlink = child.nlink.saturating_sub(1);
        let nlink = child.nlink;

        if nlink == 0 {
            let is_open = self.open_inodes.get(&entry.ino).copied().unwrap_or(0) > 0;
            if !is_open {
                self.free_all_inode_blocks(entry.ino)?;
                self.inodes.remove(&entry.ino);
                self.dirty_inodes.remove(&entry.ino);
                self.dirty_superblock = true;
            } else {
                // Kept alive until handle is released
                self.mark_inode_dirty(entry.ino);
            }
        } else {
            self.mark_inode_dirty(entry.ino);
        }

        Ok(())
    }

    pub fn rmdir(&mut self, parent_ino: u64, name: &str) -> Result<(), SunsetError> {
        let mut dir = self.read_dir_data(parent_ino)?;
        let entry = dir
            .find_entry(name)
            .cloned()
            .ok_or_else(|| SunsetError::NotFound(name.to_string()))?;
        if entry.kind != InodeKind::Directory {
            return Err(SunsetError::NotADirectory(name.to_string()));
        }

        let child_dir = self.read_dir_data(entry.ino)?;
        if !child_dir.is_empty() {
            return Err(SunsetError::NotEmpty(name.to_string()));
        }

        dir.remove_entry(name)?;
        self.write_dir_data(parent_ino, &dir)?;

        self.free_all_inode_blocks(entry.ino)?;
        self.inodes.remove(&entry.ino);
        self.dirty_inodes.remove(&entry.ino);
        self.dirty_superblock = true;

        let parent = self.get_inode_mut(parent_ino)?;
        parent.nlink = parent.nlink.saturating_sub(1);
        self.mark_inode_dirty(parent_ino);

        Ok(())
    }

    pub fn rename(
        &mut self,
        old_parent_ino: u64,
        old_name: &str,
        new_parent_ino: u64,
        new_name: &str,
    ) -> Result<(), SunsetError> {
        let mut old_dir = self.read_dir_data(old_parent_ino)?;
        let entry = old_dir
            .find_entry(old_name)
            .cloned()
            .ok_or_else(|| SunsetError::NotFound(old_name.to_string()))?;

        if old_parent_ino == new_parent_ino {
            if old_name == new_name {
                return Ok(());
            }
            if old_dir.find_entry(new_name).is_some() {
                let target = old_dir.find_entry(new_name).unwrap().clone();
                if target.kind == InodeKind::Directory {
                    let target_dir = self.read_dir_data(target.ino)?;
                    if !target_dir.is_empty() {
                        return Err(SunsetError::NotEmpty(new_name.to_string()));
                    }
                }
                self.unlink_or_rmdir(new_parent_ino, new_name)?;
                old_dir = self.read_dir_data(old_parent_ino)?;
            }
            old_dir.remove_entry(old_name)?;
            old_dir.add_entry(entry.ino, new_name, entry.kind)?;
            self.write_dir_data(old_parent_ino, &old_dir)?;
        } else {
            let mut new_dir = self.read_dir_data(new_parent_ino)?;
            if new_dir.find_entry(new_name).is_some() {
                self.unlink_or_rmdir(new_parent_ino, new_name)?;
                new_dir = self.read_dir_data(new_parent_ino)?;
                old_dir = self.read_dir_data(old_parent_ino)?;
            }
            old_dir.remove_entry(old_name)?;
            new_dir.add_entry(entry.ino, new_name, entry.kind)?;
            self.write_dir_data(old_parent_ino, &old_dir)?;
            self.write_dir_data(new_parent_ino, &new_dir)?;

            let child = self.get_inode_mut(entry.ino)?;
            child.parent_ino = new_parent_ino;
            self.mark_inode_dirty(entry.ino);
        }

        Ok(())
    }

    fn unlink_or_rmdir(&mut self, parent_ino: u64, name: &str) -> Result<(), SunsetError> {
        let dir = self.read_dir_data(parent_ino)?;
        let entry = dir
            .find_entry(name)
            .ok_or_else(|| SunsetError::NotFound(name.to_string()))?;
        if entry.kind == InodeKind::Directory {
            self.rmdir(parent_ino, name)
        } else {
            self.unlink(parent_ino, name)
        }
    }

    pub fn flush(&mut self) -> Result<(), SunsetError> {
        if self.dirty_inodes.is_empty() && !self.dirty_superblock {
            return Ok(());
        }

        // Serialize all inodes
        let inode_bytes = bincode::serialize(&self.inodes)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize inodes: {}", e)))?;

        let needed_blocks = ((inode_bytes.len() + PLAINTEXT_BLOCK_SIZE - 1)
            / PLAINTEXT_BLOCK_SIZE)
            .max(1);

        // Allocate additional blocks if needed
        while self.superblock.inode_blocks.len() < needed_blocks {
            let b = self.allocate_block()?;
            self.superblock.inode_blocks.push(b);
            self.dirty_superblock = true;
        }

        // Free excess blocks if inode table shrank
        while self.superblock.inode_blocks.len() > needed_blocks {
            let b = self.superblock.inode_blocks.pop().unwrap();
            self.free_block(b)?;
            self.dirty_superblock = true;
        }

        // Write inode blocks
        for (i, &b) in self.superblock.inode_blocks.iter().enumerate() {
            let start = i * PLAINTEXT_BLOCK_SIZE;
            let end = (start + PLAINTEXT_BLOCK_SIZE).min(inode_bytes.len());
            let mut block_data = [0u8; PLAINTEXT_BLOCK_SIZE];
            if start < inode_bytes.len() {
                block_data[..end - start].copy_from_slice(&inode_bytes[start..end]);
            }
            self.block_dev.write_block(b, &block_data)?;
        }

        // Dual superblock update: increment seq and alternate target
        self.superblock.seq += 1;
        self.superblock.modified_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sb_bytes = bincode::serialize(&self.superblock)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize superblock: {}", e)))?;

        let target_sb_block = if self.active_sb_block == SUPERBLOCK_0_ID {
            SUPERBLOCK_1_ID
        } else {
            SUPERBLOCK_0_ID
        };

        // Write new superblock to target, flush to disk
        self.block_dev.write_block(target_sb_block, &sb_bytes)?;
        self.block_dev.flush()?;
        self.active_sb_block = target_sb_block;

        // Also mirror to the other superblock
        let other_sb_block = if self.active_sb_block == SUPERBLOCK_0_ID {
            SUPERBLOCK_1_ID
        } else {
            SUPERBLOCK_0_ID
        };
        self.block_dev.write_block(other_sb_block, &sb_bytes)?;
        self.block_dev.flush()?;

        self.dirty_inodes.clear();
        self.dirty_superblock = false;

        Ok(())
    }

    pub fn total_blocks(&self) -> u64 {
        self.superblock.total_blocks
    }

    pub fn free_blocks_count(&self) -> u64 {
        self.superblock.free_blocks.len() as u64
    }

    pub fn inodes_count(&self) -> u64 {
        self.inodes.len() as u64
    }
}

impl Drop for SunsetEngine {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

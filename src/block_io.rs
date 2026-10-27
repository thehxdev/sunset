use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::crypto::{
    create_cipher, create_verification_token, decrypt_block_with_cipher, derive_key,
    encrypt_block_with_cipher, generate_nonce, generate_salt, verify_key, MasterKey,
    ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, NONCE_SIZE,
};
use crate::error::SunsetError;
use crate::format::{
    HEADER_SIZE, OnDiskHeader, PLAINTEXT_BLOCK_SIZE, STORED_BLOCK_SIZE,
};

pub const DEFAULT_CACHE_CAPACITY: usize = 2048; // 8 MB cache (2048 * 4KB)

#[cfg(unix)]
fn pwrite_exact(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(unix)]
fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn pwrite_exact(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0;
    while written < buf.len() {
        let n = file.seek_write(&buf[written..], offset + written as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        written += n;
    }
    Ok(())
}

#[cfg(windows)]
fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0;
    while read < buf.len() {
        let n = file.seek_read(&mut buf[read..], offset + read as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ));
        }
        read += n;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn pwrite_exact(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(buf)
}

#[cfg(not(any(unix, windows)))]
fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
}

struct CacheNode {
    block_id: u64,
    data: Box<[u8; PLAINTEXT_BLOCK_SIZE]>,
    dirty: bool,
    prev: Option<usize>,
    next: Option<usize>,
}

pub struct BlockCache {
    capacity: usize,
    nodes: Vec<CacheNode>,
    map: HashMap<u64, usize>,
    free_slots: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
}

impl BlockCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(16),
            nodes: Vec::with_capacity(capacity),
            map: HashMap::with_capacity(capacity),
            free_slots: Vec::new(),
            head: None,
            tail: None,
        }
    }

    fn remove_node(&mut self, idx: usize) {
        let prev = self.nodes[idx].prev;
        let next = self.nodes[idx].next;
        if let Some(p) = prev {
            self.nodes[p].next = next;
        } else if self.head == Some(idx) {
            self.head = next;
        }
        if let Some(n) = next {
            self.nodes[n].prev = prev;
        } else if self.tail == Some(idx) {
            self.tail = prev;
        }
        self.nodes[idx].prev = None;
        self.nodes[idx].next = None;
    }

    fn push_head(&mut self, idx: usize) {
        self.nodes[idx].prev = None;
        self.nodes[idx].next = self.head;
        if let Some(h) = self.head {
            self.nodes[h].prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx);
        }
    }

    fn move_to_head(&mut self, idx: usize) {
        if self.head != Some(idx) {
            self.remove_node(idx);
            self.push_head(idx);
        }
    }

    fn pop_tail(&mut self) -> Option<usize> {
        let t = self.tail?;
        self.remove_node(t);
        Some(t)
    }

    pub fn get(&mut self, block_id: u64) -> Option<&[u8; PLAINTEXT_BLOCK_SIZE]> {
        if let Some(&idx) = self.map.get(&block_id) {
            self.move_to_head(idx);
            Some(&*self.nodes[idx].data)
        } else {
            None
        }
    }

    pub fn put(
        &mut self,
        block_id: u64,
        data: Box<[u8; PLAINTEXT_BLOCK_SIZE]>,
        dirty: bool,
    ) -> Option<(u64, Box<[u8; PLAINTEXT_BLOCK_SIZE]>)> {
        if let Some(&idx) = self.map.get(&block_id) {
            self.nodes[idx].data = data;
            self.nodes[idx].dirty |= dirty;
            self.move_to_head(idx);
            return None;
        }

        if let Some(slot) = self.free_slots.pop() {
            self.nodes[slot] = CacheNode {
                block_id,
                data,
                dirty,
                prev: None,
                next: None,
            };
            self.push_head(slot);
            self.map.insert(block_id, slot);
            return None;
        }

        if self.nodes.len() < self.capacity {
            let slot = self.nodes.len();
            self.nodes.push(CacheNode {
                block_id,
                data,
                dirty,
                prev: None,
                next: None,
            });
            self.push_head(slot);
            self.map.insert(block_id, slot);
            return None;
        }

        // Evict LRU tail
        let tail_idx = self.pop_tail()?;
        let evicted_block = self.nodes[tail_idx].block_id;
        let evicted_dirty = self.nodes[tail_idx].dirty;
        self.map.remove(&evicted_block);

        let evicted_data = if evicted_dirty {
            Some((evicted_block, self.nodes[tail_idx].data.clone()))
        } else {
            None
        };

        self.nodes[tail_idx].block_id = block_id;
        self.nodes[tail_idx].data = data;
        self.nodes[tail_idx].dirty = dirty;
        self.push_head(tail_idx);
        self.map.insert(block_id, tail_idx);

        evicted_data
    }

    pub fn invalidate(&mut self, block_id: u64) {
        if let Some(idx) = self.map.remove(&block_id) {
            self.remove_node(idx);
            self.free_slots.push(idx);
        }
    }

    pub fn invalidate_above_or_equal(&mut self, threshold_block: u64) {
        let to_remove: Vec<u64> = self
            .map
            .keys()
            .copied()
            .filter(|&id| id >= threshold_block)
            .collect();
        for id in to_remove {
            self.invalidate(id);
        }
    }

    pub fn take_dirty_sorted(&mut self) -> Vec<(u64, Box<[u8; PLAINTEXT_BLOCK_SIZE]>)> {
        let mut dirty = Vec::new();
        for node in &mut self.nodes {
            if node.dirty && self.map.contains_key(&node.block_id) {
                dirty.push((node.block_id, node.data.clone()));
                node.dirty = false;
            }
        }
        dirty.sort_unstable_by_key(|&(id, _)| id);
        dirty
    }
}

pub struct BlockDevice {
    file: File,
    key: MasterKey,
    header: OnDiskHeader,
    cipher: chacha20poly1305::XChaCha20Poly1305,
    file_len: u64,
    cache: BlockCache,
}

impl BlockDevice {
    pub fn create(
        path: &Path,
        passphrase: &str,
        initial_blocks: Option<u64>,
    ) -> Result<Self, SunsetError> {
        let salt = generate_salt();
        let key = derive_key(
            passphrase,
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )?;
        let (verify_nonce, verify_ct, verify_tag) = create_verification_token(&key)?;

        let header = OnDiskHeader::new(
            salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            verify_nonce,
            verify_ct,
            verify_tag,
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to create archive '{}': {}", path.display(), e),
                ))
            })?;

        let header_bytes = header.to_bytes()?;
        pwrite_exact(&file, &header_bytes, 0)?;

        let cipher = create_cipher(&key);
        let file_len = header_bytes.len() as u64;
        let cache = BlockCache::new(DEFAULT_CACHE_CAPACITY);

        let mut dev = Self {
            file,
            key,
            header,
            cipher,
            file_len,
            cache,
        };

        if let Some(blocks) = initial_blocks {
            let zero_block = [0u8; PLAINTEXT_BLOCK_SIZE];
            for i in 0..blocks {
                dev.write_block(i, &zero_block)?;
            }
        }

        dev.flush()?;
        Ok(dev)
    }

    pub fn open(path: &Path, passphrase: &str) -> Result<Self, SunsetError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to open archive '{}': {}", path.display(), e),
                ))
            })?;

        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE as u64 {
            return Err(SunsetError::Format(
                "Archive file is too small to contain valid Sunset header".to_string(),
            ));
        }

        let mut header_buf = [0u8; HEADER_SIZE];
        pread_exact(&file, &mut header_buf, 0).map_err(|e| {
            SunsetError::Format(format!(
                "Failed to read archive header from '{}': {}",
                path.display(),
                e
            ))
        })?;

        let header = OnDiskHeader::from_bytes(&header_buf)?;

        let key = derive_key(
            passphrase,
            &header.salt,
            header.m_cost,
            header.t_cost,
            header.p_cost,
        )?;

        verify_key(&key, &header.verify_nonce, &header.verify_ct, &header.verify_tag)
            .map_err(|_| SunsetError::InvalidKey)?;

        let cipher = create_cipher(&key);
        let cache = BlockCache::new(DEFAULT_CACHE_CAPACITY);

        Ok(Self {
            file,
            key,
            header,
            cipher,
            file_len,
            cache,
        })
    }

    pub fn header(&self) -> &OnDiskHeader {
        &self.header
    }

    pub fn key(&self) -> &MasterKey {
        &self.key
    }

    fn block_offset(block_index: u64) -> u64 {
        HEADER_SIZE as u64 + block_index * STORED_BLOCK_SIZE as u64
    }

    fn write_block_to_disk(
        &self,
        block_index: u64,
        data: &[u8; PLAINTEXT_BLOCK_SIZE],
    ) -> Result<(), SunsetError> {
        let offset = Self::block_offset(block_index);
        let nonce = generate_nonce();
        let aad = block_index.to_le_bytes();
        let ciphertext = encrypt_block_with_cipher(&self.cipher, &nonce, data, &aad)?;

        let mut raw_buf = vec![0u8; STORED_BLOCK_SIZE];
        raw_buf[..NONCE_SIZE].copy_from_slice(&nonce);
        raw_buf[NONCE_SIZE..].copy_from_slice(&ciphertext);

        pwrite_exact(&self.file, &raw_buf, offset)?;
        Ok(())
    }

    fn read_block_from_disk(&self, block_index: u64) -> Result<Vec<u8>, SunsetError> {
        let offset = Self::block_offset(block_index);
        let mut raw_buf = vec![0u8; STORED_BLOCK_SIZE];
        pread_exact(&self.file, &mut raw_buf, offset)?;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&raw_buf[..NONCE_SIZE]);
        let ciphertext = &raw_buf[NONCE_SIZE..];

        let aad = block_index.to_le_bytes();
        let decrypted = decrypt_block_with_cipher(&self.cipher, &nonce, ciphertext, &aad)
            .map_err(|_| SunsetError::CorruptedBlock(block_index))?;

        Ok(decrypted)
    }

    pub fn read_block(&mut self, block_index: u64) -> Result<Vec<u8>, SunsetError> {
        if let Some(cached) = self.cache.get(block_index) {
            return Ok(cached.to_vec());
        }

        let offset = Self::block_offset(block_index);
        if offset + STORED_BLOCK_SIZE as u64 > self.file_len {
            return Err(SunsetError::CorruptedBlock(block_index));
        }

        let decrypted = self.read_block_from_disk(block_index)?;
        let mut box_data = Box::new([0u8; PLAINTEXT_BLOCK_SIZE]);
        box_data.copy_from_slice(&decrypted);

        if let Some((evicted_id, evicted_data)) = self.cache.put(block_index, box_data, false) {
            self.write_block_to_disk(evicted_id, &evicted_data)?;
        }

        Ok(decrypted)
    }

    pub fn write_block(&mut self, block_index: u64, data: &[u8]) -> Result<(), SunsetError> {
        let mut payload = Box::new([0u8; PLAINTEXT_BLOCK_SIZE]);
        let copy_len = data.len().min(PLAINTEXT_BLOCK_SIZE);
        payload[..copy_len].copy_from_slice(&data[..copy_len]);

        let end_offset = Self::block_offset(block_index) + STORED_BLOCK_SIZE as u64;
        if end_offset > self.file_len {
            self.file_len = end_offset;
        }

        if let Some((evicted_id, evicted_data)) = self.cache.put(block_index, payload, true) {
            self.write_block_to_disk(evicted_id, &evicted_data)?;
        }

        Ok(())
    }

    pub fn invalidate_block(&mut self, block_index: u64) {
        self.cache.invalidate(block_index);
    }

    pub fn total_blocks_on_disk(&mut self) -> Result<u64, SunsetError> {
        if self.file_len < HEADER_SIZE as u64 {
            return Ok(0);
        }
        Ok((self.file_len - HEADER_SIZE as u64) / STORED_BLOCK_SIZE as u64)
    }

    pub fn file_size(&self) -> Result<u64, SunsetError> {
        Ok(self.file_len)
    }

    pub fn truncate(&mut self, total_blocks: u64) -> Result<(), SunsetError> {
        self.cache.invalidate_above_or_equal(total_blocks);
        self.file_len = Self::block_offset(total_blocks);
        self.file.set_len(self.file_len)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn update_header_change_counter(&mut self, counter: u64) -> Result<(), SunsetError> {
        self.header.change_counter = counter;
        let bytes = self.header.to_bytes()?;
        pwrite_exact(&self.file, &bytes, 0)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), SunsetError> {
        let dirty = self.cache.take_dirty_sorted();
        for (bid, data) in dirty {
            self.write_block_to_disk(bid, &data)?;
        }
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_device_lifecycle() {
        let dir = std::env::temp_dir();
        let path = dir.join("sunset_test_block_device_prod.bin");
        let _ = std::fs::remove_file(&path);

        let pass = "vault_master_key_123!";
        {
            let mut dev = BlockDevice::create(&path, pass, None).unwrap();
            let mut data = vec![0u8; PLAINTEXT_BLOCK_SIZE];
            data[0..5].copy_from_slice(b"HELLO");
            dev.write_block(0, &data).unwrap();
            dev.flush().unwrap();
        }

        // Reopen with right pass
        {
            let mut dev = BlockDevice::open(&path, pass).unwrap();
            let read_data = dev.read_block(0).unwrap();
            assert_eq!(&read_data[0..5], b"HELLO");
        }

        // Reopen with wrong pass
        {
            let res = BlockDevice::open(&path, "wrong_pass");
            assert!(matches!(res, Err(SunsetError::InvalidKey)));
        }

        let _ = std::fs::remove_file(&path);
    }
}

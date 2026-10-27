use crate::crypto::{NONCE_SIZE, SALT_SIZE, TAG_SIZE, VERIFY_MSG_LEN};
use crate::error::SunsetError;
use serde::{Deserialize, Serialize};

/// Dedicated file format signature (mirrors SQLite3 signature design).
/// 16 bytes: ASCII "SUNSET format 1\0"
pub const SUNSET_MAGIC: &[u8; 16] = b"SUNSET format 1\0";
pub const MAGIC: &[u8; 16] = SUNSET_MAGIC;

/// Magic for decrypted Superblock plaintext payload.
pub const SUNSET_SB_MAGIC: &[u8; 8] = b"SUNSETSB";

pub const FORMAT_VERSION: u32 = 1;
pub const COMPAT_VERSION: u32 = 1;

/// Application ID for Sunset ("SUNS" in ASCII big-endian / 0x53554E53)
pub const APP_ID: u32 = 0x5355_4E53;

pub const HEADER_SIZE: usize = 256;
pub const PLAINTEXT_BLOCK_SIZE: usize = 4096;
pub const STORED_BLOCK_SIZE: usize = NONCE_SIZE + PLAINTEXT_BLOCK_SIZE + TAG_SIZE; // 24 + 4096 + 16 = 4136

pub const SUPERBLOCK_0_ID: u64 = 0;
pub const SUPERBLOCK_1_ID: u64 = 1;
pub const FIRST_ALLOCATABLE_BLOCK: u64 = 2;
pub const ROOT_INODE_ID: u64 = 1;
pub const MAX_NAME_LEN: usize = 255;

pub const AUTO_VACUUM_NONE: u32 = 0;
pub const AUTO_VACUUM_FULL: u32 = 1;

pub const KDF_ARGON2ID: u32 = 1;
pub const CIPHER_XCHACHA20_POLY1305: u32 = 1;

/// IEEE 802.3 standard 32-bit Cyclic Redundancy Check (polynomial 0xEDB88320).
/// Deterministic and identical across all CPU architectures and platforms.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Standard deterministic bincode configuration for cross-platform portability.
/// Forces fixed-width integers (no varint variance) and Little-Endian byte order.
pub type BincodeConfig = bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::NoLimit,
>;

pub fn bincode_config() -> BincodeConfig {
    bincode::config::standard()
        .with_fixed_int_encoding()
        .with_little_endian()
}

/// Fixed 256-byte plaintext on-disk header at offset 0 of every Sunset archive.
///
/// Layout (Little-Endian):
/// - 0x00..0x10 (16B): Magic signature `b"SUNSET format 1\0"`
/// - 0x10..0x14  (4B): Format write version (1)
/// - 0x14..0x18  (4B): Minimum compatible read version (1)
/// - 0x18..0x1C  (4B): Plaintext block size (4096)
/// - 0x1C..0x20  (4B): Stored physical block size (4136)
/// - 0x20..0x24  (4B): KDF algorithm ID (1 = Argon2id)
/// - 0x24..0x28  (4B): KDF memory cost `m_cost`
/// - 0x28..0x2C  (4B): KDF time cost `t_cost`
/// - 0x2C..0x30  (4B): KDF parallelism `p_cost`
/// - 0x30..0x50 (32B): KDF salt
/// - 0x50..0x54  (4B): Cipher algorithm ID (1 = XChaCha20-Poly1305)
/// - 0x54..0x6C (24B): Key verification nonce
/// - 0x6C..0x8C (32B): Key verification ciphertext
/// - 0x8C..0x9C (16B): Key verification Poly1305 MAC tag
/// - 0x9C..0xA0  (4B): Auto-vacuum mode (1 = full auto-shrink on file deletion)
/// - 0xA0..0xA8  (8B): Change counter / file generation counter
/// - 0xA8..0xAC  (4B): Application ID (`0x53554E53` / "SUNS")
/// - 0xAC..0xFC (80B): Reserved bytes for future expansion (0x00)
/// - 0xFC..0x100 (4B): Header CRC32 checksum (covers bytes 0x00..0xFC)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDiskHeader {
    pub signature: [u8; 16],
    pub format_version: u32,
    pub compat_version: u32,
    pub block_size: u32,
    pub stored_block_size: u32,
    pub kdf_algo: u32,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_SIZE],
    pub cipher_algo: u32,
    pub verify_nonce: [u8; NONCE_SIZE],
    pub verify_ct: [u8; VERIFY_MSG_LEN],
    pub verify_tag: [u8; TAG_SIZE],
    pub auto_vacuum: u32,
    pub change_counter: u64,
    pub app_id: u32,
    pub reserved: [u8; 80],
    pub checksum: u32,
}

impl OnDiskHeader {
    pub fn new(
        salt: [u8; SALT_SIZE],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        verify_nonce: [u8; NONCE_SIZE],
        verify_ct: [u8; VERIFY_MSG_LEN],
        verify_tag: [u8; TAG_SIZE],
    ) -> Self {
        let mut header = Self {
            signature: *SUNSET_MAGIC,
            format_version: FORMAT_VERSION,
            compat_version: COMPAT_VERSION,
            block_size: PLAINTEXT_BLOCK_SIZE as u32,
            stored_block_size: STORED_BLOCK_SIZE as u32,
            kdf_algo: KDF_ARGON2ID,
            m_cost,
            t_cost,
            p_cost,
            salt,
            cipher_algo: CIPHER_XCHACHA20_POLY1305,
            verify_nonce,
            verify_ct,
            verify_tag,
            auto_vacuum: AUTO_VACUUM_FULL,
            change_counter: 1,
            app_id: APP_ID,
            reserved: [0u8; 80],
            checksum: 0,
        };
        if let Ok(bytes) = header.to_bytes() {
            header.checksum = u32::from_le_bytes(bytes[252..256].try_into().unwrap());
        }
        header
    }

    /// Serializes header to exact 256-byte binary representation with LE integers and CRC32.
    pub fn to_bytes(&self) -> Result<[u8; HEADER_SIZE], SunsetError> {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..16].copy_from_slice(&self.signature);
        buf[16..20].copy_from_slice(&self.format_version.to_le_bytes());
        buf[20..24].copy_from_slice(&self.compat_version.to_le_bytes());
        buf[24..28].copy_from_slice(&self.block_size.to_le_bytes());
        buf[28..32].copy_from_slice(&self.stored_block_size.to_le_bytes());
        buf[32..36].copy_from_slice(&self.kdf_algo.to_le_bytes());
        buf[36..40].copy_from_slice(&self.m_cost.to_le_bytes());
        buf[40..44].copy_from_slice(&self.t_cost.to_le_bytes());
        buf[44..48].copy_from_slice(&self.p_cost.to_le_bytes());
        buf[48..80].copy_from_slice(&self.salt);
        buf[80..84].copy_from_slice(&self.cipher_algo.to_le_bytes());
        buf[84..108].copy_from_slice(&self.verify_nonce);
        buf[108..140].copy_from_slice(&self.verify_ct);
        buf[140..156].copy_from_slice(&self.verify_tag);
        buf[156..160].copy_from_slice(&self.auto_vacuum.to_le_bytes());
        buf[160..168].copy_from_slice(&self.change_counter.to_le_bytes());
        buf[168..172].copy_from_slice(&self.app_id.to_le_bytes());
        buf[172..252].copy_from_slice(&self.reserved);

        let crc = crc32(&buf[0..252]);
        buf[252..256].copy_from_slice(&crc.to_le_bytes());

        Ok(buf)
    }

    /// Deserializes header from raw 256-byte slice with strict validation and CRC32 verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SunsetError> {
        if bytes.len() < HEADER_SIZE {
            return Err(SunsetError::Format(
                "Header is too short to be a valid Sunset archive".to_string(),
            ));
        }

        // Verify CRC32 checksum first
        let stored_crc = u32::from_le_bytes(
            bytes[252..256]
                .try_into()
                .map_err(|_| SunsetError::Format("Failed to parse checksum".to_string()))?,
        );
        let computed_crc = crc32(&bytes[0..252]);
        if stored_crc != computed_crc {
            return Err(SunsetError::Format(format!(
                "Archive header checksum mismatch: corrupted header (stored 0x{:08X}, expected 0x{:08X})",
                stored_crc, computed_crc
            )));
        }

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&bytes[0..16]);
        if &signature != SUNSET_MAGIC {
            return Err(SunsetError::Format(
                "Invalid archive signature: not a valid Sunset archive file".to_string(),
            ));
        }

        let format_version = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let compat_version = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let block_size = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let stored_block_size = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        let kdf_algo = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let m_cost = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let t_cost = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let p_cost = u32::from_le_bytes(bytes[44..48].try_into().unwrap());

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[48..80]);

        let cipher_algo = u32::from_le_bytes(bytes[80..84].try_into().unwrap());

        let mut verify_nonce = [0u8; NONCE_SIZE];
        verify_nonce.copy_from_slice(&bytes[84..108]);

        let mut verify_ct = [0u8; VERIFY_MSG_LEN];
        verify_ct.copy_from_slice(&bytes[108..140]);

        let mut verify_tag = [0u8; TAG_SIZE];
        verify_tag.copy_from_slice(&bytes[140..156]);

        let auto_vacuum = u32::from_le_bytes(bytes[156..160].try_into().unwrap());
        let change_counter = u64::from_le_bytes(bytes[160..168].try_into().unwrap());
        let app_id = u32::from_le_bytes(bytes[168..172].try_into().unwrap());

        let mut reserved = [0u8; 80];
        reserved.copy_from_slice(&bytes[172..252]);

        if format_version > FORMAT_VERSION || compat_version > FORMAT_VERSION {
            return Err(SunsetError::Format(format!(
                "Unsupported archive version: {} (current version: {})",
                format_version, FORMAT_VERSION
            )));
        }

        if block_size != PLAINTEXT_BLOCK_SIZE as u32 {
            return Err(SunsetError::Format(format!(
                "Unsupported block size: {} (expected {})",
                block_size, PLAINTEXT_BLOCK_SIZE
            )));
        }

        if stored_block_size != STORED_BLOCK_SIZE as u32 {
            return Err(SunsetError::Format(format!(
                "Unsupported stored block size: {} (expected {})",
                stored_block_size, STORED_BLOCK_SIZE
            )));
        }

        if app_id != APP_ID {
            return Err(SunsetError::Format(format!(
                "Invalid application ID: 0x{:08X} (expected 0x{:08X})",
                app_id, APP_ID
            )));
        }

        Ok(Self {
            signature,
            format_version,
            compat_version,
            block_size,
            stored_block_size,
            kdf_algo,
            m_cost,
            t_cost,
            p_cost,
            salt,
            cipher_algo,
            verify_nonce,
            verify_ct,
            verify_tag,
            auto_vacuum,
            change_counter,
            app_id,
            reserved,
            checksum: stored_crc,
        })
    }
}

/// In-memory representation of decrypted Superblock payload with explicit binary wire serialization.
///
/// Plaintext wire layout (4096 bytes):
/// - 0x00..0x08 (8B): Magic `b"SUNSETSB"`
/// - 0x08..0x0C (4B): Format version (1)
/// - 0x0C..0x14 (8B): Sequence number (`seq`)
/// - 0x14..0x1C (8B): Root inode ID (`root_ino`)
/// - 0x1C..0x24 (8B): Next inode ID (`next_ino`)
/// - 0x24..0x2C (8B): Total physical blocks in file (`total_blocks`)
/// - 0x2C..0x34 (8B): Modified timestamp (`modified_time`)
/// - 0x34..0x38 (4B): Auto-vacuum mode (1 = full)
/// - 0x38..0x40 (8B): Freelist trunk block (0 = none)
/// - 0x40..0x44 (4B): Inode blocks count
/// - 0x44..0x48 (4B): Inline free blocks count
/// - 0x48..0x4C (4B): Reserved
/// - 0x4C..0x50 (4B): Payload CRC32 (covers 0x00..0x4C and block pointer lists)
/// - 0x50..: Inode blocks (`[u64; inode_blocks_count]`, LE)
/// - Followed by inline free blocks (`[u64; free_blocks_count]`, LE)
/// - Remaining bytes to 4096: zero padding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuperblockPayload {
    pub seq: u64,
    pub root_ino: u64,
    pub next_ino: u64,
    pub total_blocks: u64,
    pub modified_time: u64,
    pub auto_vacuum: u32,
    pub freelist_trunk: u64,
    pub free_blocks: Vec<u64>,
    pub inode_blocks: Vec<u64>,
}

impl Default for SuperblockPayload {
    fn default() -> Self {
        Self::new()
    }
}

impl SuperblockPayload {
    pub fn new() -> Self {
        Self {
            seq: 1,
            root_ino: ROOT_INODE_ID,
            next_ino: ROOT_INODE_ID + 1,
            total_blocks: FIRST_ALLOCATABLE_BLOCK, // 0 and 1 reserved for superblocks
            modified_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            auto_vacuum: AUTO_VACUUM_FULL,
            freelist_trunk: 0,
            free_blocks: Vec::new(),
            inode_blocks: Vec::new(),
        }
    }

    /// Serializes superblock into deterministic 4096-byte plaintext wire format.
    pub fn to_bytes(&self) -> Result<[u8; PLAINTEXT_BLOCK_SIZE], SunsetError> {
        let max_ptrs = (PLAINTEXT_BLOCK_SIZE - 80) / 8;
        let total_ptrs = self.inode_blocks.len() + self.free_blocks.len();
        if total_ptrs > max_ptrs {
            return Err(SunsetError::Format(format!(
                "Superblock block pointer overflow: {} pointers exceed maximum capacity of {}",
                total_ptrs, max_ptrs
            )));
        }

        let mut buf = [0u8; PLAINTEXT_BLOCK_SIZE];
        buf[0..8].copy_from_slice(SUNSET_SB_MAGIC);
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf[12..20].copy_from_slice(&self.seq.to_le_bytes());
        buf[20..28].copy_from_slice(&self.root_ino.to_le_bytes());
        buf[28..36].copy_from_slice(&self.next_ino.to_le_bytes());
        buf[36..44].copy_from_slice(&self.total_blocks.to_le_bytes());
        buf[44..52].copy_from_slice(&self.modified_time.to_le_bytes());
        buf[52..56].copy_from_slice(&self.auto_vacuum.to_le_bytes());
        buf[56..64].copy_from_slice(&self.freelist_trunk.to_le_bytes());
        buf[64..68].copy_from_slice(&(self.inode_blocks.len() as u32).to_le_bytes());
        buf[68..72].copy_from_slice(&(self.free_blocks.len() as u32).to_le_bytes());
        // 72..76 reserved (zeroed)

        let mut offset = 80;
        for &b in &self.inode_blocks {
            buf[offset..offset + 8].copy_from_slice(&b.to_le_bytes());
            offset += 8;
        }
        for &b in &self.free_blocks {
            buf[offset..offset + 8].copy_from_slice(&b.to_le_bytes());
            offset += 8;
        }

        // Calculate CRC32 over header fields (0..76) and block lists (80..offset)
        let mut crc_data = Vec::with_capacity(76 + (offset - 80));
        crc_data.extend_from_slice(&buf[0..76]);
        crc_data.extend_from_slice(&buf[80..offset]);
        let crc = crc32(&crc_data);
        buf[76..80].copy_from_slice(&crc.to_le_bytes());

        Ok(buf)
    }

    /// Deserializes superblock from 4096-byte plaintext wire format with CRC32 verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SunsetError> {
        if bytes.len() < PLAINTEXT_BLOCK_SIZE {
            return Err(SunsetError::Format(
                "Superblock payload buffer is too small".to_string(),
            ));
        }

        if &bytes[0..8] != SUNSET_SB_MAGIC {
            return Err(SunsetError::Format(
                "Invalid superblock magic: corrupted superblock block".to_string(),
            ));
        }

        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version > FORMAT_VERSION {
            return Err(SunsetError::Format(format!(
                "Unsupported superblock version: {}",
                version
            )));
        }

        let seq = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let root_ino = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        let next_ino = u64::from_le_bytes(bytes[28..36].try_into().unwrap());
        let total_blocks = u64::from_le_bytes(bytes[36..44].try_into().unwrap());
        let modified_time = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
        let auto_vacuum = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let freelist_trunk = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        let inode_count = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
        let free_count = u32::from_le_bytes(bytes[68..72].try_into().unwrap()) as usize;
        let stored_crc = u32::from_le_bytes(bytes[76..80].try_into().unwrap());

        let max_ptrs = (PLAINTEXT_BLOCK_SIZE - 80) / 8;
        if inode_count + free_count > max_ptrs {
            return Err(SunsetError::Format(
                "Superblock block pointer count exceeds payload capacity".to_string(),
            ));
        }

        let total_payload_bytes = 80 + (inode_count + free_count) * 8;
        let mut crc_data = Vec::with_capacity(76 + (total_payload_bytes - 80));
        crc_data.extend_from_slice(&bytes[0..76]);
        crc_data.extend_from_slice(&bytes[80..total_payload_bytes]);
        let computed_crc = crc32(&crc_data);
        if stored_crc != computed_crc {
            return Err(SunsetError::Format(format!(
                "Superblock CRC32 checksum mismatch (stored 0x{:08X}, expected 0x{:08X})",
                stored_crc, computed_crc
            )));
        }

        let mut offset = 80;
        let mut inode_blocks = Vec::with_capacity(inode_count);
        for _ in 0..inode_count {
            let b = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            inode_blocks.push(b);
            offset += 8;
        }

        let mut free_blocks = Vec::with_capacity(free_count);
        for _ in 0..free_count {
            let b = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            free_blocks.push(b);
            offset += 8;
        }

        Ok(Self {
            seq,
            root_ino,
            next_ino,
            total_blocks,
            modified_time,
            auto_vacuum,
            freelist_trunk,
            free_blocks,
            inode_blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_standard_vector() {
        // Standard IEEE 802.3 CRC-32 test vector
        let data = b"123456789";
        assert_eq!(crc32(data), 0xCBF4_3926);
    }

    #[test]
    fn test_ondisk_header_roundtrip_and_crc() {
        let salt = [42u8; 32];
        let nonce = [7u8; 24];
        let ct = [99u8; 32];
        let tag = [11u8; 16];

        let header = OnDiskHeader::new(salt, 65536, 3, 4, nonce, ct, tag);
        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = OnDiskHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);

        // Test corruption detection
        let mut corrupted = bytes;
        corrupted[10] ^= 0xFF; // Corrupt a byte in signature
        assert!(OnDiskHeader::from_bytes(&corrupted).is_err());
    }

    #[test]
    fn test_superblock_payload_roundtrip_and_crc() {
        let mut sb = SuperblockPayload::new();
        sb.seq = 100;
        sb.total_blocks = 50;
        sb.inode_blocks = vec![2, 3, 4];
        sb.free_blocks = vec![10, 11, 12, 13];

        let bytes = sb.to_bytes().unwrap();
        assert_eq!(bytes.len(), PLAINTEXT_BLOCK_SIZE);

        let parsed = SuperblockPayload::from_bytes(&bytes).unwrap();
        assert_eq!(sb, parsed);

        // Test corruption detection
        let mut corrupted = bytes;
        corrupted[30] ^= 0x01;
        assert!(SuperblockPayload::from_bytes(&corrupted).is_err());
    }
}

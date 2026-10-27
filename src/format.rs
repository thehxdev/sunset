use crate::crypto::{NONCE_SIZE, SALT_SIZE, TAG_SIZE, VERIFY_MSG_LEN};
use crate::error::SunsetError;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 8] = b"SUNSETFS";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 256;
pub const PLAINTEXT_BLOCK_SIZE: usize = 4096;
pub const STORED_BLOCK_SIZE: usize = NONCE_SIZE + PLAINTEXT_BLOCK_SIZE + TAG_SIZE; // 24 + 4096 + 16 = 4136

pub const SUPERBLOCK_0_ID: u64 = 0;
pub const SUPERBLOCK_1_ID: u64 = 1;
pub const FIRST_ALLOCATABLE_BLOCK: u64 = 2;
pub const ROOT_INODE_ID: u64 = 1;
pub const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub block_size: u32,
    pub stored_block_size: u32,
    pub salt: [u8; SALT_SIZE],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub verify_nonce: [u8; NONCE_SIZE],
    pub verify_ct: [u8; VERIFY_MSG_LEN],
    pub verify_tag: [u8; TAG_SIZE],
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
        Self {
            magic: *MAGIC,
            version: FORMAT_VERSION,
            block_size: PLAINTEXT_BLOCK_SIZE as u32,
            stored_block_size: STORED_BLOCK_SIZE as u32,
            salt,
            m_cost,
            t_cost,
            p_cost,
            verify_nonce,
            verify_ct,
            verify_tag,
        }
    }

    pub fn to_bytes(&self) -> Result<[u8; HEADER_SIZE], SunsetError> {
        let serialized = bincode::serialize(self)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize header: {}", e)))?;
        if serialized.len() > HEADER_SIZE {
            return Err(SunsetError::Format("Header exceeds 256 bytes".to_string()));
        }
        let mut buf = [0u8; HEADER_SIZE];
        buf[..serialized.len()].copy_from_slice(&serialized);
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SunsetError> {
        if bytes.len() < HEADER_SIZE {
            return Err(SunsetError::Format(
                "Header is too short to be a valid Sunset archive".to_string(),
            ));
        }
        let header: Self = bincode::deserialize(bytes).map_err(|e| {
            SunsetError::Format(format!("Failed to deserialize archive header: {}", e))
        })?;
        if &header.magic != MAGIC {
            return Err(SunsetError::Format(
                "Invalid archive header: magic bytes mismatch (not a Sunset archive)".to_string(),
            ));
        }
        if header.version != FORMAT_VERSION {
            return Err(SunsetError::Format(format!(
                "Unsupported archive version: {} (supported: {})",
                header.version, FORMAT_VERSION
            )));
        }
        if header.block_size != PLAINTEXT_BLOCK_SIZE as u32 {
            return Err(SunsetError::Format(format!(
                "Unsupported block size: {} (expected {})",
                header.block_size, PLAINTEXT_BLOCK_SIZE
            )));
        }
        if header.stored_block_size != STORED_BLOCK_SIZE as u32 {
            return Err(SunsetError::Format(format!(
                "Unsupported stored block size: {} (expected {})",
                header.stored_block_size, STORED_BLOCK_SIZE
            )));
        }
        Ok(header)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperblockPayload {
    pub seq: u64,
    pub root_ino: u64,
    pub next_ino: u64,
    pub total_blocks: u64,
    pub free_blocks: Vec<u64>,
    pub inode_blocks: Vec<u64>,
    pub modified_time: u64,
}

impl SuperblockPayload {
    pub fn new() -> Self {
        Self {
            seq: 1,
            root_ino: ROOT_INODE_ID,
            next_ino: ROOT_INODE_ID + 1,
            total_blocks: FIRST_ALLOCATABLE_BLOCK, // 0 and 1 reserved for superblocks
            free_blocks: Vec::new(),
            inode_blocks: Vec::new(),
            modified_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

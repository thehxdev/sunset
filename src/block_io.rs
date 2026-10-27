use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{
    create_verification_token, derive_key, encrypt_block, decrypt_block, generate_nonce,
    generate_salt, verify_key, MasterKey, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST,
    NONCE_SIZE,
};
use crate::error::SunsetError;
use crate::format::{
    HEADER_SIZE, OnDiskHeader, PLAINTEXT_BLOCK_SIZE, STORED_BLOCK_SIZE,
};

pub struct BlockDevice {
    file: File,
    key: MasterKey,
    header: OnDiskHeader,
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

        let mut file = OpenOptions::new()
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
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header_bytes)?;

        let mut dev = Self { file, key, header };

        if let Some(blocks) = initial_blocks {
            let zero_block = [0u8; PLAINTEXT_BLOCK_SIZE];
            for i in 0..blocks {
                dev.write_block(i, &zero_block)?;
            }
        }

        dev.file.flush()?;
        dev.file.sync_data()?;
        Ok(dev)
    }

    pub fn open(path: &Path, passphrase: &str) -> Result<Self, SunsetError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to open archive '{}': {}", path.display(), e),
                ))
            })?;

        let mut header_buf = [0u8; HEADER_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header_buf)
            .map_err(|e| {
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

        Ok(Self { file, key, header })
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

    pub fn read_block(&mut self, block_index: u64) -> Result<Vec<u8>, SunsetError> {
        let offset = Self::block_offset(block_index);
        let file_len = self.file.metadata()?.len();

        if offset + STORED_BLOCK_SIZE as u64 > file_len {
            return Err(SunsetError::CorruptedBlock(block_index));
        }

        self.file.seek(SeekFrom::Start(offset))?;
        let mut raw_buf = vec![0u8; STORED_BLOCK_SIZE];
        self.file.read_exact(&mut raw_buf)?;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&raw_buf[..NONCE_SIZE]);
        let ciphertext = &raw_buf[NONCE_SIZE..];

        let aad = block_index.to_le_bytes();
        let decrypted = decrypt_block(&self.key, &nonce, ciphertext, &aad)
            .map_err(|_| SunsetError::CorruptedBlock(block_index))?;

        Ok(decrypted)
    }

    pub fn write_block(&mut self, block_index: u64, data: &[u8]) -> Result<(), SunsetError> {
        let offset = Self::block_offset(block_index);

        let mut payload = [0u8; PLAINTEXT_BLOCK_SIZE];
        let copy_len = data.len().min(PLAINTEXT_BLOCK_SIZE);
        payload[..copy_len].copy_from_slice(&data[..copy_len]);

        let nonce = generate_nonce();
        let aad = block_index.to_le_bytes();
        let ciphertext = encrypt_block(&self.key, &nonce, &payload, &aad)?;

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&nonce)?;
        self.file.write_all(&ciphertext)?;

        Ok(())
    }

    pub fn total_blocks_on_disk(&mut self) -> Result<u64, SunsetError> {
        let file_len = self.file.metadata()?.len();
        if file_len < HEADER_SIZE as u64 {
            return Ok(0);
        }
        Ok((file_len - HEADER_SIZE as u64) / STORED_BLOCK_SIZE as u64)
    }

    pub fn flush(&mut self) -> Result<(), SunsetError> {
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

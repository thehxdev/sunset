use std::collections::HashMap;

use crate::error::SunsetError;
use crate::format::{bincode_config, MAX_NAME_LEN};
use crate::inode::InodeKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub name: String,
    pub kind: InodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectoryData {
    pub entries: Vec<DirEntry>,
    #[serde(skip)]
    name_map: HashMap<String, usize>,
}

impl DirectoryData {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            name_map: HashMap::new(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SunsetError> {
        bincode::serde::encode_to_vec(self, bincode_config())
            .map_err(|e| SunsetError::Format(format!("Failed to serialize directory: {}", e)))
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, SunsetError> {
        if slice.is_empty() {
            return Ok(Self::new());
        }
        let (mut data, _): (Self, usize) = bincode::serde::decode_from_slice(slice, bincode_config())
            .map_err(|e| SunsetError::Format(format!("Failed to deserialize directory: {}", e)))?;
        let mut map = HashMap::with_capacity(data.entries.len());
        for (idx, e) in data.entries.iter().enumerate() {
            if Self::validate_name(&e.name).is_err() {
                return Err(SunsetError::Format(
                    "Invalid directory entry name in archive".to_string(),
                ));
            }
            map.insert(e.name.clone(), idx);
        }
        data.name_map = map;
        Ok(data)
    }

    pub fn find_entry(&self, name: &str) -> Option<&DirEntry> {
        if let Some(&idx) = self.name_map.get(name) {
            self.entries.get(idx)
        } else {
            self.entries.iter().find(|e| e.name == name)
        }
    }

    pub fn validate_name(name: &str) -> Result<(), SunsetError> {
        if name.is_empty() {
            return Err(SunsetError::InvalidArgument(
                "File name cannot be empty".to_string(),
            ));
        }
        if name == "." || name == ".." {
            return Err(SunsetError::InvalidArgument(
                "Cannot use '.' or '..' as entry name".to_string(),
            ));
        }
        if name.contains('/') || name.contains('\0') {
            return Err(SunsetError::InvalidArgument(
                "File name cannot contain '/' or null characters".to_string(),
            ));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(SunsetError::NameTooLong(name.to_string()));
        }
        Ok(())
    }

    pub fn add_entry(&mut self, ino: u64, name: &str, kind: InodeKind) -> Result<(), SunsetError> {
        Self::validate_name(name)?;
        if self.find_entry(name).is_some() {
            return Err(SunsetError::AlreadyExists(name.to_string()));
        }
        let idx = self.entries.len();
        self.entries.push(DirEntry {
            ino,
            name: name.to_string(),
            kind,
        });
        self.name_map.insert(name.to_string(), idx);
        Ok(())
    }

    pub fn remove_entry(&mut self, name: &str) -> Result<DirEntry, SunsetError> {
        let pos = match self.name_map.remove(name) {
            Some(idx) => idx,
            None => self
                .entries
                .iter()
                .position(|e| e.name == name)
                .ok_or_else(|| SunsetError::NotFound(name.to_string()))?,
        };
        let removed = self.entries.remove(pos);
        for idx in pos..self.entries.len() {
            self.name_map.insert(self.entries[idx].name.clone(), idx);
        }
        Ok(removed)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

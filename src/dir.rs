use crate::error::SunsetError;
use crate::format::MAX_NAME_LEN;
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
}

impl DirectoryData {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SunsetError> {
        bincode::serialize(self)
            .map_err(|e| SunsetError::Format(format!("Failed to serialize directory: {}", e)))
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, SunsetError> {
        if slice.is_empty() {
            return Ok(Self::new());
        }
        bincode::deserialize(slice)
            .map_err(|e| SunsetError::Format(format!("Failed to deserialize directory: {}", e)))
    }

    pub fn find_entry(&self, name: &str) -> Option<&DirEntry> {
        self.entries.iter().find(|e| e.name == name)
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
        self.entries.push(DirEntry {
            ino,
            name: name.to_string(),
            kind,
        });
        Ok(())
    }

    pub fn remove_entry(&mut self, name: &str) -> Result<DirEntry, SunsetError> {
        if let Some(pos) = self.entries.iter().position(|e| e.name == name) {
            Ok(self.entries.remove(pos))
        } else {
            Err(SunsetError::NotFound(name.to_string()))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

use crate::crypto::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SunsetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Archive format error: {0}")]
    Format(String),

    #[error("Archive data integrity violation: block #{0} failed cryptographic authentication tag verification (possible tampering or bit rot)")]
    CorruptedBlock(u64),

    #[error("Invalid encryption key or corrupted archive header (authentication failed)")]
    InvalidKey,

    #[error("No such file or directory: '{0}'")]
    NotFound(String),

    #[error("File or directory already exists: '{0}'")]
    AlreadyExists(String),

    #[error("Directory not empty: '{0}'")]
    NotEmpty(String),

    #[error("Not a directory: '{0}'")]
    NotADirectory(String),

    #[error("Is a directory: '{0}'")]
    IsADirectory(String),

    #[error("File name exceeds maximum allowed length of 255 bytes: '{0}'")]
    NameTooLong(String),

    #[error("Read-only file system")]
    ReadOnly,

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("No space left on device")]
    NoSpace,
}

impl SunsetError {
    pub fn to_errno(&self) -> fuser::Errno {
        let code = match self {
            SunsetError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            SunsetError::Crypto(_) => libc::EIO,
            SunsetError::Format(_) => libc::EIO,
            SunsetError::CorruptedBlock(_) => libc::EIO,
            SunsetError::InvalidKey => libc::EACCES,
            SunsetError::NotFound(_) => libc::ENOENT,
            SunsetError::AlreadyExists(_) => libc::EEXIST,
            SunsetError::NotEmpty(_) => libc::ENOTEMPTY,
            SunsetError::NotADirectory(_) => libc::ENOTDIR,
            SunsetError::IsADirectory(_) => libc::EISDIR,
            SunsetError::NameTooLong(_) => libc::ENAMETOOLONG,
            SunsetError::ReadOnly => libc::EROFS,
            SunsetError::InvalidArgument(_) => libc::EINVAL,
            SunsetError::NoSpace => libc::ENOSPC,
        };
        fuser::Errno::from_i32(code)
    }
}

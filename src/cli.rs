use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;

use crate::error::SunsetError;

#[derive(Parser, Debug)]
#[command(
    name = "sunset",
    about = "Encrypted user-space file-system residing in a single binary file",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new encrypted file-system archive with an encryption key
    Init {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Encryption key (passphrase or key string)
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,

        /// Optional initial preallocated size (e.g., "10M", "100M", "1G")
        #[arg(short, long)]
        size: Option<String>,
    },

    /// Mount the encrypted archive directly to a local directory via FUSE
    Mount {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Mount point directory
        mountpoint: PathBuf,

        /// Encryption key (passphrase or key string)
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,

        /// Additional FUSE mount options (comma-separated, e.g. "ro,allow_other")
        #[arg(short, long)]
        options: Option<String>,
    },

    /// Verify key and check integrity of all encrypted blocks in archive
    Check {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// List directory contents inside archive
    Ls {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Path inside archive (default: "/")
        #[arg(default_value = "/")]
        path: String,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Output file contents from archive to stdout
    Cat {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Path inside archive
        path: String,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Copy a host file into the encrypted archive
    Put {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Local host source file path
        src: PathBuf,

        /// Archive destination file path
        dst: String,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Extract a file from the encrypted archive to host
    Get {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Archive source file path
        src: String,

        /// Local host destination path
        dst: PathBuf,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Create a directory inside the encrypted archive
    Mkdir {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Directory path inside archive
        path: String,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Remove a file or empty directory from inside the encrypted archive
    Rm {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Path inside archive to delete
        path: String,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Defragment archive and shrink container file to minimum physical size (like SQLite vacuum)
    Vacuum {
        /// Path to the archive binary file
        archive: PathBuf,

        /// Encryption key
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a file containing the encryption key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Read encryption key from standard input
        #[arg(long)]
        key_stdin: bool,
    },

    /// Display archive container format specification and metadata
    Info {
        /// Path to the archive binary file
        archive: PathBuf,
    },
}

pub fn resolve_key(
    key: Option<String>,
    key_file: Option<PathBuf>,
    key_stdin: bool,
    is_init: bool,
) -> Result<String, SunsetError> {
    if let Some(k) = key {
        return Ok(k);
    }

    if let Some(kf) = key_file {
        let content = std::fs::read_to_string(&kf).map_err(|e| {
            SunsetError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read key file '{}': {}", kf.display(), e),
            ))
        })?;
        return Ok(content.trim().to_string());
    }

    if key_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| SunsetError::Io(std::io::Error::new(e.kind(), "Failed to read key from stdin")))?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }

    if let Ok(env_key) = std::env::var("SUNSET_KEY") {
        if !env_key.is_empty() {
            return Ok(env_key);
        }
    }

    if std::io::stdin().is_terminal() {
        if is_init {
            let pass1 = rpassword::prompt_password("Enter encryption key: ")
                .map_err(|e| SunsetError::Io(std::io::Error::new(e.kind(), "Failed to read password")))?;
            if pass1.is_empty() {
                return Err(SunsetError::InvalidArgument(
                    "Encryption key cannot be empty".to_string(),
                ));
            }
            let pass2 = rpassword::prompt_password("Confirm encryption key: ")
                .map_err(|e| SunsetError::Io(std::io::Error::new(e.kind(), "Failed to read password confirmation")))?;
            if pass1 != pass2 {
                return Err(SunsetError::InvalidArgument(
                    "Encryption keys do not match".to_string(),
                ));
            }
            return Ok(pass1);
        } else {
            let pass = rpassword::prompt_password("Enter encryption key: ")
                .map_err(|e| SunsetError::Io(std::io::Error::new(e.kind(), "Failed to read password")))?;
            return Ok(pass);
        }
    }

    Err(SunsetError::InvalidArgument(
        "No encryption key provided. Pass key via -k/--key, --key-file, --key-stdin, or set SUNSET_KEY environment variable."
            .to_string(),
    ))
}

pub fn parse_size_to_blocks(size_str: &str) -> Result<u64, SunsetError> {
    let s = size_str.trim().to_uppercase();
    let (num_str, mult) = if s.ends_with("GB") || s.ends_with('G') {
        let part = s.trim_end_matches("GB").trim_end_matches('G');
        (part, 1024 * 1024 * 1024u64)
    } else if s.ends_with("MB") || s.ends_with('M') {
        let part = s.trim_end_matches("MB").trim_end_matches('M');
        (part, 1024 * 1024u64)
    } else if s.ends_with("KB") || s.ends_with('K') {
        let part = s.trim_end_matches("KB").trim_end_matches('K');
        (part, 1024u64)
    } else {
        (s.as_str(), 1u64)
    };

    let bytes = num_str
        .trim()
        .parse::<u64>()
        .map_err(|_| SunsetError::InvalidArgument(format!("Invalid size format: '{}' (examples: '100M', '2G')", size_str)))?
        * mult;

    Ok(bytes.div_ceil(4096))
}

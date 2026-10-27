# Sunset: Encrypted User-Space File System

`sunset` is a secure, user-space encrypted file system where all files, directories, metadata, and contents reside in a single standalone binary file. It can be mounted directly into the Linux file system using FUSE for transparent access, or inspected headlessly via built-in CLI commands.

---

## Key Features

- **Single Binary Container**: Entire file system (inodes, directory trees, file contents, free lists) stored inside one portable file (e.g. `vault.bin`).
- **Strong Stream Cipher**: Pure Rust `XChaCha20-Poly1305` authenticated encryption (256-bit key, 192-bit random nonce, 128-bit Poly1305 MAC tag).
- **Relocation & Tamper Defense**: Block indices authenticated as Additional Authenticated Data (AAD). Block reordering or bit flips immediately rejected with I/O error.
- **Argon2id Key Derivation**: High-entropy 256-bit key derived from user passphrase with 32-byte CSPRNG salt.
- **Dual-Superblock Crash Resilience**: Alternating superblocks with monotonic sequence numbers prevent metadata corruption on unexpected power loss.
- **Huge File Support**: 12 direct blocks, single-indirect, double-indirect, and triple-indirect block mapping supporting files up to 512 GB with sparse hole allocation.
- **Masked Interactive Input**: Prompts securely with hidden input if keys omitted on terminal. Also supports `-k`, `--key-file`, `--key-stdin`, and `SUNSET_KEY`.
- **POSIX Semantics**: Standard directory traversal, file handles, unlinking open files, file truncation, permissions (`umask`), timestamps, and read-only (`-o ro`) mount.
- **Dual-Mode Operation**: Mounts via FUSE or operates headlessly via built-in archive commands (`ls`, `cat`, `put`, `get`, `mkdir`, `check`).

---

## On-Disk Binary Format

```
+-------------------------------------------------------------------------+
| Plaintext Header (Offset 0x0000 - 0x00FF, 256 bytes)                    |
| - Magic: b"SUNSETFS" (8 bytes)                                          |
| - Format Version: u32 = 1 (4 bytes)                                     |
| - Plaintext Block Size: u32 = 4096 (4 bytes)                            |
| - Stored Block Size: u32 = 4136 (4 bytes)                               |
| - Salt: [u8; 32] (Argon2id salt)                                        |
| - Argon2id Params: m_cost (4), t_cost (4), p_cost (4)                   |
| - Verification Token: Nonce (24) + Ciphertext (32) + Poly1305 Tag (16)  |
| - Reserved Padding (120 bytes)                                          |
+-------------------------------------------------------------------------+
| Block 0: Primary Superblock (4136 bytes: Nonce[24] + Encrypted[4096] + Tag[16]) |
+-------------------------------------------------------------------------+
| Block 1: Backup Superblock  (4136 bytes: Nonce[24] + Encrypted[4096] + Tag[16]) |
+-------------------------------------------------------------------------+
| Block 2..N: Encrypted Inode Tables, Directory Tables, Data Blocks       |
+-------------------------------------------------------------------------+
```

Every physical block is stored as:
$$\text{Physical Block} = \text{Nonce}_{24} \,\|\, \text{Ciphertext}_{4096} \,\|\, \text{Poly1305 Tag}_{16}$$
Decryption uses $\text{AAD} = \text{block\_index}_{\text{u64 (LE)}}$.

---

## Installation & Build

### Prerequisites
- Linux OS with kernel $\ge 4.5$
- `fuse3` / `fusermount3` installed:
  - openSUSE / SLES: `zypper install fuse3`
  - Debian / Ubuntu: `apt install fuse3 libfuse3-3`
  - Arch Linux: `pacman -S fuse3`
  - Fedora / RHEL: `dnf install fuse3`
- Rust 1.85+ toolchain

### Build Release Binary
```bash
cargo build --release
sudo cp target/release/sunset /usr/local/bin/
```

Verify installation:
```bash
sunset --version
```

---

## CLI Reference

```
Usage: sunset <COMMAND>

Commands:
  init   Initialize a new encrypted file-system archive with an encryption key
  mount  Mount the encrypted archive directly to a local directory via FUSE
  check  Verify key and check integrity of all encrypted blocks in archive
  ls     List directory contents inside archive
  cat    Output file contents from archive to stdout
  put    Copy a host file into the encrypted archive
  get    Extract a file from the encrypted archive to host
  mkdir  Create a directory inside the encrypted archive
  help   Print this message or the help of the given subcommand(s)
```

### Common Authentication Flags
All commands accept key inputs via:
- Masked TTY prompt (default if no flag given on interactive terminal)
- `-k, --key <KEY>`: Pass key string directly on command line
- `--key-file <PATH>`: Read key from file
- `--key-stdin`: Read key from standard input pipe
- `SUNSET_KEY`: Environment variable

---

## How-to Guides

### 1. How to Initialize a New Encrypted Archive

To create a new encrypted container:

```bash
# Interactive masked prompt with confirmation:
sunset init vault.bin

# Or specifying initial preallocation size:
sunset init vault.bin --size 100M

# Or passing key via flag:
sunset init vault.bin -k "MyVeryStrongPassphrase123!"
```

---

### 2. How to Mount and Use as a Normal Directory

Mount the archive directly into your file system:

```bash
# 1. Create mount directory if needed
mkdir -p /home/user/secure_vault

# 2. Mount container
sunset mount vault.bin /home/user/secure_vault
# (Enter encryption key when prompted)

# 3. Work like a normal directory
cd /home/user/secure_vault
touch notes.txt
echo "Confidential data" > notes.txt
mkdir private_docs
cp ~/financials.pdf private_docs/
ls -la
```

---

### 3. How to Unmount

Unmount from another terminal or tab:

```bash
fusermount3 -u /home/user/secure_vault
```

Or press `Ctrl+C` in the foreground terminal running `sunset mount`. All buffers and metadata flush cleanly before exit.

---

### 4. How to Mount Read-Only

Mount container with `-o ro` to prevent any modifications:

```bash
sunset mount vault.bin /mnt/vault -o ro -k "MySecretKey"
```

Any write, create, delete, or rename attempt returns `EROFS` (Read-only file system).

---

### 5. How to Automate & Script Without Prompts

#### Using Piped Standard Input (`--key-stdin`)
```bash
echo "MySecretKey" | sunset mount vault.bin /mnt/vault --key-stdin
```

#### Using Key Files (`--key-file`)
```bash
echo "MySecretKey" > ~/.vault_key
chmod 600 ~/.vault_key

sunset mount vault.bin /mnt/vault --key-file ~/.vault_key
```

#### Using Environment Variable (`SUNSET_KEY`)
```bash
export SUNSET_KEY="MySecretKey"
sunset mount vault.bin /mnt/vault
```

---

### 6. How to Use Standalone Without Mounting (Headless Inspection)

When FUSE is unavailable (e.g., inside restricted containers or headless servers without `/dev/fuse`), use built-in archive commands:

```bash
# List archive root
sunset ls vault.bin -k "MySecretKey"

# List subfolder
sunset ls vault.bin docs/reports -k "MySecretKey"

# Put a file into archive
sunset put vault.bin local_report.pdf docs/reports/q3.pdf -k "MySecretKey"

# Print a file from archive to stdout
sunset cat vault.bin docs/reports/q3.pdf -k "MySecretKey"

# Extract file from archive to host
sunset get vault.bin docs/reports/q3.pdf /tmp/extracted_q3.pdf -k "MySecretKey"

# Create a folder inside archive
sunset mkdir vault.bin docs/backups -k "MySecretKey"
```

---

### 7. How to Verify Container Integrity

Check that key is correct and all encrypted blocks in the container pass Poly1305 MAC authentication:

```bash
sunset check vault.bin -k "MySecretKey"
```

Output:
```
Verifying 120 blocks in archive...
Archive verified successfully: all 120 blocks intact and authenticated.
```

If any block has been tampered with or corrupted on disk, `sunset check` reports exact block index:
```
Error: Archive data integrity violation: block #14 failed cryptographic authentication tag verification (possible tampering or bit rot)
```

---

## Troubleshooting & Diagnostics

| Error Message | Cause | Resolution |
| :--- | :--- | :--- |
| `Archive file '...' does not exist` | Container file path incorrect or not initialized. | Run `sunset init <path>` first. |
| `Invalid encryption key or corrupted archive header (authentication failed)` | Passphrase incorrect or header corrupted. | Double-check passphrase. |
| `FUSE mount failed on '...': No such file or directory` | System lacks `/dev/fuse` or `fusermount3`. | Install `fuse3` package or check container device permissions. Alternatively use standalone CLI (`ls`, `cat`, `put`, `get`). |
| `Cannot remove directory '...': directory is not empty` | Attempting to `rmdir` folder with files. | Remove contents first or use `rm -r` inside mount. |
| `Read-only file system` | Mounted with `-o ro`. | Unmount and remount without `-o ro` to allow writes. |
| `Archive data integrity violation: block #N failed cryptographic authentication tag verification` | Bit flip, disk corruption, or malicious tampering. | Restore block from backup; data rejected rather than returning corrupted plaintext. |

---

## Security Guarantees

1. **Confidentiality**: Plaintext blocks encrypted with 256-bit XChaCha20. No plaintext leaks into container.
2. **Integrity & Authenticity**: 128-bit Poly1305 authentication tag per block verifies data has not been modified.
3. **Anti-Replay / Anti-Relocation**: Logical block index authenticated in AAD. Swapping block positions corrupts authentication tags and fails decryption.
4. **Metadata Privacy**: Directory records, file names, file sizes, and timestamps encrypted inside data blocks. Only top-level format salt and verification token visible in header.
5. **Memory Safety**: Pure Rust implementation with zero unsafe pointer arithmetic in crypto layers. Master keys zeroized on drop.

# Sunset How-To Guides

This guide covers real-world deployment patterns and operational practices for `sunset`.

---

## Table of Contents
1. [Basic Walkthrough: Initializing and Mounting](#1-basic-walkthrough)
2. [Managing Secure Backups](#2-managing-secure-backups)
3. [Automating with Systemd on Linux](#3-automating-with-systemd-on-linux)
4. [Using in Docker / Headless Containers Without FUSE](#4-headless-usage-without-fuse)
5. [Disaster Recovery & Verifying Bit Integrity](#5-disaster-recovery)
6. [Best Practices for Key Security](#6-best-practices-for-key-security)

---

## 1. Basic Walkthrough

### Step 1: Create Container
```bash
sunset init my_vault.bin
```
Output:
```
Enter encryption key: 
Confirm encryption key: 
Initialized encrypted archive at: my_vault.bin
```

### Step 2: Mount Container
```bash
mkdir -p ~/vault
sunset mount my_vault.bin ~/vault
```

### Step 3: Use Standard Linux Utilities
In another terminal:
```bash
cd ~/vault
echo "Secrets stored here" > secrets.txt
mkdir work_notes
cp -r ~/projects/sample work_notes/
ls -la
```

### Step 4: Unmount
```bash
fusermount3 -u ~/vault
```

---

## 2. Managing Secure Backups

Because a `sunset` filesystem is a single file, backup and replication are straightforward:

```bash
# 1. Unmount container prior to cold backup (recommended for snapshot consistency)
fusermount3 -u ~/vault

# 2. Sync container file to remote storage
rsync -avz --progress my_vault.bin user@backup-server:/storage/backups/
```

Even if the backup file is intercepted over an insecure network or public cloud, it remains fully encrypted with 256-bit XChaCha20-Poly1305.

---

## 3. Automating with Systemd on Linux

To mount a Sunset archive automatically on user login or system boot:

### Step 1: Store Encryption Key Securely
```bash
sudo mkdir -p /etc/sunset
sudo sh -c 'echo "MySystemVaultKeySecret" > /etc/sunset/vault.key'
sudo chmod 600 /etc/sunset/vault.key
```

### Step 2: Create Systemd Service File
Create `/etc/systemd/system/sunset-vault.service`:

```ini
[Unit]
Description=Sunset Encrypted User-Space File System
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sunset mount /var/lib/vault.bin /mnt/secure_vault --key-file /etc/sunset/vault.key
ExecStop=/usr/bin/fusermount3 -u /mnt/secure_vault
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Step 3: Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sunset-vault
```

Check status:
```bash
sudo systemctl status sunset-vault
```

---

## 4. Headless Usage Without FUSE

In restricted container environments (such as Kubernetes pods or minimal Docker containers without `--device /dev/fuse`), you can manage archive contents directly:

```bash
# Set key once in shell environment
export SUNSET_KEY="ProductionSecureKey"

# Inspect contents
sunset ls /data/vault.bin

# Add files
sunset put /data/vault.bin local_app.conf config/app.conf

# Fetch file
sunset get /data/vault.bin config/app.conf /tmp/fetched_app.conf

# Stream file to pipeline
sunset cat /data/vault.bin logs/error.log | grep "CRITICAL"
```

---

## 5. Disaster Recovery

If you suspect filesystem corruption or hardware disk degradation:

### Run Integrity Audit
```bash
sunset check my_vault.bin -k "MySecretKey"
```

If a power failure occurred during a write operation:
`sunset` features dual-superblock architecture with atomic sequence numbers. The filesystem automatically recovers using the mirrored backup superblock (Block 1) and restores state seamlessly.

---

## 6. Best Practices for Key Security

1. **Avoid Passing Keys in Command Line Flags on Shared Systems**:
   Using `-k "pass"` exposes the password in `ps aux` and shell history. Prefer:
   - Interactive TTY prompt
   - `--key-file` with `chmod 600`
   - `--key-stdin`
   - `export SUNSET_KEY`
2. **Key Erasure**:
   `sunset` uses the `Zeroize` trait to zero out derived master keys and sensitive buffers from process memory when dropped.

---

## 7. Container Compaction and Shrinking on File Deletion

`sunset` includes SQLite-inspired auto-vacuum compaction:
- **Instant Disk Reclaim**: When a file is unlinked (`rm` on FUSE mount or `sunset rm`), or truncated down, vacated physical blocks are reclaimed. If holes exist inside the archive, trailing blocks are moved into the vacant slots and the container file is truncated using `set_len`.
- **Manual Vacuum**: You can trigger explicit defragmentation anytime via:
  ```bash
  sunset vacuum /data/vault.bin -k "MySecretKey"
  ```
- **Inspect Container Metadata**: Check container wire layout, block counts, and CRC32 without needing the encryption key:
  ```bash
  sunset info /data/vault.bin
  ```

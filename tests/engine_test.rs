use std::path::PathBuf;
use sunset::format::{HEADER_SIZE, ROOT_INODE_ID, STORED_BLOCK_SIZE};
use sunset::fs_engine::SunsetEngine;
use sunset::inode::InodeKind;

fn temp_archive_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn test_engine_init_and_reopen() {
    let path = temp_archive_path("sunset_engine_test_init.bin");
    let pass = "my_strong_key_1";

    {
        let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
        let root = engine.get_inode(ROOT_INODE_ID).unwrap();
        assert_eq!(root.kind, InodeKind::Directory);
        engine.flush().unwrap();
    }

    // Reopen and check root
    {
        let engine = SunsetEngine::open(&path, pass).unwrap();
        let root = engine.get_inode(ROOT_INODE_ID).unwrap();
        assert_eq!(root.kind, InodeKind::Directory);
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_engine_file_crud_and_block_reuse() {
    let path = temp_archive_path("sunset_engine_test_crud.bin");
    let pass = "my_strong_key_crud";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // 1. Create a file
    let file_node = engine
        .create_file(ROOT_INODE_ID, "hello.txt", 0o644, 1000, 1000)
        .unwrap();
    let ino = file_node.ino;

    // 2. Write data (span across multiple blocks, e.g. 10 KB = 3 blocks)
    let sample_data = b"STREAM_CIPHER_TEST_DATA_".repeat(500); // 12,000 bytes
    let written = engine.write_bytes(ino, 0, &sample_data).unwrap();
    assert_eq!(written, sample_data.len());

    // 3. Read back and verify exact match
    let read_data = engine.read_bytes(ino, 0, sample_data.len()).unwrap();
    assert_eq!(read_data, sample_data);

    // 4. Overwrite middle bytes
    let patch = b"OVERWRITTEN_CHUNK";
    engine.write_bytes(ino, 4090, patch).unwrap();
    let read_patched = engine.read_bytes(ino, 4090, patch.len()).unwrap();
    assert_eq!(read_patched, patch);

    // 5. Truncate down to 500 bytes (file should physically shrink on disk)
    let total_before_truncate = engine.total_blocks();
    engine.truncate(ino, 500).unwrap();
    let truncated_data = engine.read_bytes(ino, 0, 1000).unwrap();
    assert_eq!(truncated_data.len(), 500);
    assert_eq!(&truncated_data[..24], &sample_data[..24]);

    // Check total blocks shrank on truncation
    assert!(engine.total_blocks() < total_before_truncate);

    // 6. Delete file (unlink)
    engine.unlink(ROOT_INODE_ID, "hello.txt").unwrap();
    assert!(engine.get_inode(ino).is_err());

    // 7. Create another file and write, should reuse freed blocks without inflating file
    let file2 = engine
        .create_file(ROOT_INODE_ID, "second.txt", 0o644, 1000, 1000)
        .unwrap();
    engine.write_bytes(file2.ino, 0, &sample_data).unwrap();
    engine.flush().unwrap();

    let total_after = engine.total_blocks();
    assert!(total_after <= total_before_truncate + 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_engine_directories_and_subtrees() {
    let path = temp_archive_path("sunset_engine_test_dirs.bin");
    let pass = "my_dir_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // Create dir: /docs
    let docs = engine.mkdir(ROOT_INODE_ID, "docs", 0o755, 1000, 1000).unwrap();

    // Create dir: /docs/personal
    let personal = engine.mkdir(docs.ino, "personal", 0o755, 1000, 1000).unwrap();

    // Create file: /docs/personal/diary.txt
    let diary = engine
        .create_file(personal.ino, "diary.txt", 0o600, 1000, 1000)
        .unwrap();
    let diary_content = b"Top secret diary entry encrypted with XChaCha20!";
    engine.write_bytes(diary.ino, 0, diary_content).unwrap();

    // Lookup path
    let docs_lookup = engine.lookup(ROOT_INODE_ID, "docs").unwrap();
    assert_eq!(docs_lookup.ino, docs.ino);

    let personal_lookup = engine.lookup(docs_lookup.ino, "personal").unwrap();
    assert_eq!(personal_lookup.ino, personal.ino);

    let diary_lookup = engine.lookup(personal_lookup.ino, "diary.txt").unwrap();
    assert_eq!(diary_lookup.ino, diary.ino);

    let diary_read = engine.read_bytes(diary_lookup.ino, 0, 100).unwrap();
    assert_eq!(diary_read, diary_content);

    // Cannot rmdir /docs/personal because it is not empty
    assert!(engine.rmdir(docs.ino, "personal").is_err());

    // Delete diary.txt
    engine.unlink(personal.ino, "diary.txt").unwrap();

    // Now rmdir /docs/personal succeeds
    assert!(engine.rmdir(docs.ino, "personal").is_ok());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_engine_large_file_indirect_blocks() {
    let path = temp_archive_path("sunset_engine_test_large.bin");
    let pass = "large_file_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    let file = engine
        .create_file(ROOT_INODE_ID, "big.bin", 0o644, 1000, 1000)
        .unwrap();

    // 12 direct blocks * 4096 = 49152 bytes.
    // Write at offset 70,000 (forces single indirect block allocation)
    let payload = b"INDIRECT_BLOCK_DATA_PAYLOAD";
    engine.write_bytes(file.ino, 70_000, payload).unwrap();

    let node = engine.get_inode(file.ino).unwrap();
    assert_eq!(node.size, 70_000 + payload.len() as u64);
    assert_ne!(node.indirect_block, 0);

    // Read back
    let read = engine.read_bytes(file.ino, 70_000, payload.len()).unwrap();
    assert_eq!(read, payload);

    // Reading sparse hole before 70,000 returns zeroes
    let hole = engine.read_bytes(file.ino, 10_000, 16).unwrap();
    assert_eq!(hole, vec![0u8; 16]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_dual_superblock_crash_recovery() {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    let path = temp_archive_path("sunset_engine_test_dual_sb.bin");
    let pass = "crash_recovery_pass";

    {
        let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
        let file = engine.create_file(ROOT_INODE_ID, "saved.txt", 0o644, 1000, 1000).unwrap();
        engine.write_bytes(file.ino, 0, b"Persisted before crash").unwrap();
        engine.flush().unwrap();
    }

    // Intentionally corrupt Superblock 0 (bytes from HEADER_SIZE to HEADER_SIZE + STORED_BLOCK_SIZE)
    {
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER_SIZE as u64)).unwrap();
        file.write_all(&[0xFF; STORED_BLOCK_SIZE]).unwrap();
        file.sync_data().unwrap();
    }

    // Reopen: must automatically recover from Superblock 1!
    {
        let mut engine = SunsetEngine::open(&path, pass).expect("Should recover using backup superblock");
        let file = engine.lookup(ROOT_INODE_ID, "saved.txt").unwrap();
        let content = engine.read_bytes(file.ino, 0, 30).unwrap();
        assert_eq!(&content, b"Persisted before crash");

        // Flush will repair Superblock 0
        engine.flush().unwrap();
    }

    // Reopen again: both should be valid now
    {
        let mut engine = SunsetEngine::open(&path, pass).unwrap();
        let file = engine.lookup(ROOT_INODE_ID, "saved.txt").unwrap();
        let content = engine.read_bytes(file.ino, 0, 30).unwrap();
        assert_eq!(&content, b"Persisted before crash");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_triple_indirect_huge_file() {
    let path = temp_archive_path("sunset_engine_test_triple.bin");
    let pass = "triple_indirect_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let file = engine.create_file(ROOT_INODE_ID, "huge.img", 0o644, 1000, 1000).unwrap();

    // Direct (12) + Single (512) + Double (512*512) = 262,668 blocks = 1,075,888,128 bytes (~1.075 GB).
    // Write at block 270,000 (offset = 270,000 * 4096 = 1,105,920,000 bytes > 1.1 GB):
    let huge_offset = 270_000u64 * 4096;
    let payload = b"PAYLOAD_INSIDE_TRIPLE_INDIRECT_BLOCK!";

    engine.write_bytes(file.ino, huge_offset, payload).unwrap();

    let node = engine.get_inode(file.ino).unwrap();
    assert_eq!(node.size, huge_offset + payload.len() as u64);
    assert_ne!(node.triple_indirect_block, 0);

    // Read back
    let read = engine.read_bytes(file.ino, huge_offset, payload.len()).unwrap();
    assert_eq!(read, payload);

    // Read sparse hole
    let hole = engine.read_bytes(file.ino, 100_000, 16).unwrap();
    assert_eq!(hole, vec![0u8; 16]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_open_file_unlinking() {
    let path = temp_archive_path("sunset_engine_test_unlink_open.bin");
    let pass = "unlink_open_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let file = engine.create_file(ROOT_INODE_ID, "ephemeral.txt", 0o644, 1000, 1000).unwrap();
    let ino = file.ino;

    // Simulate process opening file
    engine.on_file_open(ino);

    // Another process unlinks file
    engine.unlink(ROOT_INODE_ID, "ephemeral.txt").unwrap();

    // File should not be found by name in directory
    assert!(engine.lookup(ROOT_INODE_ID, "ephemeral.txt").is_err());

    // But open process can still write and read!
    engine.write_bytes(ino, 0, b"Data written to unlinked open file").unwrap();
    let read = engine.read_bytes(ino, 0, 34).unwrap();
    assert_eq!(&read, b"Data written to unlinked open file");

    // When process closes file handle:
    engine.on_file_release(ino).unwrap();

    // Now inode should be completely gone
    assert!(engine.get_inode(ino).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_name_validation() {
    let path = temp_archive_path("sunset_engine_test_names.bin");
    let pass = "name_val_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // Empty name
    assert!(engine.create_file(ROOT_INODE_ID, "", 0o644, 1000, 1000).is_err());

    // Slashes
    assert!(engine.create_file(ROOT_INODE_ID, "foo/bar", 0o644, 1000, 1000).is_err());

    // Dot and dotdot
    assert!(engine.create_file(ROOT_INODE_ID, ".", 0o644, 1000, 1000).is_err());
    assert!(engine.create_file(ROOT_INODE_ID, "..", 0o644, 1000, 1000).is_err());

    // Name too long (> 255 bytes)
    let too_long = "a".repeat(256);
    assert!(engine.create_file(ROOT_INODE_ID, &too_long, 0o644, 1000, 1000).is_err());

    // Name exactly 255 bytes succeeds
    let max_len = "a".repeat(255);
    assert!(engine.create_file(ROOT_INODE_ID, &max_len, 0o644, 1000, 1000).is_ok());

    let _ = std::fs::remove_file(&path);
}

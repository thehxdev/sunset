use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use sunset::format::{
    crc32, APP_ID, AUTO_VACUUM_FULL, CIPHER_XCHACHA20_POLY1305, COMPAT_VERSION, FORMAT_VERSION,
    HEADER_SIZE, KDF_ARGON2ID, PLAINTEXT_BLOCK_SIZE, ROOT_INODE_ID, STORED_BLOCK_SIZE,
    SUNSET_MAGIC,
};
use sunset::fs_engine::SunsetEngine;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn test_signature_and_wire_layout_offsets() {
    let path = temp_path("sunset_test_wire_layout.bin");
    let pass = "test_wire_pass_123";

    {
        let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
        engine.flush().unwrap();
    }

    let mut file = File::open(&path).unwrap();
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header).unwrap();

    // 1. Signature (0x00..0x10): Dedicated signature "SUNSET format 1\0"
    assert_eq!(&header[0..16], SUNSET_MAGIC);

    // 2. Format write version (0x10..0x14): u32 LE
    assert_eq!(
        u32::from_le_bytes(header[16..20].try_into().unwrap()),
        FORMAT_VERSION
    );

    // 3. Minimum compatible read version (0x14..0x18): u32 LE
    assert_eq!(
        u32::from_le_bytes(header[20..24].try_into().unwrap()),
        COMPAT_VERSION
    );

    // 4. Plaintext block size (0x18..0x1C): 4096
    assert_eq!(
        u32::from_le_bytes(header[24..28].try_into().unwrap()),
        PLAINTEXT_BLOCK_SIZE as u32
    );

    // 5. Stored block size (0x1C..0x20): 4136
    assert_eq!(
        u32::from_le_bytes(header[28..32].try_into().unwrap()),
        STORED_BLOCK_SIZE as u32
    );

    // 6. KDF algorithm (0x20..0x24): 1 (Argon2id)
    assert_eq!(
        u32::from_le_bytes(header[32..36].try_into().unwrap()),
        KDF_ARGON2ID
    );

    // 7. Cipher algorithm (0x50..0x54): 1 (XChaCha20-Poly1305)
    assert_eq!(
        u32::from_le_bytes(header[80..84].try_into().unwrap()),
        CIPHER_XCHACHA20_POLY1305
    );

    // 8. Auto-vacuum (0x9C..0xA0): 1 (FULL auto-shrink enabled)
    assert_eq!(
        u32::from_le_bytes(header[156..160].try_into().unwrap()),
        AUTO_VACUUM_FULL
    );

    // 9. Application ID (0xA8..0xAC): 0x53554E53 ("SUNS")
    assert_eq!(
        u32::from_le_bytes(header[168..172].try_into().unwrap()),
        APP_ID
    );

    // 10. Reserved bytes (0xAC..0xFC): all zero
    assert_eq!(&header[172..252], &[0u8; 80]);

    // 11. Header CRC32 (0xFC..0x100): Valid checksum covering 0..252
    let expected_crc = crc32(&header[0..252]);
    let stored_crc = u32::from_le_bytes(header[252..256].try_into().unwrap());
    assert_eq!(stored_crc, expected_crc);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_header_corruption_and_tampering_rejection() {
    let path = temp_path("sunset_test_corruption.bin");
    let pass = "test_tamper_pass";

    {
        let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
        engine.flush().unwrap();
    }

    let mut raw_bytes = std::fs::read(&path).unwrap();

    // Corrupt one bit in the header
    raw_bytes[100] ^= 0x01;
    let tamper_path = temp_path("sunset_test_tampered.bin");
    std::fs::write(&tamper_path, &raw_bytes).unwrap();

    // Must be rejected with format error (checksum mismatch)
    let res = SunsetEngine::open(&tamper_path, pass);
    assert!(res.is_err());
    let err_msg = format!("{}", res.err().unwrap());
    assert!(err_msg.contains("checksum mismatch"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&tamper_path);
}

#[test]
fn test_container_shrinking_on_file_deletion() {
    let path = temp_path("sunset_test_shrinking.bin");
    let pass = "test_shrink_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let initial_file_len = std::fs::metadata(&path).unwrap().len();
    // Base archive: Header (256) + 2 superblocks (2 * 4136) + 1 inode block (4136) = 12664 bytes
    assert_eq!(
        initial_file_len,
        HEADER_SIZE as u64 + 3 * STORED_BLOCK_SIZE as u64
    );

    // Write a 64 KB file (16 blocks)
    let file1 = engine
        .create_file(ROOT_INODE_ID, "data.bin", 0o644, 1000, 1000)
        .unwrap();
    let sample = vec![0xAB; 64 * 1024];
    engine.write_bytes(file1.ino, 0, &sample).unwrap();
    engine.flush().unwrap();

    let expanded_len = std::fs::metadata(&path).unwrap().len();
    assert!(
        expanded_len >= initial_file_len + 16 * STORED_BLOCK_SIZE as u64,
        "File should expand when 64KB data is written"
    );

    // Now delete the file: with auto-vacuum, the container must shrink back immediately!
    engine.unlink(ROOT_INODE_ID, "data.bin").unwrap();
    engine.flush().unwrap();

    let shrunk_len = std::fs::metadata(&path).unwrap().len();
    println!("shrunk_len: {}, total_blocks: {}, inode_blocks: {:?}", shrunk_len, engine.total_blocks(), engine.inodes_count());
    assert_eq!(
        shrunk_len, initial_file_len,
        "Container must physically shrink back to initial size after file deletion"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_interleaved_file_deletion_and_block_relocation() {
    let path = temp_path("sunset_test_relocation.bin");
    let pass = "test_reloc_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // Create 3 files: File A, File B, File C
    let file_a = engine
        .create_file(ROOT_INODE_ID, "file_a.dat", 0o644, 1000, 1000)
        .unwrap();
    let data_a = b"AAA_FIRST_FILE_PAYLOAD_".repeat(200); // 4800 bytes (2 blocks)
    engine.write_bytes(file_a.ino, 0, &data_a).unwrap();

    let file_b = engine
        .create_file(ROOT_INODE_ID, "file_b.dat", 0o644, 1000, 1000)
        .unwrap();
    let data_b = b"BBB_SECOND_FILE_PAYLOAD_".repeat(300); // 7200 bytes (2 blocks)
    engine.write_bytes(file_b.ino, 0, &data_b).unwrap();

    let file_c = engine
        .create_file(ROOT_INODE_ID, "file_c.dat", 0o644, 1000, 1000)
        .unwrap();
    let data_c = b"CCC_THIRD_FILE_PAYLOAD_".repeat(400); // 9600 bytes (3 blocks)
    engine.write_bytes(file_c.ino, 0, &data_c).unwrap();

    engine.flush().unwrap();
    let size_all = std::fs::metadata(&path).unwrap().len();

    // Delete the FIRST file (file A).
    // This creates holes at physical blocks occupied by file A.
    // Auto-vacuum compaction must relocate the trailing blocks (from file C) into file A's vacated slots
    // and physically truncate the container!
    engine.unlink(ROOT_INODE_ID, "file_a.dat").unwrap();
    engine.flush().unwrap();

    let size_after_del_a = std::fs::metadata(&path).unwrap().len();
    assert!(
        size_after_del_a < size_all,
        "Container must shrink after deleting file A"
    );

    // Verify File B and File C data are 100% intact and uncorrupted after relocation!
    let b_lookup = engine.lookup(ROOT_INODE_ID, "file_b.dat").unwrap();
    let read_b = engine.read_bytes(b_lookup.ino, 0, data_b.len()).unwrap();
    assert_eq!(read_b, data_b, "File B data must match after relocation");

    let c_lookup = engine.lookup(ROOT_INODE_ID, "file_c.dat").unwrap();
    let read_c = engine.read_bytes(c_lookup.ino, 0, data_c.len()).unwrap();
    assert_eq!(read_c, data_c, "File C data must match after relocation");

    // Reopen archive from disk to verify on-disk persistent integrity
    drop(engine);
    let mut reopened = SunsetEngine::open(&path, pass).unwrap();

    let b_reopened = reopened.lookup(ROOT_INODE_ID, "file_b.dat").unwrap();
    assert_eq!(
        reopened
            .read_bytes(b_reopened.ino, 0, data_b.len())
            .unwrap(),
        data_b
    );

    let c_reopened = reopened.lookup(ROOT_INODE_ID, "file_c.dat").unwrap();
    assert_eq!(
        reopened
            .read_bytes(c_reopened.ino, 0, data_c.len())
            .unwrap(),
        data_c
    );

    // Delete File B and File C
    reopened.unlink(ROOT_INODE_ID, "file_b.dat").unwrap();
    reopened.unlink(ROOT_INODE_ID, "file_c.dat").unwrap();
    reopened.flush().unwrap();

    let final_size = std::fs::metadata(&path).unwrap().len();
    assert_eq!(
        final_size,
        HEADER_SIZE as u64 + 3 * STORED_BLOCK_SIZE as u64,
        "Container must shrink to minimal base size after deleting all files"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_large_file_indirect_block_shrinking_and_truncation() {
    let path = temp_path("sunset_test_indirect_shrink.bin");
    let pass = "test_indirect_shrink_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // Write a 200 KB file (requires 50 blocks, spanning direct and single indirect blocks)
    let file = engine
        .create_file(ROOT_INODE_ID, "big.bin", 0o644, 1000, 1000)
        .unwrap();
    let large_data = vec![0x77; 200 * 1024];
    engine.write_bytes(file.ino, 0, &large_data).unwrap();
    engine.flush().unwrap();

    let peak_size = std::fs::metadata(&path).unwrap().len();

    // Truncate file from 200 KB down to 1 KB (1 block)
    engine.truncate(file.ino, 1024).unwrap();
    engine.flush().unwrap();

    let truncated_size = std::fs::metadata(&path).unwrap().len();
    assert!(
        truncated_size < peak_size - (45 * STORED_BLOCK_SIZE as u64),
        "Container file must shrink by freed indirect blocks upon truncation"
    );

    // Verify 1 KB content
    let read_back = engine.read_bytes(file.ino, 0, 1024).unwrap();
    assert_eq!(read_back, &large_data[..1024]);

    // Truncate to 0 and delete
    engine.truncate(file.ino, 0).unwrap();
    engine.unlink(ROOT_INODE_ID, "big.bin").unwrap();
    engine.flush().unwrap();

    let min_size = std::fs::metadata(&path).unwrap().len();
    assert_eq!(
        min_size,
        HEADER_SIZE as u64 + 3 * STORED_BLOCK_SIZE as u64
    );

    let _ = std::fs::remove_file(&path);
}

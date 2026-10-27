use rand::{Rng, RngExt};
use std::path::PathBuf;
use sunset::dir::DirectoryData;
use sunset::format::{
    OnDiskHeader, SuperblockPayload, HEADER_SIZE, PLAINTEXT_BLOCK_SIZE, ROOT_INODE_ID,
    STORED_BLOCK_SIZE,
};
use sunset::fs_engine::SunsetEngine;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn test_fuzz_header_parser() {
    let mut rng = rand::rng();
    let mut buf = [0u8; HEADER_SIZE];

    // 1. Completely random bytes fuzzing
    for _ in 0..5000 {
        rng.fill_bytes(&mut buf);
        let _ = OnDiskHeader::from_bytes(&buf);
    }

    // 2. Fuzzing valid header with random bitflips
    let salt = [42u8; 32];
    let nonce = [7u8; 24];
    let ct = [99u8; 32];
    let tag = [11u8; 16];
    let valid_header = OnDiskHeader::new(salt, 65536, 3, 4, nonce, ct, tag);
    let valid_bytes = valid_header.to_bytes().unwrap();

    for _ in 0..5000 {
        let mut corrupted = valid_bytes;
        // Flip between 1 and 16 random bits
        let flips = rng.random_range(1..=16);
        for _ in 0..flips {
            let byte_idx = rng.random_range(0..HEADER_SIZE);
            let bit_idx = rng.random_range(0..8);
            corrupted[byte_idx] ^= 1 << bit_idx;
        }

        // Must never panic; if CRC or magic corrupted, must cleanly error
        if let Ok(parsed) = OnDiskHeader::from_bytes(&corrupted) {
            // If it somehow passed CRC and magic (astronomically rare bit flip cancellation), it must be internally valid
            assert_eq!(parsed.block_size, PLAINTEXT_BLOCK_SIZE as u32);
        }
    }

    // 3. Truncated slices fuzzing
    for len in 0..HEADER_SIZE {
        let _ = OnDiskHeader::from_bytes(&valid_bytes[..len]);
    }
}

#[test]
fn test_fuzz_superblock_payload() {
    let mut rng = rand::rng();

    // 1. Completely random bytes fuzzing of various lengths
    for _ in 0..5000 {
        let len = rng.random_range(0..=PLAINTEXT_BLOCK_SIZE * 2);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        let _ = SuperblockPayload::from_bytes(&buf);
    }

    // 2. Valid superblock with bit mutations
    let mut sb = SuperblockPayload::new();
    sb.seq = 100;
    sb.total_blocks = 200;
    sb.inode_blocks = vec![2, 3, 4];
    sb.free_blocks = vec![10, 11, 12, 13, 14, 15];
    let valid_sb_bytes = sb.to_bytes().unwrap();

    for _ in 0..5000 {
        let mut corrupted = valid_sb_bytes;
        let flips = rng.random_range(1..=8);
        for _ in 0..flips {
            let byte_idx = rng.random_range(0..PLAINTEXT_BLOCK_SIZE);
            let bit_idx = rng.random_range(0..8);
            corrupted[byte_idx] ^= 1 << bit_idx;
        }
        let _ = SuperblockPayload::from_bytes(&corrupted);
    }
}

#[test]
fn test_fuzz_directory_deserialization_and_names() {
    let mut rng = rand::rng();

    // 1. Arbitrary byte fuzzing
    for _ in 0..3000 {
        let len = rng.random_range(0..=8192);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        let _ = DirectoryData::from_bytes(&buf);
    }

    // 2. Name validation fuzzing: control chars, emojis, slashes, nulls, huge strings
    let invalid_chars = ['\0', '/', '\r', '\n'];
    for _ in 0..2000 {
        let len = rng.random_range(0..=400);
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            if rng.random_bool(0.1) {
                let ch = invalid_chars[rng.random_range(0..invalid_chars.len())];
                s.push(ch);
            } else {
                let ch = rng.random_range(32..=126) as u8 as char;
                s.push(ch);
            }
        }

        let res = DirectoryData::validate_name(&s);
        if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\0') || s.len() > 255 {
            assert!(res.is_err(), "Expected failure for name: {:?}", s);
        } else {
            assert!(res.is_ok(), "Expected success for valid name: {:?}", s);
        }
    }
}

#[test]
fn test_fuzz_ciphertext_bitflips_and_block_swapping() {
    let mut rng = rand::rng();
    let salt = [11u8; 32];
    let key = sunset::crypto::derive_key("fuzz_secret_pass", &salt, 1024, 1, 1).unwrap();
    let nonce = sunset::crypto::generate_nonce();
    let plaintext = [0x42u8; PLAINTEXT_BLOCK_SIZE];
    let aad = 5u64.to_le_bytes();

    let ciphertext = sunset::crypto::encrypt_block(&key, &nonce, &plaintext, &aad).unwrap();
    assert_eq!(ciphertext.len(), PLAINTEXT_BLOCK_SIZE + 16);

    // 1. In-depth bit flip fuzzing on AEAD decryption (5,000 random bit flips)
    // Every single bit flip in nonce, ciphertext, or Poly1305 tag must trigger AEAD authentication error
    for _ in 0..5000 {
        let flip_nonce = rng.random_bool(0.2);
        if flip_nonce {
            let mut bad_nonce = nonce;
            let byte_idx = rng.random_range(0..bad_nonce.len());
            bad_nonce[byte_idx] ^= 1 << rng.random_range(0..8);
            let res = sunset::crypto::decrypt_block(&key, &bad_nonce, &ciphertext, &aad);
            assert!(res.is_err());
        } else {
            let mut bad_ct = ciphertext.clone();
            let byte_idx = rng.random_range(0..bad_ct.len());
            bad_ct[byte_idx] ^= 1 << rng.random_range(0..8);
            let res = sunset::crypto::decrypt_block(&key, &nonce, &bad_ct, &aad);
            assert!(res.is_err());
        }
    }

    // 2. AAD Tampering / Block Swapping Fuzzing (500 random different block indices)
    for _ in 0..500 {
        let wrong_block_id: u64 = rng.random_range(6..100_000);
        let wrong_aad = wrong_block_id.to_le_bytes();
        let res = sunset::crypto::decrypt_block(&key, &nonce, &ciphertext, &wrong_aad);
        assert!(
            res.is_err(),
            "Decryption with wrong block AAD must fail authentication"
        );
    }

    // 3. Full archive block swapping on disk
    let path = temp_path("sunset_fuzz_tamper.bin");
    let pass = "fuzz_key_safe_123!";
    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let f1 = engine
        .create_file(ROOT_INODE_ID, "secret_a.txt", 0o644, 1000, 1000)
        .unwrap();
    let data_a = b"CONFIDENTIAL_DATA_CHUNK_AAA".repeat(100);
    engine.write_bytes(f1.ino, 0, &data_a).unwrap();

    let f2 = engine
        .create_file(ROOT_INODE_ID, "secret_b.txt", 0o644, 1000, 1000)
        .unwrap();
    let data_b = b"CONFIDENTIAL_DATA_CHUNK_BBB".repeat(100);
    engine.write_bytes(f2.ino, 0, &data_b).unwrap();
    engine.flush().unwrap();
    drop(engine);

    let raw_archive = std::fs::read(&path).unwrap();
    assert!(raw_archive.len() >= HEADER_SIZE + 4 * STORED_BLOCK_SIZE);

    let b2_start = HEADER_SIZE + 2 * STORED_BLOCK_SIZE;
    let b3_start = HEADER_SIZE + 3 * STORED_BLOCK_SIZE;
    let b2_data = raw_archive[b2_start..b2_start + STORED_BLOCK_SIZE].to_vec();
    let b3_data = raw_archive[b3_start..b3_start + STORED_BLOCK_SIZE].to_vec();

    let mut swapped_file = raw_archive;
    swapped_file[b2_start..b2_start + STORED_BLOCK_SIZE].copy_from_slice(&b3_data);
    swapped_file[b3_start..b3_start + STORED_BLOCK_SIZE].copy_from_slice(&b2_data);

    let swapped_path = temp_path("sunset_swapped.bin");
    std::fs::write(&swapped_path, &swapped_file).unwrap();

    let swapped_res = SunsetEngine::open(&swapped_path, pass);
    if let Ok(mut eng) = swapped_res {
        let r1 = eng.read_bytes(f1.ino, 0, data_a.len());
        let r2 = eng.read_bytes(f2.ino, 0, data_b.len());
        assert!(r1.is_err() || r2.is_err(), "Block swapping must be detected by AAD authentication");
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&swapped_path);
}

#[test]
fn test_fuzz_truncated_archive_boundaries() {
    let path = temp_path("sunset_fuzz_trunc.bin");
    let pass = "trunc_fuzz_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let file = engine
        .create_file(ROOT_INODE_ID, "sample.txt", 0o644, 1000, 1000)
        .unwrap();
    engine.write_bytes(file.ino, 0, b"TEST DATA PAYLOAD").unwrap();
    engine.flush().unwrap();
    drop(engine);

    let raw = std::fs::read(&path).unwrap();
    let total_len = raw.len();

    // 1. Test all byte boundaries below 256 (fails header size check cleanly)
    for len in 0..HEADER_SIZE {
        let trunc_path = temp_path(&format!("sunset_trunc_{}.bin", len));
        std::fs::write(&trunc_path, &raw[..len]).unwrap();

        let res = SunsetEngine::open(&trunc_path, pass);
        assert!(res.is_err());

        let _ = std::fs::remove_file(&trunc_path);
    }

    // 2. Sample boundaries across physical metadata blocks
    let sample_points = [
        HEADER_SIZE,
        HEADER_SIZE + 10,
        HEADER_SIZE + 1000,
        HEADER_SIZE + STORED_BLOCK_SIZE / 2,
        HEADER_SIZE + STORED_BLOCK_SIZE,
        HEADER_SIZE + STORED_BLOCK_SIZE + 50,
        HEADER_SIZE + 2 * STORED_BLOCK_SIZE,
    ];

    for &len in &sample_points {
        let trunc_path = temp_path(&format!("sunset_trunc_block_{}.bin", len));
        std::fs::write(&trunc_path, &raw[..len]).unwrap();

        let res = SunsetEngine::open(&trunc_path, pass);
        assert!(res.is_err(), "Length {} must fail open", len);

        let _ = std::fs::remove_file(&trunc_path);
    }

    // 3. When truncated at directory data block boundary (total_len - 1), reading dir data must fail
    let data_trunc_path = temp_path("sunset_trunc_data.bin");
    std::fs::write(&data_trunc_path, &raw[..total_len - 1]).unwrap();
    if let Ok(mut eng) = SunsetEngine::open(&data_trunc_path, pass) {
        let dir_res = eng.read_dir_data(ROOT_INODE_ID);
        assert!(dir_res.is_err(), "Reading truncated directory block must fail");
    }
    let _ = std::fs::remove_file(&data_trunc_path);

    // 4. When truncated at file data block boundary (block 3 truncated)
    let block3_trunc_path = temp_path("sunset_trunc_block3.bin");
    let block3_cutoff = HEADER_SIZE + 3 * STORED_BLOCK_SIZE + 100;
    std::fs::write(&block3_trunc_path, &raw[..block3_cutoff]).unwrap();
    if let Ok(mut eng) = SunsetEngine::open(&block3_trunc_path, pass) {
        let read_res = eng.read_bytes(file.ino, 0, 100);
        assert!(read_res.is_err(), "Reading truncated file block must fail");
    }
    let _ = std::fs::remove_file(&block3_trunc_path);

    let _ = std::fs::remove_file(&path);
}

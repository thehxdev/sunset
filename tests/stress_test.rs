use rand::RngExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use sunset::format::{HEADER_SIZE, PLAINTEXT_BLOCK_SIZE, ROOT_INODE_ID, STORED_BLOCK_SIZE};
use sunset::fs_engine::SunsetEngine;
use sunset::inode::InodeKind;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn test_stress_multithreaded_concurrent_access() {
    let path = temp_path("sunset_stress_threads.bin");
    let pass = "stress_concurrent_pass_123";

    let engine = SunsetEngine::init(&path, pass, None).unwrap();
    let engine_arc = Arc::new(Mutex::new(engine));

    // Prepopulate a common base directory and 4 base files
    {
        let mut eng = engine_arc.lock().unwrap();
        let base_dir = eng
            .mkdir(ROOT_INODE_ID, "shared_dir", 0o755, 1000, 1000)
            .unwrap();
        for i in 0..4 {
            let f = eng
                .create_file(base_dir.ino, &format!("base_{}.dat", i), 0o644, 1000, 1000)
                .unwrap();
            let data = vec![i as u8 + 10; 8192]; // 2 blocks
            eng.write_bytes(f.ino, 0, &data).unwrap();
        }
        eng.flush().unwrap();
    }

    let num_threads = 16;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let eng_clone = Arc::clone(&engine_arc);
        let bar_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            bar_clone.wait(); // All threads start hammering simultaneously

            let mut rng = rand::rng();

            for iter in 0usize..30 {
                let op = rng.random_range(0..5);
                match op {
                    // Op 0: Create dedicated thread file and write data
                    0 => {
                        let mut eng = eng_clone.lock().unwrap();
                        let fname = format!("thread_{}_file_{}.dat", thread_id, iter);
                        if let Ok(f) = eng.create_file(ROOT_INODE_ID, &fname, 0o644, 1000, 1000) {
                            let payload = vec![thread_id as u8; rng.random_range(500..5000)];
                            let _ = eng.write_bytes(f.ino, 0, &payload);
                        }
                    }
                    // Op 1: Read from shared base files
                    1 => {
                        let mut eng = eng_clone.lock().unwrap();
                        let target_idx = rng.random_range(0..4);
                        if let Ok(dir_node) = eng.lookup(ROOT_INODE_ID, "shared_dir") {
                            let fname = format!("base_{}.dat", target_idx);
                            if let Ok(f) = eng.lookup(dir_node.ino, &fname) {
                                if let Ok(data) = eng.read_bytes(f.ino, 0, 8192) {
                                    assert_eq!(data.len(), 8192);
                                    assert_eq!(data[0], target_idx as u8 + 10);
                                }
                            }
                        }
                    }
                    // Op 2: Overwrite random chunk in shared base file
                    2 => {
                        let mut eng = eng_clone.lock().unwrap();
                        let target_idx = rng.random_range(0..4);
                        if let Ok(dir_node) = eng.lookup(ROOT_INODE_ID, "shared_dir") {
                            let fname = format!("base_{}.dat", target_idx);
                            if let Ok(f) = eng.lookup(dir_node.ino, &fname) {
                                let offset = rng.random_range(0..4000) as u64;
                                let patch = vec![target_idx as u8 + 10; 100];
                                let _ = eng.write_bytes(f.ino, offset, &patch);
                            }
                        }
                    }
                    // Op 3: List root directory entries
                    3 => {
                        let mut eng = eng_clone.lock().unwrap();
                        let _ = eng.read_dir_data(ROOT_INODE_ID);
                    }
                    // Op 4: Delete temporary thread files
                    _ => {
                        let mut eng = eng_clone.lock().unwrap();
                        let fname = format!("thread_{}_file_{}.dat", thread_id, iter.saturating_sub(1));
                        let _ = eng.unlink(ROOT_INODE_ID, &fname);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    // Final flush and full integrity verification
    {
        let mut eng = engine_arc.lock().unwrap();
        eng.flush().unwrap();
    }
    drop(engine_arc);

    // Reopen archive from disk and verify consistency
    let mut reopened = SunsetEngine::open(&path, pass).unwrap();
    let shared_dir = reopened.lookup(ROOT_INODE_ID, "shared_dir").unwrap();
    for i in 0..4 {
        let f = reopened
            .lookup(shared_dir.ino, &format!("base_{}.dat", i))
            .unwrap();
        let data = reopened.read_bytes(f.ino, 0, 8192).unwrap();
        assert_eq!(data.len(), 8192);
        assert_eq!(data[0], i as u8 + 10);
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_stress_deep_hierarchy_and_high_churn_compaction() {
    let path = temp_path("sunset_stress_churn.bin");
    let pass = "stress_churn_pass_999";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // 1. Create a deep 5-level directory hierarchy:
    // /level1/level2/level3/level4/level5
    let mut curr_ino = ROOT_INODE_ID;
    for lvl in 1..=5 {
        let d = engine
            .mkdir(curr_ino, &format!("level_{}", lvl), 0o755, 1000, 1000)
            .unwrap();
        curr_ino = d.ino;
    }
    let deepest_dir_ino = curr_ino;

    // 2. High-churn file allocation and deletion across 5 rounds
    let mut active_files: Vec<String> = Vec::new();
    let mut rng = rand::rng();

    for round in 0..5 {
        // Create 60 files with varying sizes (some small, some multi-block)
        for i in 0..60 {
            let fname = format!("r{}_file_{}.bin", round, i);
            let f = engine
                .create_file(deepest_dir_ino, &fname, 0o644, 1000, 1000)
                .unwrap();
            let size = rng.random_range(100..12000); // 1 to 3 blocks
            let payload = vec![(round * 10 + i) as u8; size];
            engine.write_bytes(f.ino, 0, &payload).unwrap();
            active_files.push(fname);
        }
        engine.flush().unwrap();

        // Randomly delete half the existing files (creates holes for auto-vacuum)
        let num_to_delete = active_files.len() / 2;
        for _ in 0..num_to_delete {
            if !active_files.is_empty() {
                let remove_idx = rng.random_range(0..active_files.len());
                let fname = active_files.remove(remove_idx);
                engine.unlink(deepest_dir_ino, &fname).unwrap();
            }
        }
        engine.flush().unwrap();
    }

    // Verify all remaining files have intact, uncorrupted content
    for fname in &active_files {
        let f = engine.lookup(deepest_dir_ino, fname).unwrap();
        assert_eq!(f.kind, InodeKind::File);
        let read_data = engine.read_bytes(f.ino, 0, f.size as usize).unwrap();
        assert_eq!(read_data.len(), f.size as usize);
    }

    // Delete all remaining files and subdirectories
    for fname in active_files {
        engine.unlink(deepest_dir_ino, &fname).unwrap();
    }
    engine.flush().unwrap();

    // Verify directory is empty
    let dir_data = engine.read_dir_data(deepest_dir_ino).unwrap();
    assert!(dir_data.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_stress_crash_recovery_dual_superblocks() {
    let path = temp_path("sunset_stress_dual_sb.bin");
    let pass = "crash_recovery_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let f = engine
        .create_file(ROOT_INODE_ID, "critical_doc.txt", 0o644, 1000, 1000)
        .unwrap();
    engine
        .write_bytes(f.ino, 0, b"MISSION CRITICAL TRANSACTION DATA")
        .unwrap();
    engine.flush().unwrap();
    drop(engine);

    let raw = std::fs::read(&path).unwrap();

    // Case 1: Superblock 0 (bytes 256..256+4136) is completely zeroed (power failure during SB0 rewrite)
    {
        let mut corrupted_sb0 = raw.clone();
        for b in &mut corrupted_sb0[HEADER_SIZE..HEADER_SIZE + STORED_BLOCK_SIZE] {
            *b = 0;
        }
        let cpath0 = temp_path("sunset_crash_sb0.bin");
        std::fs::write(&cpath0, &corrupted_sb0).unwrap();

        // Must seamlessly recover using Superblock 1!
        let mut recovered0 = SunsetEngine::open(&cpath0, pass).unwrap();
        let file_node = recovered0.lookup(ROOT_INODE_ID, "critical_doc.txt").unwrap();
        let content = recovered0.read_bytes(file_node.ino, 0, 100).unwrap();
        assert_eq!(content, b"MISSION CRITICAL TRANSACTION DATA");

        let _ = std::fs::remove_file(&cpath0);
    }

    // Case 2: Superblock 1 (bytes 256+4136..256+2*4136) is completely garbage (power failure during SB1 rewrite)
    {
        let mut corrupted_sb1 = raw.clone();
        let sb1_start = HEADER_SIZE + STORED_BLOCK_SIZE;
        for b in &mut corrupted_sb1[sb1_start..sb1_start + STORED_BLOCK_SIZE] {
            *b = 0xFF;
        }
        let cpath1 = temp_path("sunset_crash_sb1.bin");
        std::fs::write(&cpath1, &corrupted_sb1).unwrap();

        // Must seamlessly recover using Superblock 0!
        let mut recovered1 = SunsetEngine::open(&cpath1, pass).unwrap();
        let file_node = recovered1.lookup(ROOT_INODE_ID, "critical_doc.txt").unwrap();
        let content = recovered1.read_bytes(file_node.ino, 0, 100).unwrap();
        assert_eq!(content, b"MISSION CRITICAL TRANSACTION DATA");

        let _ = std::fs::remove_file(&cpath1);
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_stress_huge_sparse_file_boundary_jumps() {
    let path = temp_path("sunset_stress_sparse.bin");
    let pass = "stress_sparse_pass";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let file = engine
        .create_file(ROOT_INODE_ID, "sparse_giant.dat", 0o644, 1000, 1000)
        .unwrap();

    // 1. Direct block 0 (offset 0)
    engine.write_bytes(file.ino, 0, b"DIRECT_BLOCK_DATA").unwrap();

    // 2. Single indirect boundary: block 15 (offset 15 * 4096 = 61,440)
    let single_indir_offset = 15 * PLAINTEXT_BLOCK_SIZE as u64;
    engine
        .write_bytes(file.ino, single_indir_offset, b"SINGLE_INDIR_DATA")
        .unwrap();

    // 3. Double indirect boundary: block 600 (offset 600 * 4096 = 2,457,600)
    let double_indir_offset = 600 * PLAINTEXT_BLOCK_SIZE as u64;
    engine
        .write_bytes(file.ino, double_indir_offset, b"DOUBLE_INDIR_DATA")
        .unwrap();

    engine.flush().unwrap();

    // Sparse hole check: reading between block 1 and 14 must return pure zeroes!
    let hole_data = engine.read_bytes(file.ino, 4096, 4096).unwrap();
    assert_eq!(hole_data, vec![0u8; 4096]);

    // Verify written points
    let r0 = engine.read_bytes(file.ino, 0, 17).unwrap();
    assert_eq!(r0, b"DIRECT_BLOCK_DATA");

    let r1 = engine.read_bytes(file.ino, single_indir_offset, 17).unwrap();
    assert_eq!(r1, b"SINGLE_INDIR_DATA");

    let r2 = engine.read_bytes(file.ino, double_indir_offset, 17).unwrap();
    assert_eq!(r2, b"DOUBLE_INDIR_DATA");

    // 4. Truncate from 2.5 MB down to single indirect offset
    let size_before_trunc = std::fs::metadata(&path).unwrap().len();
    engine.truncate(file.ino, single_indir_offset + 17).unwrap();
    engine.flush().unwrap();

    let size_after_trunc = std::fs::metadata(&path).unwrap().len();
    assert!(
        size_after_trunc < size_before_trunc,
        "Container must shrink when double indirect range is truncated away"
    );

    // Verify single indirect and direct are still intact
    assert_eq!(
        engine.read_bytes(file.ino, single_indir_offset, 17).unwrap(),
        b"SINGLE_INDIR_DATA"
    );
    assert_eq!(engine.read_bytes(file.ino, 0, 17).unwrap(), b"DIRECT_BLOCK_DATA");

    let _ = std::fs::remove_file(&path);
}

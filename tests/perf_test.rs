use std::path::PathBuf;
use std::time::Instant;
use sunset::format::ROOT_INODE_ID;
use sunset::fs_engine::SunsetEngine;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn bench_throughput_large_file() {
    let path = temp_path("sunset_perf_large_file.bin");
    let pass = "benchmark_key_123";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    // 20 MB payload (exceeds default 8MB cache capacity, forcing heavy LRU page evictions)
    let payload = vec![0x5A; 20 * 1024 * 1024];

    let t0 = Instant::now();
    let file = engine
        .create_file(ROOT_INODE_ID, "big_20mb.dat", 0o644, 1000, 1000)
        .unwrap();

    let t_create = t0.elapsed();

    let t_write_start = Instant::now();
    let written = engine.write_bytes(file.ino, 0, &payload).unwrap();
    assert_eq!(written, payload.len());
    engine.flush().unwrap();
    let t_write = t_write_start.elapsed();

    let t_read_start = Instant::now();
    let read_back = engine.read_bytes(file.ino, 0, payload.len()).unwrap();
    assert_eq!(read_back.len(), payload.len());
    assert_eq!(&read_back[..100], &payload[..100]);
    assert_eq!(&read_back[payload.len() - 100..], &payload[payload.len() - 100..]);
    let t_read = t_read_start.elapsed();

    println!(
        "\n[BENCHMARK] 20MB file create: {:?}, write+flush: {:?}, read: {:?}",
        t_create, t_write, t_read
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn bench_many_small_files() {
    let path = temp_path("sunset_perf_many_files.bin");
    let pass = "benchmark_key_123";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();

    let dir = engine
        .mkdir(ROOT_INODE_ID, "small_files", 0o755, 1000, 1000)
        .unwrap();

    let count = 2000;
    let t_start = Instant::now();
    for i in 0..count {
        let name = format!("file_{}.txt", i);
        let f = engine.create_file(dir.ino, &name, 0o644, 1000, 1000).unwrap();
        let data = format!("Payload for file {}", i);
        engine.write_bytes(f.ino, 0, data.as_bytes()).unwrap();
    }
    engine.flush().unwrap();
    let t_create_write = t_start.elapsed();

    let t_read_start = Instant::now();
    for i in 0..count {
        let name = format!("file_{}.txt", i);
        let f = engine.lookup(dir.ino, &name).unwrap();
        let expected = format!("Payload for file {}", i);
        let data = engine.read_bytes(f.ino, 0, expected.len()).unwrap();
        assert_eq!(data, expected.as_bytes());
    }
    let t_read = t_read_start.elapsed();

    let t_delete_start = Instant::now();
    for i in 0..count {
        let name = format!("file_{}.txt", i);
        engine.unlink(dir.ino, &name).unwrap();
    }
    engine.flush().unwrap();
    let t_delete = t_delete_start.elapsed();

    println!(
        "\n[BENCHMARK] 2000 small files: create+write: {:?}, read: {:?}, unlink+flush: {:?}",
        t_create_write, t_read, t_delete
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn bench_random_block_io() {
    let path = temp_path("sunset_perf_random_io.bin");
    let pass = "benchmark_key_123";

    let mut engine = SunsetEngine::init(&path, pass, None).unwrap();
    let file = engine
        .create_file(ROOT_INODE_ID, "random.dat", 0o644, 1000, 1000)
        .unwrap();

    // Preallocate 1000 blocks (4 MB)
    let chunk = vec![0xAA; 4096];
    for b in 0..1000 {
        engine.write_bytes(file.ino, b * 4096, &chunk).unwrap();
    }
    engine.flush().unwrap();

    // Perform 5000 random block overwrites
    let t_start = Instant::now();
    let patch = [0x55; 4096];
    for i in 0..5000 {
        let lblock = (i * 73) % 1000;
        engine.write_bytes(file.ino, lblock * 4096, &patch).unwrap();
    }
    engine.flush().unwrap();
    let t_random_writes = t_start.elapsed();

    // Perform 5000 random reads
    let t_read_start = Instant::now();
    for i in 0..5000 {
        let lblock = (i * 37) % 1000;
        let buf = engine.read_bytes(file.ino, lblock * 4096, 4096).unwrap();
        assert_eq!(buf.len(), 4096);
    }
    let t_random_reads = t_read_start.elapsed();

    println!(
        "\n[BENCHMARK] 5000 random 4KB writes: {:?}, 5000 random 4KB reads: {:?}",
        t_random_writes, t_random_reads
    );

    let _ = std::fs::remove_file(&path);
}

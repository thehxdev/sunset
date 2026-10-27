use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn get_bin_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("sunset");
    path
}

#[test]
fn test_cli_end_to_end() {
    let sunset_bin = get_bin_path();
    let test_dir = std::env::current_dir().unwrap();
    let archive_path = test_dir.join("test_cli_archive.bin");
    let key_file = test_dir.join("test_cli_key.txt");
    let host_src = test_dir.join("test_cli_src.txt");
    let host_dst = test_dir.join("test_cli_dst.txt");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&key_file);
    let _ = std::fs::remove_file(&host_src);
    let _ = std::fs::remove_file(&host_dst);

    std::fs::write(&key_file, "super_secure_vault_key_999\n").unwrap();
    let src_content = b"TEST DATA REPEATED: ".repeat(250); // 5000 bytes spanning multiple blocks
    std::fs::write(&host_src, &src_content).unwrap();

    // 1. sunset init with --key-file
    let output = Command::new(&sunset_bin)
        .arg("init")
        .arg(&archive_path)
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset init");
    assert!(output.status.success(), "init failed: {:?}", String::from_utf8_lossy(&output.stderr));

    // 2. sunset mkdir
    let output = Command::new(&sunset_bin)
        .arg("mkdir")
        .arg(&archive_path)
        .arg("nested_dir")
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset mkdir");
    assert!(output.status.success());

    // 3. sunset put
    let output = Command::new(&sunset_bin)
        .arg("put")
        .arg(&archive_path)
        .arg(&host_src)
        .arg("nested_dir/data.bin")
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset put");
    assert!(output.status.success());

    // 4. sunset ls
    let output = Command::new(&sunset_bin)
        .arg("ls")
        .arg(&archive_path)
        .arg("nested_dir")
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset ls");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("data.bin"));

    // 5. sunset cat
    let output = Command::new(&sunset_bin)
        .arg("cat")
        .arg(&archive_path)
        .arg("nested_dir/data.bin")
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset cat");
    assert!(output.status.success());
    assert_eq!(output.stdout, src_content);

    // 6. sunset get
    let output = Command::new(&sunset_bin)
        .arg("get")
        .arg(&archive_path)
        .arg("nested_dir/data.bin")
        .arg(&host_dst)
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset get");
    assert!(output.status.success());
    let extracted = std::fs::read(&host_dst).unwrap();
    assert_eq!(extracted, src_content);

    // 7. sunset check
    let output = Command::new(&sunset_bin)
        .arg("check")
        .arg(&archive_path)
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .expect("Failed to run sunset check");
    assert!(output.status.success());

    // 8. Wrong key fails with helpful message
    let output = Command::new(&sunset_bin)
        .arg("ls")
        .arg(&archive_path)
        .arg("-k")
        .arg("definitely_wrong_key")
        .output()
        .expect("Failed to run sunset ls with wrong key");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid encryption key") || stderr.contains("authentication failed"));

    // 9. Non-existent archive produces helpful error message
    let output = Command::new(&sunset_bin)
        .arg("ls")
        .arg("non_existent_archive_12345.bin")
        .arg("-k")
        .arg("some_key")
        .output()
        .expect("Failed to run sunset ls on non-existent archive");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist") && stderr.contains("sunset init"));

    // 10. --key-stdin works via piped stdin
    let mut child = Command::new(&sunset_bin)
        .arg("cat")
        .arg(&archive_path)
        .arg("nested_dir/data.bin")
        .arg("--key-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process with stdin");

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"super_secure_vault_key_999\n").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, src_content);

    // Cleanup
    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&key_file);
    let _ = std::fs::remove_file(&host_src);
    let _ = std::fs::remove_file(&host_dst);
}

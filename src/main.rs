use clap::Parser;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use sunset::block_io::BlockDevice;
use sunset::cli::{parse_size_to_blocks, resolve_key, Cli, Commands};
use sunset::error::SunsetError;
use sunset::format::ROOT_INODE_ID;
use sunset::fs_engine::SunsetEngine;
use sunset::fuse_adapter::SunsetFuseFs;
use sunset::inode::InodeKind;

fn ensure_archive_exists(path: &Path) -> Result<(), SunsetError> {
    if !path.exists() {
        return Err(SunsetError::NotFound(format!(
            "Archive file '{}' does not exist. Run 'sunset init {}' to initialize a new archive.",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

fn resolve_path_to_ino(engine: &mut SunsetEngine, path_str: &str) -> Result<u64, SunsetError> {
    let clean = path_str.trim().trim_matches('/');
    if clean.is_empty() {
        return Ok(ROOT_INODE_ID);
    }
    let mut curr_ino = ROOT_INODE_ID;
    for segment in clean.split('/') {
        if segment.is_empty() {
            continue;
        }
        let node = engine.lookup(curr_ino, segment)?;
        curr_ino = node.ino;
    }
    Ok(curr_ino)
}

fn resolve_parent_and_name(
    engine: &mut SunsetEngine,
    path_str: &str,
) -> Result<(u64, String), SunsetError> {
    let clean = path_str.trim().trim_matches('/');
    if clean.is_empty() {
        return Err(SunsetError::InvalidArgument(
            "Path cannot be empty or root".to_string(),
        ));
    }
    if let Some(pos) = clean.rfind('/') {
        let parent_path = &clean[..pos];
        let name = &clean[pos + 1..];
        let parent_ino = resolve_path_to_ino(engine, parent_path)?;
        Ok((parent_ino, name.to_string()))
    } else {
        Ok((ROOT_INODE_ID, clean.to_string()))
    }
}

fn parse_mount_options(opts_str: &str) -> Vec<fuser::MountOption> {
    let mut opts = Vec::new();
    for opt in opts_str.split(',') {
        let opt = opt.trim();
        match opt {
            "ro" => opts.push(fuser::MountOption::RO),
            "rw" => opts.push(fuser::MountOption::RW),
            "auto_unmount" => opts.push(fuser::MountOption::AutoUnmount),
            "default_permissions" => opts.push(fuser::MountOption::DefaultPermissions),
            "dev" => opts.push(fuser::MountOption::Dev),
            "nodev" => opts.push(fuser::MountOption::NoDev),
            "suid" => opts.push(fuser::MountOption::Suid),
            "nosuid" => opts.push(fuser::MountOption::NoSuid),
            "exec" => opts.push(fuser::MountOption::Exec),
            "noexec" => opts.push(fuser::MountOption::NoExec),
            other if !other.is_empty() => opts.push(fuser::MountOption::CUSTOM(other.to_string())),
            _ => {}
        }
    }
    opts
}

fn format_mode(mode: u32, kind: InodeKind) -> String {
    let type_char = match kind {
        InodeKind::Directory => 'd',
        InodeKind::File => '-',
        InodeKind::Symlink => 'l',
    };
    let rwx = [
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 { 'x' } else { '-' },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 { 'x' } else { '-' },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 { 'x' } else { '-' },
    ];
    let perm_str: String = rwx.iter().collect();
    format!("{}{}", type_char, perm_str)
}

fn run() -> Result<(), SunsetError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            archive,
            key,
            key_file,
            key_stdin,
            size,
        } => {
            let k = resolve_key(key, key_file, key_stdin, true)?;
            let blocks = size
                .as_deref()
                .map(parse_size_to_blocks)
                .transpose()?;

            SunsetEngine::init(&archive, &k, blocks)?;
            println!("Initialized encrypted archive at: {}", archive.display());
        }

        Commands::Mount {
            archive,
            mountpoint,
            key,
            key_file,
            key_stdin,
            options,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let engine = SunsetEngine::open(&archive, &k)?;

            if !mountpoint.exists() {
                std::fs::create_dir_all(&mountpoint).map_err(|e| {
                    SunsetError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to create mount point directory '{}': {}",
                            mountpoint.display(),
                            e
                        ),
                    ))
                })?;
            }

            let mut config = fuser::Config::default();
            config.mount_options.push(fuser::MountOption::FSName(format!(
                "sunset:{}",
                archive.display()
            )));
            config
                .mount_options
                .push(fuser::MountOption::Subtype("sunsetfs".to_string()));

            let is_ro = options
                .as_deref()
                .map(|o| o.split(',').any(|x| x.trim() == "ro"))
                .unwrap_or(false);

            if let Some(opts_str) = options {
                let parsed = parse_mount_options(&opts_str);
                config.mount_options.extend(parsed);
            }

            println!(
                "Mounting encrypted archive {} to {}...",
                archive.display(),
                mountpoint.display()
            );

            let fs = SunsetFuseFs::new(engine, is_ro);
            let mut session = fuser::Session::new(fs, &mountpoint, &config).map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "FUSE mount failed on '{}': {}. Make sure FUSE is supported on this system and fusermount3 is installed.",
                        mountpoint.display(),
                        e
                    ),
                ))
            })?;

            println!(
                "File-system mounted successfully. Press Ctrl+C or run 'fusermount3 -u {}' to unmount.",
                mountpoint.display()
            );

            let unmounter = std::sync::Arc::new(std::sync::Mutex::new(session.unmount_callable()));
            let mountpoint_clone = mountpoint.clone();
            let unmounter_clone = unmounter.clone();
            let signal_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let signal_count_clone = signal_count.clone();

            let _ = ctrlc::set_handler(move || {
                let count = signal_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count == 1 {
                    eprintln!(
                        "\nReceived shutdown signal (Ctrl+C). Gracefully unmounting {}...",
                        mountpoint_clone.display()
                    );
                    if let Ok(mut u) = unmounter_clone.lock() {
                        let _ = u.unmount();
                    }
                    let _ = std::process::Command::new("fusermount3")
                        .arg("-u")
                        .arg("-q")
                        .arg("-z")
                        .arg(&mountpoint_clone)
                        .status();
                } else {
                    eprintln!(
                        "\nForce exiting: detaching {}...",
                        mountpoint_clone.display()
                    );
                    let _ = std::process::Command::new("fusermount3")
                        .arg("-u")
                        .arg("-q")
                        .arg("-z")
                        .arg(&mountpoint_clone)
                        .status();
                    std::process::exit(0);
                }
            });

            if let Err(e) = session.run() {
                if e.kind() != std::io::ErrorKind::NotConnected
                    && e.raw_os_error() != Some(libc::ENODEV)
                {
                    return Err(SunsetError::Io(std::io::Error::new(
                        e.kind(),
                        format!("FUSE session error on '{}': {}", mountpoint.display(), e),
                    )));
                }
            }

            // Cleanup mount if needed
            if let Ok(mut u) = unmounter.lock() {
                let _ = u.unmount();
            }
            let _ = std::process::Command::new("fusermount3")
                .arg("-u")
                .arg("-q")
                .arg("-z")
                .arg(&mountpoint)
                .status();

            println!("Unmounted {} successfully.", mountpoint.display());
        }

        Commands::Check {
            archive,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let mut dev = BlockDevice::open(&archive, &k)?;
            let total = dev.total_blocks_on_disk()?;
            println!("Verifying {} blocks in archive...", total);

            for b in 0..total {
                dev.read_block(b)?;
            }

            println!(
                "Archive verified successfully: all {} blocks intact and authenticated.",
                total
            );
        }

        Commands::Ls {
            archive,
            path,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let mut engine = SunsetEngine::open(&archive, &k)?;
            let target_ino = resolve_path_to_ino(&mut engine, &path)?;
            let node = engine.get_inode(target_ino)?.clone();

            match node.kind {
                InodeKind::Directory => {
                    let dir_data = engine.read_dir_data(target_ino)?;
                    for entry in dir_data.entries {
                        let entry_node = engine.get_inode(entry.ino)?;
                        let mode_str = format_mode(entry_node.mode, entry.kind);
                        println!(
                            "{} {:>10} {}",
                            mode_str, entry_node.size, entry.name
                        );
                    }
                }
                InodeKind::File => {
                    let mode_str = format_mode(node.mode, InodeKind::File);
                    println!("{} {:>10} {}", mode_str, node.size, path);
                }
                InodeKind::Symlink => {
                    let mode_str = format_mode(node.mode, InodeKind::Symlink);
                    println!("{} {:>10} {}", mode_str, node.size, path);
                }
            }
        }

        Commands::Cat {
            archive,
            path,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let mut engine = SunsetEngine::open(&archive, &k)?;
            let file_ino = resolve_path_to_ino(&mut engine, &path)?;
            let node = engine.get_inode(file_ino)?.clone();
            if node.kind != InodeKind::File {
                return Err(SunsetError::IsADirectory(path));
            }

            let data = engine.read_bytes(file_ino, 0, node.size as usize)?;
            std::io::stdout().write_all(&data)?;
        }

        Commands::Put {
            archive,
            src,
            dst,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let local_data = std::fs::read(&src).map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read source file '{}': {}", src.display(), e),
                ))
            })?;

            let mut engine = SunsetEngine::open(&archive, &k)?;
            let (parent_ino, filename) = resolve_parent_and_name(&mut engine, &dst)?;

            let file_ino = match engine.lookup(parent_ino, &filename) {
                Ok(node) => {
                    if node.kind != InodeKind::File {
                        return Err(SunsetError::IsADirectory(dst));
                    }
                    engine.truncate(node.ino, 0)?;
                    node.ino
                }
                Err(SunsetError::NotFound(_)) => {
                    let node = engine.create_file(parent_ino, &filename, 0o644, 1000, 1000)?;
                    node.ino
                }
                Err(e) => return Err(e),
            };

            engine.write_bytes(file_ino, 0, &local_data)?;
            engine.flush()?;
            println!(
                "Stored {} bytes to '{}' in archive",
                local_data.len(),
                dst
            );
        }

        Commands::Get {
            archive,
            src,
            dst,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let mut engine = SunsetEngine::open(&archive, &k)?;
            let file_ino = resolve_path_to_ino(&mut engine, &src)?;
            let node = engine.get_inode(file_ino)?.clone();
            if node.kind != InodeKind::File {
                return Err(SunsetError::IsADirectory(src));
            }

            let data = engine.read_bytes(file_ino, 0, node.size as usize)?;
            std::fs::write(&dst, data).map_err(|e| {
                SunsetError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to write extracted file to '{}': {}",
                        dst.display(),
                        e
                    ),
                ))
            })?;
            println!("Extracted {} bytes to '{}'", node.size, dst.display());
        }

        Commands::Mkdir {
            archive,
            path,
            key,
            key_file,
            key_stdin,
        } => {
            ensure_archive_exists(&archive)?;
            let k = resolve_key(key, key_file, key_stdin, false)?;
            let mut engine = SunsetEngine::open(&archive, &k)?;
            let (parent_ino, dirname) = resolve_parent_and_name(&mut engine, &path)?;
            engine.mkdir(parent_ino, &dirname, 0o755, 1000, 1000)?;
            engine.flush()?;
            println!("Created directory '{}' in archive", path);
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    env_logger::init();
    if let Err(err) = run() {
        eprintln!("sunset: error: {}", err);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

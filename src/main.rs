// fuse-overlayfs: Overlay Filesystem in Userspace
//
// Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
// Copyright (C) 2018-2020 Red Hat Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod config;
mod copyup;
mod datasource;
mod direct;
mod error;
mod layer;
mod mapping;
mod node;
mod overlay;
mod sys;
mod whiteout;
mod xattr;

use log::info;
use std::os::fd::{AsRawFd, OwnedFd};

fn main() {
    // Support FUSE_OVERLAYFS_DEBUG_LOG=/path/to/file for logging in daemon mode
    if let Ok(log_path) = std::env::var("FUSE_OVERLAYFS_DEBUG_LOG") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("cannot open debug log file");
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Debug)
            .target(env_logger::Target::Pipe(Box::new(file)))
            .init();
    } else {
        env_logger::init();
    }

    let args: Vec<String> = std::env::args().collect();
    let config = match config::parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fuse-overlayfs: {}", e);
            std::process::exit(1);
        }
    };

    // Validate required options
    let lowerdir = match &config.lowerdir {
        Some(l) => l.clone(),
        None => {
            eprintln!("fuse-overlayfs: no lowerdir specified");
            std::process::exit(1);
        }
    };

    let mountpoint = match &config.mountpoint {
        Some(m) => m.clone(),
        None => {
            eprintln!("fuse-overlayfs: no mountpoint specified");
            std::process::exit(1);
        }
    };

    if config.redirect_dir.as_deref().is_some_and(|r| r != "off") {
        eprintln!("fuse-overlayfs: fuse-overlayfs only supports redirect_dir=off");
        std::process::exit(1);
    }

    // Raise RLIMIT_NOFILE
    set_limits();

    // Check if /proc is writable
    check_writeable_proc();

    // Initialize workdir
    let workdir_fd: Option<OwnedFd> = config.workdir.as_ref().map(|wd| {
        match sys::openat2::open_trusted(wd, libc::O_DIRECTORY, 0) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("fuse-overlayfs: cannot open workdir {}: {}", wd, e);
                std::process::exit(1);
            }
        }
    });
    let workdir_raw_fd = workdir_fd.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1);

    // Initialize layers
    let layers = match layer::init_layers(
        &lowerdir,
        config.upperdir.as_deref(),
        config.nfs_filehandles,
        config.xattr_permissions,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fuse-overlayfs: {}", e);
            std::process::exit(1);
        }
    };

    if config.debug {
        eprintln!("uid={}", config.uid_str.as_deref().unwrap_or("unchanged"));
        eprintln!("gid={}", config.gid_str.as_deref().unwrap_or("unchanged"));
        eprintln!(
            "upperdir={}",
            config.upperdir.as_deref().unwrap_or("NOT USED")
        );
        eprintln!(
            "workdir={}",
            config.workdir.as_deref().unwrap_or("NOT USED")
        );
        eprintln!("lowerdir={}", &lowerdir);
        eprintln!("mountpoint={}", &mountpoint);
        eprintln!("plugins={}", config.plugins.as_deref().unwrap_or("<none>"));
        eprintln!(
            "fsync={}",
            if config.fsync { "enabled" } else { "disabled" }
        );
    }

    // Build mount options and ACL for fuser from parsed config
    let mut fuse_options = vec![fuser::MountOption::FSName("fuse-overlayfs".to_string())];
    let mut acl = fuser::SessionACL::Owner;

    for opt in &config.fuse_options {
        match opt.as_str() {
            "default_permissions" => fuse_options.push(fuser::MountOption::DefaultPermissions),
            "allow_other" => acl = fuser::SessionACL::All,
            "allow_root" => acl = fuser::SessionACL::RootAndOwner,
            "ro" => fuse_options.push(fuser::MountOption::RO),
            "suid" => fuse_options.push(fuser::MountOption::Suid),
            "nosuid" => fuse_options.push(fuser::MountOption::NoSuid),
            "dev" => fuse_options.push(fuser::MountOption::Dev),
            "nodev" => fuse_options.push(fuser::MountOption::NoDev),
            "exec" => fuse_options.push(fuser::MountOption::Exec),
            "noexec" => fuse_options.push(fuser::MountOption::NoExec),
            "atime" => fuse_options.push(fuser::MountOption::Atime),
            "noatime" => fuse_options.push(fuser::MountOption::NoAtime),
            "diratime" => fuse_options.push(fuser::MountOption::CUSTOM("diratime".to_string())),
            "nodiratime" => fuse_options.push(fuser::MountOption::CUSTOM("nodiratime".to_string())),
            "debug" => fuse_options.push(fuser::MountOption::CUSTOM("debug".to_string())),
            other if other.starts_with("max_write=") => {
                fuse_options.push(fuser::MountOption::CUSTOM(other.to_string()));
            }
            other if other.starts_with("fsname=") => {
                // Already set FSName above, skip duplicate
            }
            other => {
                fuse_options.push(fuser::MountOption::CUSTOM(other.to_string()));
            }
        }
    }

    // SELinux context= is consumed by config parsing (not passed to FUSE),
    // matching the C code's fuse_opt_parse template behavior.

    let foreground = config.foreground;

    // Configure multithreading
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut fuse_config = fuser::Config::default();
    fuse_config.mount_options = fuse_options;
    fuse_config.acl = acl;
    fuse_config.n_threads = Some(n_threads);
    fuse_config.clone_fd = true;

    let notifier_lock = std::sync::Arc::new(std::sync::OnceLock::new());
    let fs = overlay::OverlayFs::new(config, layers, workdir_raw_fd, notifier_lock.clone());

    // Mount the filesystem (this creates the FUSE session and mounts)
    info!("mounting on {} with {} threads", &mountpoint, n_threads);
    let session = match fuser::Session::new(fs, std::path::Path::new(&mountpoint), &fuse_config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fuse-overlayfs: mount failed: {}", e);
            std::process::exit(1);
        }
    };

    // Make the notifier available to the filesystem for cache invalidation.
    let _ = notifier_lock.set(session.notifier());

    // Daemonize if not running in foreground (must happen before spawning threads)
    if !foreground {
        sys::process::daemonize();
    }

    // Register SIGUSR1 handler after daemonize (fork kills non-calling threads)
    setup_sigusr1();

    // Run the FUSE event loop (spawns worker threads internally)
    let bg = match session.spawn() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fuse-overlayfs: session error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = bg.join() {
        eprintln!("fuse-overlayfs: session error: {}", e);
        std::process::exit(1);
    }
}

fn set_limits() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let rlim = getrlimit(Resource::Nofile);
    if let Some(hard) = rlim.maximum {
        if let Err(e) = setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(hard),
                maximum: Some(hard),
            },
        ) {
            eprintln!("fuse-overlayfs: cannot set nofile rlimit: {}", e);
        }
    }
}

fn setup_sigusr1() {
    use signal_hook::consts::SIGUSR1;
    use signal_hook::iterator::Signals;
    use std::sync::atomic::Ordering;

    // Open a persistent log fd for SIGUSR1 output (survives daemonize).
    // Falls back to stderr (which may be /dev/null after daemonize).
    let log_fd = if let Ok(log_path) = std::env::var("FUSE_OVERLAYFS_DEBUG_LOG") {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(|f| {
                use std::os::fd::IntoRawFd;
                f.into_raw_fd()
            })
            .unwrap_or(libc::STDERR_FILENO)
    } else {
        libc::STDERR_FILENO
    };

    let mut signals = match Signals::new([SIGUSR1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fuse-overlayfs: cannot register SIGUSR1 handler: {}", e);
            return;
        }
    };

    std::thread::spawn(move || {
        for _ in signals.forever() {
            let inodes = node::STAT_INODES.load(Ordering::Relaxed);
            let nodes = node::STAT_NODES.load(Ordering::Relaxed);
            let passthrough = node::STAT_PASSTHROUGH.load(Ordering::Relaxed);
            let msg = format!(
                "# INODES: {}\n# NODES: {}\n# PASSTHROUGH: {}\n",
                inodes,
                nodes,
                if passthrough { "enabled" } else { "disabled" }
            );
            let _ = unsafe { libc::write(log_fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
        }
    });
}

fn check_writeable_proc() {
    let c_proc = std::ffi::CString::new("/proc").unwrap();
    let sfs = match sys::fs::statfs(&c_proc) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("fuse-overlayfs: error stating /proc");
            return;
        }
    };

    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    if sfs.f_type as i64 != PROC_SUPER_MAGIC {
        eprintln!(
            "fuse-overlayfs: invalid file system type found on /proc: {}, expected {}",
            sfs.f_type, PROC_SUPER_MAGIC
        );
        return;
    }

    if let Ok(stvfs) = sys::fs::statvfs(&c_proc)
        && (stvfs.f_flag & libc::ST_RDONLY) != 0
    {
        eprintln!(
            "fuse-overlayfs: /proc seems to be mounted as readonly, it can lead to unexpected failures"
        );
    }
}

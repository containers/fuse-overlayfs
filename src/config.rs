// SPDX-License-Identifier: GPL-2.0-or-later
//
// CLI option parsing. Replicates the exact -o key=value syntax from the C version.

use crate::mapping::{self, IdMapping};
use log::warn;

/// All configuration parsed from the command line.
#[derive(Debug)]
pub struct OverlayConfig {
    // Paths
    pub lowerdir: Option<String>,
    pub upperdir: Option<String>,
    pub workdir: Option<String>,
    pub mountpoint: Option<String>,
    pub redirect_dir: Option<String>,
    pub context: Option<String>,
    pub plugins: Option<String>,

    // Mapping strings (raw, parsed later)
    pub uid_str: Option<String>,
    pub gid_str: Option<String>,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,

    // Numeric options
    pub timeout: f64,
    pub xattr_permissions: i32,
    pub nfs_filehandles: i32,

    pub threaded: bool,
    pub fsync: bool,
    pub fast_ino_check: bool,
    pub writeback: bool,
    pub disable_xattrs: bool,

    pub squash_to_uid: Option<u32>,
    pub squash_to_gid: Option<u32>,

    // Boolean flags
    pub debug: bool,
    pub foreground: bool,
    pub squash_to_root: bool,
    pub ino_t_32: bool,
    pub static_nlink: bool,
    pub volatile_mode: bool,
    pub noacl: bool,

    // FUSE mount options to pass through
    pub fuse_options: Vec<String>,

    // Process info
    pub euid: u32,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        OverlayConfig {
            lowerdir: None,
            upperdir: None,
            workdir: None,
            mountpoint: None,
            redirect_dir: None,
            context: None,
            plugins: None,
            uid_str: None,
            gid_str: None,
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
            timeout: 1_000_000_000.0,
            xattr_permissions: 0,
            nfs_filehandles: 0,
            threaded: false,
            fsync: true,
            fast_ino_check: false,
            writeback: true,
            disable_xattrs: false,
            squash_to_uid: None,
            squash_to_gid: None,
            debug: false,
            foreground: false,
            squash_to_root: false,
            ino_t_32: false,
            static_nlink: false,
            volatile_mode: false,
            noacl: false,
            fuse_options: Vec::new(),
            euid: crate::sys::process::geteuid(),
        }
    }
}

/// FUSE mount options that are passed through to the kernel.
const FUSE_PASSTHROUGH_OPTS: &[&str] = &[
    "allow_root",
    "default_permissions",
    "allow_other",
    "auto_unmount",
    "suid",
    "nosuid",
    "dev",
    "nodev",
    "exec",
    "noexec",
    "atime",
    "noatime",
    "diratime",
    "nodiratime",
    "splice_write",
    "splice_read",
    "splice_move",
    "kernel_cache",
    "max_write",
    "ro",
    "rw",
];

/// Parse command-line arguments, replicating the C version's behavior exactly.
///
/// Syntax: fuse-overlayfs [-f] [-d] [-o OPT[,OPT2,...]] MOUNTPOINT
pub fn parse_args(args: &[String]) -> Result<OverlayConfig, String> {
    let mut config = OverlayConfig::default();

    // Inject defaults based on euid (same as get_new_args in C)
    if config.euid == 0 {
        for opt in ["default_permissions", "allow_other", "suid", "noatime"] {
            config.fuse_options.push(opt.to_string());
        }
    } else {
        for opt in ["default_permissions", "noatime"] {
            config.fuse_options.push(opt.to_string());
        }
    }

    let mut i = 1; // skip argv[0]
    while i < args.len() {
        let arg = &args[i];

        if arg == "-f" {
            config.foreground = true;
            config
                .fuse_options
                .push("fsname=fuse-overlayfs".to_string());
            i += 1;
            continue;
        }

        if arg == "-d" || arg == "--debug" {
            config.debug = true;
            config.foreground = true;
            config.fuse_options.push("debug".to_string());
            i += 1;
            continue;
        }

        if arg == "--help" || arg == "-h" {
            print_help(&args[0]);
            std::process::exit(0);
        }

        if arg == "--version" || arg == "-V" {
            print_version();
            std::process::exit(0);
        }

        if arg == "-o" {
            i += 1;
            if i >= args.len() {
                return Err("missing argument for -o".to_string());
            }
            parse_option_string(&args[i], &mut config)?;
            i += 1;
            continue;
        }

        if let Some(opts) = arg.strip_prefix("-o") {
            parse_option_string(opts, &mut config)?;
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            warn!("unknown argument ignored: {}", arg);
            i += 1;
            continue;
        }

        // Non-option argument = mountpoint
        config.mountpoint = Some(arg.clone());
        i += 1;
    }

    // Post-processing: parse mappings
    if let Some(ref uid_str) = config.uid_str {
        config.uid_mappings = mapping::parse_mappings(uid_str)?;
    }
    if let Some(ref gid_str) = config.gid_str {
        config.gid_mappings = mapping::parse_mappings(gid_str)?;
    }

    // volatile is alias for fsync=0
    if config.volatile_mode {
        config.fsync = false;
    }

    // Parse timeout from string if provided
    // (the C code stores it as a string via fuse_opt, then calls atof)

    Ok(config)
}

/// Parse a comma-separated option string (from -o opt1,opt2,key=val,...).
fn parse_option_string(opts: &str, config: &mut OverlayConfig) -> Result<(), String> {
    for opt in split_options(opts) {
        parse_single_option(&opt, config)?;
    }
    Ok(())
}

/// Split option string on commas, respecting backslash escaping and quoted strings.
fn split_options(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    let mut in_quotes = false;

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                current.push(c);
                current.push(next);
                chars.next();
            }
        } else if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c == ',' && !in_quotes {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Unescape backslash sequences in path values (e.g., \: → :).
fn unescape_path(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                result.push(next);
                chars.next();
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse a single key=value or key option.
fn parse_single_option(opt: &str, config: &mut OverlayConfig) -> Result<(), String> {
    // Handle key=value options
    if let Some((key, value)) = opt.split_once('=') {
        match key {
            "lowerdir" => config.lowerdir = Some(value.to_string()),
            "upperdir" => config.upperdir = Some(unescape_path(value)),
            "workdir" => config.workdir = Some(unescape_path(value)),
            "redirect_dir" => config.redirect_dir = Some(value.to_string()),
            "context" => config.context = Some(value.to_string()),
            "uidmapping" => config.uid_str = Some(value.to_string()),
            "gidmapping" => config.gid_str = Some(value.to_string()),
            "timeout" => {
                config.timeout = value
                    .parse::<f64>()
                    .map_err(|_| format!("invalid timeout value: {}", value))?;
            }
            "threaded" => {
                config.threaded = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid threaded value: {}", value))?
                    != 0;
            }
            "fsync" | "sync" => {
                config.fsync = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid fsync value: {}", value))?
                    != 0;
            }
            "fast_ino" | "fast_ino_check" => {
                config.fast_ino_check = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid fast_ino value: {}", value))?
                    != 0;
            }
            "writeback" => {
                config.writeback = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid writeback value: {}", value))?
                    != 0;
            }
            "noxattrs" => {
                config.disable_xattrs = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid noxattrs value: {}", value))?
                    != 0;
            }
            "plugins" => config.plugins = Some(value.to_string()),
            "xattr_permissions" => {
                config.xattr_permissions = value
                    .parse::<i32>()
                    .map_err(|_| format!("invalid xattr_permissions value: {}", value))?;
            }
            "squash_to_uid" => {
                config.squash_to_uid = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid squash_to_uid value: {}", value))?,
                );
            }
            "squash_to_gid" => {
                config.squash_to_gid = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid squash_to_gid value: {}", value))?,
                );
            }
            "xino" => match value {
                "off" => config.nfs_filehandles = 0,
                "auto" => config.nfs_filehandles = 1,
                "on" => config.nfs_filehandles = 2,
                _ => {
                    return Err(format!("invalid xino value: {}", value));
                }
            },
            _ => {
                // Check if it's a FUSE passthrough option with a value
                if FUSE_PASSTHROUGH_OPTS.contains(&key) {
                    config.fuse_options.push(opt.to_string());
                } else {
                    warn!("unknown argument ignored: {}", opt);
                }
            }
        }
        return Ok(());
    }

    // Handle flag options (no value)
    match opt {
        "debug" => {
            config.debug = true;
            config.foreground = true;
            config.fuse_options.push("debug".to_string());
        }
        "squash_to_root" => config.squash_to_root = true,
        "ino32_t" => config.ino_t_32 = true,
        "static_nlink" => config.static_nlink = true,
        "volatile" => config.volatile_mode = true,
        "noacl" => config.noacl = true,
        _ => {
            if FUSE_PASSTHROUGH_OPTS.contains(&opt) {
                config.fuse_options.push(opt.to_string());
            } else {
                warn!("unknown argument ignored: {}", opt);
            }
        }
    }

    Ok(())
}

/// Split lowerdir string on colons, handling backslash-escaped colons (\:)
/// and plugin syntax (//plugin_name/data/path).
pub fn parse_lowerdir(lowerdir: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut chars = lowerdir.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == ':' {
                    // Escaped colon -> literal colon in path
                    current.push(':');
                    chars.next();
                } else {
                    current.push(c);
                }
            } else {
                current.push(c);
            }
        } else if c == ':' {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Check if a lowerdir path uses the plugin syntax: //plugin_name/data/path
pub fn parse_plugin_path(path: &str) -> Option<(&str, &str)> {
    if !path.starts_with("//") {
        return None;
    }
    let rest = &path[2..];
    // Find the next // which separates plugin opaque data from path
    if let Some(pos) = rest.find("//") {
        let plugin_opaque = &rest[..pos];
        let data_path = &rest[pos + 2..];
        Some((plugin_opaque, data_path))
    } else {
        // Only plugin opaque, no separate path
        Some((rest, ""))
    }
}

fn print_help(program: &str) {
    println!("usage: {} [options] <mountpoint>", program);
    println!();
    println!("Options:");
    println!("    -o lowerdir=DIR[:DIR...]   lower directories (required)");
    println!("    -o upperdir=DIR            upper directory");
    println!("    -o workdir=DIR             work directory");
    println!("    -o uidmapping=A:B:C[:...]  UID mapping");
    println!("    -o gidmapping=A:B:C[:...]  GID mapping");
    println!("    -o timeout=SECS            entry/attr timeout (default: 1000000000)");
    println!("    -o squash_to_root          squash all UIDs/GIDs to root");
    println!("    -o squash_to_uid=UID       squash all UIDs to UID");
    println!("    -o squash_to_gid=GID       squash all GIDs to GID");
    println!("    -o xattr_permissions=MODE  xattr permission mode (0, 1, 2)");
    println!("    -o static_nlink            use static nlink=1");
    println!("    -o noacl                   disable ACL support");
    println!(
        "    -o auto_unmount            unmount when the process exits (requires allow_other or allow_root)"
    );
    println!("    -o xino=off|auto|on        NFS file handles mode");
    println!("    -o volatile                disable fsync");
    println!("    -o plugins=PATH            plugin shared objects");
    println!("    -f                         foreground mode");
    println!("    -d, --debug                debug mode");
    println!("    -h, --help                 show this help");
    println!("    -V, --version              show version");
}

fn print_version() {
    println!("fuse-overlayfs: version {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lowerdir_simple() {
        let dirs = parse_lowerdir("/a:/b:/c");
        assert_eq!(dirs, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn test_parse_lowerdir_escaped_colon() {
        let dirs = parse_lowerdir("/a\\:b:/c");
        assert_eq!(dirs, vec!["/a:b", "/c"]);
    }

    #[test]
    fn test_parse_lowerdir_plugin() {
        let dirs = parse_lowerdir("//test//ext2:/lower");
        assert_eq!(dirs, vec!["//test//ext2", "/lower"]);
    }

    #[test]
    fn test_parse_plugin_path() {
        assert_eq!(parse_plugin_path("//test//ext2"), Some(("test", "ext2")));
        assert_eq!(parse_plugin_path("/normal/path"), None);
    }

    #[test]
    fn test_split_options() {
        let opts = split_options("lowerdir=/a:/b,upperdir=/c,debug");
        assert_eq!(opts, vec!["lowerdir=/a:/b", "upperdir=/c", "debug"]);
    }

    #[test]
    fn test_parse_args_basic() {
        let args: Vec<String> = vec![
            "fuse-overlayfs".into(),
            "-o".into(),
            "lowerdir=/lower,upperdir=/upper,workdir=/work".into(),
            "/mnt".into(),
        ];
        let config = parse_args(&args).unwrap();
        assert_eq!(config.lowerdir.as_deref(), Some("/lower"));
        assert_eq!(config.upperdir.as_deref(), Some("/upper"));
        assert_eq!(config.workdir.as_deref(), Some("/work"));
        assert_eq!(config.mountpoint.as_deref(), Some("/mnt"));
    }

    #[test]
    fn test_parse_args_auto_unmount() {
        let args: Vec<String> = vec![
            "fuse-overlayfs".into(),
            "-o".into(),
            "auto_unmount,lowerdir=/a".into(),
            "/mnt".into(),
        ];
        let config = parse_args(&args).unwrap();
        assert!(config.fuse_options.iter().any(|opt| opt == "auto_unmount"));
    }

    #[test]
    fn test_parse_args_xino() {
        let args: Vec<String> = vec![
            "fuse-overlayfs".into(),
            "-o".into(),
            "xino=auto,lowerdir=/a".into(),
            "/mnt".into(),
        ];
        let config = parse_args(&args).unwrap();
        assert_eq!(config.nfs_filehandles, 1);
    }

    #[test]
    fn test_parse_args_volatile() {
        let args: Vec<String> = vec![
            "fuse-overlayfs".into(),
            "-o".into(),
            "volatile,lowerdir=/a".into(),
            "/mnt".into(),
        ];
        let config = parse_args(&args).unwrap();
        assert!(config.volatile_mode);
        assert!(!config.fsync);
    }

    #[test]
    fn test_parse_args_multiple_o() {
        let args: Vec<String> = vec![
            "fuse-overlayfs".into(),
            "-o".into(),
            "lowerdir=/lower".into(),
            "-o".into(),
            "upperdir=/upper".into(),
            "/mnt".into(),
        ];
        let config = parse_args(&args).unwrap();
        assert_eq!(config.lowerdir.as_deref(), Some("/lower"));
        assert_eq!(config.upperdir.as_deref(), Some("/upper"));
    }
}

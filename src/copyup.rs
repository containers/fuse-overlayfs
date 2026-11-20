// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copy-up logic: copies files from lower layers to the upper layer
// so that modifications can be applied.

use crate::error::{FsError, FsResult};
use crate::layer::OvlLayer;
use crate::node::{NodeArena, NodeId};
use crate::sys::openat2;
use crate::sys::xattr as sxattr;
use crate::xattr as xattr_consts;
use std::ffi::CString;
use std::os::fd::RawFd;

/// Build a [atime, mtime] timespec pair from a stat result.
fn stat_times(st: &libc::stat) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: st.st_atime,
            tv_nsec: st.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: st.st_mtime,
            tv_nsec: st.st_mtime_nsec,
        },
    ]
}

/// Allocate a unique workdir temporary name and advance the counter.
fn next_wd_name(wd_counter: &mut u64) -> (String, CString) {
    let name = wd_counter.to_string();
    *wd_counter += 1;
    let c_name = CString::new(name.as_str()).unwrap();
    (name, c_name)
}

/// Copy xattrs from source fd to destination fd.
fn copy_xattr(sfd: RawFd, dfd: RawFd) -> FsResult<()> {
    let mut list_buf = vec![0u8; 64 * 1024];
    let list_len = match sxattr::flistxattr(sfd, &mut list_buf) {
        Ok(n) => n,
        Err(e) if e.0 == libc::ENOTSUP || e.0 == libc::ENODATA => return Ok(()),
        Err(e) => return Err(e),
    };

    // xattr names are null-separated bytes; split on \0 and skip non-UTF8 names
    let names: Vec<&str> = list_buf[..list_len]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok())
        .collect();

    let mut value_buf = vec![0u8; 64 * 1024];
    for name in names {
        // Skip internal overlay xattrs
        if name.starts_with(xattr_consts::PRIVILEGED_XATTR_PREFIX)
            || name.starts_with(xattr_consts::UNPRIVILEGED_XATTR_PREFIX)
            || name.starts_with(xattr_consts::XATTR_PREFIX)
        {
            continue;
        }

        let vlen = match sxattr::fgetxattr(sfd, name, &mut value_buf) {
            Ok(n) => n,
            Err(e) if e.0 == libc::ENODATA => continue,
            Err(e) => return Err(e),
        };

        match sxattr::fsetxattr(dfd, name, &value_buf[..vlen], 0) {
            Ok(()) => {}
            Err(e) if e.0 == libc::EPERM || e.0 == libc::ENOTSUP => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Copy data from source fd to destination fd using FICLONE → sendfile → read/write fallback.
fn copy_data(sfd: RawFd, dfd: RawFd, size: i64) -> FsResult<()> {
    use crate::sys::io;

    // Try FICLONE first
    if io::ficlone(dfd, sfd).is_ok() {
        return Ok(());
    }

    // Try sendfile
    let mut copied: i64 = 0;
    while copied < size {
        let tocopy = std::cmp::min((size - copied) as usize, usize::MAX);
        match io::sendfile(dfd, sfd, std::ptr::null_mut(), tocopy) {
            Err(e) if e.0 == libc::EINTR => continue,
            Err(_) => break,        // fall through to read/write
            Ok(0) => return Ok(()), // EOF
            Ok(n) => copied += n as i64,
        }
    }

    if copied >= size {
        return Ok(());
    }

    // Read/write fallback
    let buf_size = 1 << 20; // 1 MB
    let mut buf = vec![0u8; buf_size];
    loop {
        let nread = io::read(sfd, &mut buf)?;
        if nread == 0 {
            break;
        }
        let mut written = 0;
        while written < nread {
            let n = io::write(dfd, &buf[written..nread])?;
            written += n;
        }
    }

    Ok(())
}

/// Create parent directories on the upper layer for a node that needs copy-up.
/// Recursively walks up the parent chain.
pub fn create_node_directory(
    layers: &[OvlLayer],
    nodes: &mut NodeArena,
    node_id: NodeId,
    workdir_fd: RawFd,
    wd_counter: &mut u64,
) -> FsResult<()> {
    use crate::sys::fs;

    let node = nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
    let upper_ref = layers.first().ok_or(FsError(libc::EROFS))?;
    if node.layer_idx == 0 && !upper_ref.low {
        return Ok(());
    }

    // Recursively ensure parent is on upper first
    if let Some(parent_id) = node.parent {
        let parent_layer = nodes.get(&parent_id).map(|p| p.layer_idx).unwrap_or(0);
        if parent_layer != 0 || upper_ref.low {
            create_node_directory(layers, nodes, parent_id, workdir_fd, wd_counter)?;
        }
    }

    // Re-borrow after recursive call (arena may have been modified)
    let path = crate::node::compute_path(nodes, node_id);
    let node = nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
    let layer_idx = node.layer_idx;
    let parent_id = node.parent;
    let node_name = node.name.clone();

    let layer = layers.get(layer_idx).ok_or(FsError(libc::ENOENT))?;
    let upper = layers.first().ok_or(FsError(libc::EROFS))?;
    let upper_fd = upper.ds.root_fd();

    // Open and stat source directory
    let sfd = layer
        .ds
        .openat(&path, libc::O_RDONLY | libc::O_NONBLOCK, 0o755)?;
    let st = fs::fstat(sfd.as_raw_fd())?;
    let times = stat_times(&st);

    // Create temp dir in workdir
    let (wd_name, c_wd_name) = next_wd_name(wd_counter);

    let stat_override_mode = upper.stat_override_mode();
    let backing_mode = if stat_override_mode != crate::datasource::StatOverrideMode::None {
        st.st_mode | 0o755
    } else {
        st.st_mode
    };
    fs::mkdirat(workdir_fd, &c_wd_name, backing_mode)?;

    // Open the new dir to set ownership/xattrs/timestamps
    let dfd = openat2::safe_openat(workdir_fd, wd_name.as_bytes(), libc::O_RDONLY, 0)?;

    if stat_override_mode != crate::datasource::StatOverrideMode::None {
        let xattr_name = match stat_override_mode {
            crate::datasource::StatOverrideMode::User
            | crate::datasource::StatOverrideMode::Containers => {
                crate::datasource::XATTR_OVERRIDE_CONTAINERS_STAT
            }
            crate::datasource::StatOverrideMode::Privileged => {
                crate::datasource::XATTR_PRIVILEGED_OVERRIDE_STAT
            }
            crate::datasource::StatOverrideMode::None => unreachable!(),
        };
        let override_val = format!("{}:{}:{:o}", st.st_uid, st.st_gid, st.st_mode & 0o7777);
        let _ = sxattr::fsetxattr(dfd.as_raw_fd(), xattr_name, override_val.as_bytes(), 0);
    } else {
        let _ = fs::fchown(dfd.as_raw_fd(), st.st_uid, st.st_gid);
    }
    let _ = fs::futimens(dfd.as_raw_fd(), &times);

    // Copy xattrs from source to new dir
    let _ = copy_xattr(sfd.as_raw_fd(), dfd.as_raw_fd());

    // Safely resolve destination parent for rename
    let (_dst_guard, dst_dirfd, c_dst_name) = openat2::open_parent_safe_cstr(upper_fd, &path)?;
    match fs::renameat(workdir_fd, &c_wd_name, dst_dirfd, &c_dst_name) {
        Ok(()) => {}
        Err(FsError(err)) if err == libc::EEXIST || err == libc::ENOTEMPTY => {
            // Directory already exists, use RENAME_EXCHANGE
            const RENAME_EXCHANGE: u32 = 2;
            match fs::renameat2(
                workdir_fd,
                &c_wd_name,
                dst_dirfd,
                &c_dst_name,
                RENAME_EXCHANGE,
            ) {
                Ok(()) => {
                    let _ = fs::unlinkat(workdir_fd, &c_wd_name, libc::AT_REMOVEDIR);
                }
                Err(e) => {
                    let _ = fs::unlinkat(workdir_fd, &c_wd_name, libc::AT_REMOVEDIR);
                    return Err(e);
                }
            }
        }
        Err(FsError(libc::ENOTDIR)) => {
            // Non-dir in the way, remove it and retry
            let _ = fs::unlinkat(dst_dirfd, &c_dst_name, 0);
            match fs::renameat(workdir_fd, &c_wd_name, dst_dirfd, &c_dst_name) {
                Ok(()) => {}
                Err(e) => {
                    let _ = fs::unlinkat(workdir_fd, &c_wd_name, libc::AT_REMOVEDIR);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            let _ = fs::unlinkat(workdir_fd, &c_wd_name, libc::AT_REMOVEDIR);
            return Err(e);
        }
    }

    // Mark node as on upper layer
    if let Some(node) = nodes.get_mut(&node_id) {
        node.layer_idx = 0;
    }

    // Delete whiteout for this directory if one exists
    if let Some(pid) = parent_id {
        let parent_path = crate::node::compute_path(nodes, pid);
        let _ = crate::whiteout::delete_whiteout(upper_fd, None, &parent_path, &node_name);
    }

    Ok(())
}

/// Copy a file from a lower layer to the upper layer.
/// After this call, node's layer_idx will be 0 (upper).
///
/// With `sync`, a regular file's data is flushed with fsync(2) before it is renamed
/// into place, like kernel overlayfs's default `fsync=auto`: otherwise a crash can
/// leave an empty or partial upper file that hides the intact lower one.
pub fn copyup(
    layers: &[OvlLayer],
    nodes: &mut NodeArena,
    node_id: NodeId,
    workdir_fd: RawFd,
    wd_counter: &mut u64,
    sync: bool,
) -> FsResult<()> {
    let upper = layers.first().ok_or(FsError(libc::EROFS))?;
    if upper.low {
        return Err(FsError(libc::EROFS));
    }

    let upper_fd = upper.ds.root_fd();

    let path = crate::node::compute_path(nodes, node_id);
    let node = nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
    let layer_idx = node.layer_idx;
    let parent_id = node.parent;

    let src_layer = layers.get(layer_idx).ok_or(FsError(libc::ENOENT))?;

    // Stat the source
    let st = src_layer
        .ds
        .statat(&path, libc::AT_SYMLINK_NOFOLLOW, libc::STATX_BASIC_STATS)?;

    // Ensure parent directory exists on upper
    if let Some(pid) = parent_id {
        create_node_directory(layers, nodes, pid, workdir_fd, wd_counter)?;
    }

    let mode = st.st_mode;
    let file_type = mode & libc::S_IFMT;

    // Directory copy-up
    if file_type == libc::S_IFDIR {
        create_node_directory(layers, nodes, node_id, workdir_fd, wd_counter)?;
        return Ok(());
    }

    // Symlink copy-up: create in workdir, then rename to upper
    if file_type == libc::S_IFLNK {
        let target = src_layer.ds.readlinkat(&path)?;
        let c_target = crate::error::cstr_bytes(&target)?;
        let (_wd_name, c_wd_name) = next_wd_name(wd_counter);

        crate::sys::fs::symlinkat(&c_target, workdir_fd, &c_wd_name)?;
        let _ = crate::sys::fs::fchownat(
            workdir_fd,
            &c_wd_name,
            st.st_uid,
            st.st_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        let (_dst_guard, dst_dirfd, c_dst_name) = openat2::open_parent_safe_cstr(upper_fd, &path)?;
        if let Err(e) = crate::sys::fs::renameat(workdir_fd, &c_wd_name, dst_dirfd, &c_dst_name) {
            let _ = crate::sys::fs::unlinkat(workdir_fd, &c_wd_name, 0);
            return Err(e);
        }
        if let Some(node) = nodes.get_mut(&node_id) {
            node.layer_idx = 0;
        }
        return Ok(());
    }

    // Special file copy-up (devices, FIFOs, sockets): create in workdir, then rename to upper
    if matches!(
        file_type,
        libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK
    ) {
        let (wd_name, c_wd_name) = next_wd_name(wd_counter);

        crate::sys::fs::mknodat(workdir_fd, &c_wd_name, mode, st.st_rdev)?;
        let _ = crate::sys::fs::fchownat(
            workdir_fd,
            &c_wd_name,
            st.st_uid,
            st.st_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        // Copy xattrs to the workdir node before rename
        if let Ok(wd_fd) = openat2::safe_openat(
            workdir_fd,
            wd_name.as_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        ) {
            let sfd = src_layer.ds.openat(
                &path,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0,
            );
            if let Ok(sfd) = sfd {
                let _ = copy_xattr(sfd.as_raw_fd(), wd_fd.as_raw_fd());
            }
        }

        let (_dst_guard, dst_dirfd, c_dst_name) = openat2::open_parent_safe_cstr(upper_fd, &path)?;
        if let Err(e) = crate::sys::fs::renameat(workdir_fd, &c_wd_name, dst_dirfd, &c_dst_name) {
            let _ = crate::sys::fs::unlinkat(workdir_fd, &c_wd_name, 0);
            return Err(e);
        }
        if let Some(node) = nodes.get_mut(&node_id) {
            node.layer_idx = 0;
        }
        return Ok(());
    }

    // Regular file copy-up
    let (wd_name, c_wd_name) = next_wd_name(wd_counter);

    // Open source
    let sfd = src_layer
        .ds
        .openat(&path, libc::O_RDONLY | libc::O_NOFOLLOW, 0)?;

    // Create temp file in workdir
    let dfd = openat2::safe_openat(
        workdir_fd,
        wd_name.as_bytes(),
        libc::O_CREAT | libc::O_WRONLY,
        mode | 0o200,
    )?;

    // Set ownership
    let _ = crate::sys::fs::fchown(dfd.as_raw_fd(), st.st_uid, st.st_gid);

    // Copy data
    #[allow(clippy::unnecessary_cast)]
    let size = st.st_size as i64;
    copy_data(sfd.as_raw_fd(), dfd.as_raw_fd(), size)?;

    // Set timestamps
    let _ = crate::sys::fs::futimens(dfd.as_raw_fd(), &stat_times(&st));

    // Copy xattrs
    let _ = copy_xattr(sfd.as_raw_fd(), dfd.as_raw_fd());

    // Restore original mode (file was created with mode | 0o200 for writing)
    let _ = crate::sys::fs::fchmod(dfd.as_raw_fd(), mode);

    // Make the copy durable before it becomes visible (see `sync` above)
    if sync {
        if let Err(e) = crate::sys::io::fsync(dfd.as_raw_fd()) {
            let _ = crate::sys::fs::unlinkat(workdir_fd, &c_wd_name, 0);
            return Err(e);
        }
    }

    // Move to final location, safely resolve destination parent
    let (_dst_guard, dst_dirfd, c_dst_name) = openat2::open_parent_safe_cstr(upper_fd, &path)?;
    match crate::sys::fs::renameat(workdir_fd, &c_wd_name, dst_dirfd, &c_dst_name) {
        Ok(()) => {}
        Err(e) => {
            let _ = crate::sys::fs::unlinkat(workdir_fd, &c_wd_name, 0);
            return Err(e);
        }
    }

    // Delete any whiteout for this file
    let basename = path.rsplit(|&b| b == b'/').next().unwrap_or(&path);
    let mut wh_bytes = b".wh.".to_vec();
    wh_bytes.extend_from_slice(basename);
    if let Ok(wh_name) = CString::new(wh_bytes) {
        let _ = crate::sys::fs::unlinkat(dst_dirfd, &wh_name, 0);
    }

    if let Some(node) = nodes.get_mut(&node_id) {
        node.layer_idx = 0;
    }
    Ok(())
}

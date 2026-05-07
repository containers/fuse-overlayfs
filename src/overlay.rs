// SPDX-License-Identifier: GPL-2.0-or-later
//
// Core overlay filesystem implementation.
// Implements the fuser::Filesystem trait with all FUSE lowlevel operations.
//
// All node references use NodeId (arena-based), no raw pointers.
// All unsafe code lives in src/sys/.

// libc stat field types (st_ino, st_dev, st_mode) vary across architectures
// (u32 on 32-bit, u64 on 64-bit), so casts are needed for portability.
#![allow(clippy::unnecessary_cast)]

use crate::config::OverlayConfig;
use crate::datasource::{self, StatOverrideMode};
use crate::error::{FsError, FsResult};
use crate::layer::OvlLayer;
use crate::mapping::{self, OverflowIds};
use crate::node::{self, InodeKey, InodeTable, NodeArena, NodeId, OvlNode};
use crate::sys::{statx as sstatx, xattr as sxattr};
use crate::whiteout;
use crate::xattr;
use fuser::{
    BackingId, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    InitFlags, KernelConfig, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLseek, ReplyOpen, ReplyStatfs,
    ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use log::{debug, info, warn};

/// Convert a string to CString, returning EINVAL on failure (interior null byte).
/// Use in FUSE handlers where panicking is not acceptable.
macro_rules! cstring {
    ($s:expr, $reply:expr) => {
        match crate::error::cstr($s) {
            Ok(c) => c,
            Err(_) => {
                $reply.error(Errno::EINVAL);
                return;
            }
        }
    };
    ($s:expr) => {
        crate::error::cstr($s)?
    };
}
use crate::sys::openat2::open_parent_safe_cstr as safe_parent;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Remove all entries from a directory on the upper layer (used before rename
/// to clear out whiteout files so renameat() doesn't fail with ENOTEMPTY).
fn empty_upper_dir(upper: &OvlLayer, path: &[u8]) -> FsResult<()> {
    use crate::sys::dir::DirStream;
    let fd = upper
        .ds
        .openat(path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let dir_raw = fd.as_raw_fd();
    let mut stream = DirStream::from_raw_fd(dir_raw)?;
    while let Some(entry) = stream.next_entry() {
        if entry.name == b"." || entry.name == b".." {
            continue;
        }
        if let Ok(c_name) = crate::error::cstr_bytes(&entry.name) {
            if entry.dtype == libc::DT_DIR {
                let _ = crate::sys::fs::unlinkat(dir_raw, &c_name, libc::AT_REMOVEDIR);
            } else {
                let _ = crate::sys::fs::unlinkat(dir_raw, &c_name, 0);
            }
        }
    }
    Ok(())
}

/// The main overlay filesystem state.
pub struct OverlayFs {
    config: OverlayConfig,
    inner: RwLock<OverlayInner>,
    /// Open file handles, separated from inner for concurrent I/O.
    open_files: RwLock<FxHashMap<u64, Arc<OwnedFd>>>,
    next_fh: AtomicU64,
    /// Open directory handles, separated from inner for concurrent readdir.
    open_dirs: RwLock<FxHashMap<u64, Arc<DirHandle>>>,
    next_dh: AtomicU64,
    /// Passthrough backing IDs keyed by FUSE inode, reused across concurrent opens.
    /// The usize tracks how many open file handles reference this backing.
    inode_backings: RwLock<FxHashMap<u64, (Arc<BackingId>, usize)>>,
    /// Map from file handle to FUSE inode for backing cleanup on release.
    fh_to_ino: RwLock<FxHashMap<u64, u64>>,
    /// Whether kernel negotiated passthrough support.
    passthrough_enabled: AtomicBool,
    /// Notifier for sending cache invalidation requests to the kernel.
    /// Set after Session creation via OnceLock.
    notifier: Arc<OnceLock<fuser::Notifier>>,
}

/// Custom ioctl command: clear and re-scan a directory's cached children.
/// Encoded as _IO('f', 0x66) — direction=none, size=0, type='f'(0x66), nr=0x66.
/// Immediately rebuilds the directory listing, picking up externally created
/// whiteout files and other changes.
const FUSE_OVFS_IOC_REFRESH_DIR: libc::Ioctl = (b'f' as libc::Ioctl) << 8 | 0x66;

struct OverlayInner {
    layers: Vec<OvlLayer>,
    inodes: InodeTable,
    nodes: NodeArena,
    root_id: NodeId,
    workdir_fd: RawFd,
    ino_passthrough: bool,
    overflow: OverflowIds,
    wd_counter: u64,
    can_mknod: bool,
}

struct DirHandle {
    entries: Vec<DirEntry>,
}

struct DirEntry {
    name: Vec<u8>,
    ino: u64,
    mode: u32,
    attr: Option<FileAttr>,
    node_id: Option<NodeId>,
}

impl OverlayFs {
    pub fn new(
        config: OverlayConfig,
        layers: Vec<OvlLayer>,
        workdir_fd: RawFd,
        notifier: Arc<OnceLock<fuser::Notifier>>,
    ) -> Self {
        let ino_passthrough = crate::layer::all_same_device(&layers);
        let overflow = OverflowIds::read();

        let mut nodes = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 0, 0, true);
        let root_id = nodes.insert(root);

        let mut inodes = InodeTable::new();
        inodes.set_same_device(ino_passthrough);

        OverlayFs {
            config,
            inner: RwLock::new(OverlayInner {
                layers,
                inodes,
                nodes,
                root_id,
                workdir_fd,
                ino_passthrough,
                overflow,
                wd_counter: 1,
                can_mknod: std::env::var("FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT").is_err(),
            }),
            open_files: RwLock::new(FxHashMap::default()),
            next_fh: AtomicU64::new(1),
            open_dirs: RwLock::new(FxHashMap::default()),
            next_dh: AtomicU64::new(1),
            inode_backings: RwLock::new(FxHashMap::default()),
            fh_to_ino: RwLock::new(FxHashMap::default()),
            passthrough_enabled: AtomicBool::new(false),
            notifier,
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs_f64(self.config.timeout)
    }

    /// Allocate a file handle and store the fd.
    fn alloc_fh(&self, fd: OwnedFd) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.open_files.write().insert(fh, Arc::new(fd));
        fh
    }

    /// Allocate a directory handle and store it.
    fn alloc_dh(&self, handle: DirHandle) -> u64 {
        let dh = self.next_dh.fetch_add(1, Ordering::Relaxed);
        self.open_dirs.write().insert(dh, Arc::new(handle));
        dh
    }

    /// Get a clone of an open file's Arc<OwnedFd>.
    fn get_file(&self, fh: u64) -> Option<Arc<OwnedFd>> {
        self.open_files.read().get(&fh).cloned()
    }

    /// Try to open a file with FUSE passthrough; fall back to normal open.
    /// Reuses BackingId for the same FUSE inode (kernel requires same backing
    /// for concurrent opens of the same inode).
    fn reply_open_maybe_passthrough(&self, ino: u64, fd: OwnedFd, reply: ReplyOpen) {
        let mut fuse_flags = FopenFlags::empty();
        if self.config.timeout > 0.0 {
            fuse_flags |= FopenFlags::FOPEN_KEEP_CACHE;
        }

        if self.passthrough_enabled.load(Ordering::Relaxed) {
            // Check if we already have a BackingId for this inode (concurrent open).
            // Use a single write lock to avoid TOCTOU race with concurrent release().
            {
                let mut backings = self.inode_backings.write();
                if let Some((backing_id, count)) = backings.get_mut(&ino) {
                    let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                    let backing_id = Arc::clone(backing_id);
                    *count += 1;
                    drop(backings);
                    self.open_files.write().insert(fh, Arc::new(fd));
                    self.fh_to_ino.write().insert(fh, ino);
                    debug!("open: reusing passthrough for fh={}, ino={}", fh, ino);
                    // FOPEN_KEEP_CACHE is incompatible with passthrough
                    reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &backing_id);
                    return;
                }
            }

            // Create a new BackingId for this inode.
            match reply.open_backing(&fd) {
                Ok(backing_id) => {
                    let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                    let backing_id = Arc::new(backing_id);

                    // Re-check under lock: another thread may have inserted a
                    // backing for this inode between our check above and now.
                    let mut backings = self.inode_backings.write();
                    if let Some((existing_id, count)) = backings.get_mut(&ino) {
                        // Another thread won the race — reuse its backing and
                        // discard the one we just created (it drops on scope exit).
                        let existing_id = Arc::clone(existing_id);
                        *count += 1;
                        drop(backings);
                        self.open_files.write().insert(fh, Arc::new(fd));
                        self.fh_to_ino.write().insert(fh, ino);
                        debug!(
                            "open: race resolved, reusing passthrough for fh={}, ino={}",
                            fh, ino
                        );
                        reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &existing_id);
                    } else {
                        backings.insert(ino, (Arc::clone(&backing_id), 1));
                        drop(backings);
                        self.open_files.write().insert(fh, Arc::new(fd));
                        self.fh_to_ino.write().insert(fh, ino);
                        debug!("open: using passthrough for fh={}, ino={}", fh, ino);
                        reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &backing_id);
                    }
                    return;
                }
                Err(e) => {
                    // Passthrough not supported at runtime, disable for future opens
                    info!("passthrough disabled at runtime: {}", e);
                    self.passthrough_enabled.store(false, Ordering::Relaxed);
                    node::STAT_PASSTHROUGH.store(false, Ordering::Relaxed);
                }
            }
        }

        let fh = self.alloc_fh(fd);
        reply.opened(FileHandle(fh), fuse_flags);
    }

    /// Common implementation for unlink and rmdir.
    fn do_rm(&self, parent: u64, name: &[u8], is_dir: bool, reply: ReplyEmpty) {
        let mut inner = self.inner.write();

        let node_id = match inner.do_lookup_file(parent, Some(name), &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if inner.is_whiteout_or_missing(&node_id) {
            reply.error(Errno::ENOENT);
            return;
        }

        if is_dir {
            inner.reload_dir(node_id, &self.config);
            let empty = inner
                .nodes
                .get(&node_id)
                .and_then(|n| n.children())
                .map(|ch| {
                    ch.values()
                        .all(|cid| inner.nodes.get(cid).map(|c| c.hidden).unwrap_or(true))
                })
                .unwrap_or(true);
            if !empty {
                reply.error(Errno::ENOTEMPTY);
                return;
            }
        }

        if let Err(e) = inner.get_node_up(node_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let pnode_id = match inner.do_lookup_file(parent, None, &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if let Err(e) = inner.get_node_up(pnode_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        if let Err(e) = inner.hide_node(node_id, true) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        // Remove from parent's children, clean up inode table, and drop from arena.
        // If other hardlink names still reference the same inode, remember the
        // FUSE inode number so we can invalidate it after replying.
        let mut inval_fuse_ino: Option<u64> = None;
        if let Some(removed_id) = inner
            .nodes
            .get_mut(&pnode_id)
            .and_then(|p| p.remove_child(name))
        {
            if let Some(node) = inner.nodes.get(&removed_id) {
                let key = InodeKey {
                    ino: node.tmp_ino,
                    dev: node.tmp_dev,
                };
                // Check if surviving hardlinks exist before removing this node.
                if let Some(fuse_ino) = inner.inodes.key_to_fuse_ino(&key) {
                    let surviving = inner
                        .inodes
                        .get_by_key(&key)
                        .map(|oi| {
                            oi.nodes
                                .iter()
                                .any(|id| *id != removed_id && inner.nodes.contains_key(id))
                        })
                        .unwrap_or(false);
                    if surviving {
                        inval_fuse_ino = Some(fuse_ino);
                    }
                }
                inner.inodes.remove_node_id(&key, removed_id);
            }
            inner.nodes.remove(&removed_id);
        }

        // Drop the write lock before sending the notification.
        drop(inner);

        reply.ok();

        // Invalidate the kernel's cached inode attributes so that
        // surviving hardlink names get a fresh GETATTR on next access.
        // Without this, the kernel VFS may reject linkat() with ENOENT
        // after unlinking one name of a hardlink pair.
        if let Some(fuse_ino) = inval_fuse_ino
            && let Some(notifier) = self.notifier.get()
        {
            let _ = notifier.inval_inode(INodeNo(fuse_ino), 0, 0);
        }
    }
}

// ---- Helper functions ----

/// Convert a libc::stat to fuser::FileAttr.
fn stat_to_attr(st: &libc::stat) -> FileAttr {
    let kind = mode_to_filetype(st.st_mode);
    FileAttr {
        ino: INodeNo(st.st_ino as u64),
        size: st.st_size as u64,
        blocks: st.st_blocks as u64,
        atime: UNIX_EPOCH + Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
        mtime: UNIX_EPOCH + Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
        ctime: UNIX_EPOCH + Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
        crtime: UNIX_EPOCH,
        kind,
        perm: (st.st_mode & 0o7777) as u16,
        nlink: st.st_nlink as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev as u32,
        blksize: st.st_blksize as u32,
        flags: 0,
    }
}

fn mode_to_filetype(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

impl OverlayInner {
    /// Compute the overlay-relative path for a node.
    fn node_path(&self, id: NodeId) -> Vec<u8> {
        node::compute_path(&self.nodes, id)
    }

    /// Get a node by id, returning ENOENT on missing.
    fn node(&self, id: &NodeId) -> FsResult<&OvlNode> {
        self.nodes.get(id).ok_or(FsError(libc::ENOENT))
    }

    /// Returns true if the node is missing from the arena.
    fn is_whiteout_or_missing(&self, id: &NodeId) -> bool {
        !self.nodes.contains_key(id)
    }

    /// Get a layer by index, returning ENOENT on out-of-bounds.
    fn layer(&self, idx: usize) -> FsResult<&OvlLayer> {
        self.layers.get(idx).ok_or(FsError(libc::ENOENT))
    }

    /// Get a node and its associated layer, returning ENOENT if either is missing.
    fn node_and_layer(&self, id: NodeId) -> FsResult<(&OvlNode, &OvlLayer)> {
        let node = self.node(&id)?;
        let layer = self.layer(node.layer_idx)?;
        Ok((node, layer))
    }

    /// Get the upper (writable) layer, returning EROFS if not available.
    fn upper(&self) -> FsResult<&OvlLayer> {
        self.upper_layer().ok_or(FsError(libc::EROFS))
    }

    /// Resolve the parent directory for a file creation operation.
    /// Looks up the parent, copies it up if needed, and returns
    /// (pnode_id, pnode_path, upper_fd, child_path).
    fn prepare_create_parent(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        config: &OverlayConfig,
    ) -> FsResult<(NodeId, Vec<u8>, RawFd, Vec<u8>)> {
        let pnode_id = self
            .do_lookup_file(parent_ino, None, config)
            .ok_or(FsError(libc::ENOENT))?;
        self.get_node_up(pnode_id)?;
        let pnode_path = self.node_path(pnode_id);
        let upper_fd = self.layers[0].ds.root_fd();
        let child_path = OverlayInner::child_path(&pnode_path, name);
        Ok((pnode_id, pnode_path, upper_fd, child_path))
    }

    /// Stat a newly created child on the upper layer and register it in the
    /// overlay tree.  Returns `(fuse_ino, attr)` on success.
    fn stat_and_register_child(
        &mut self,
        pnode_id: NodeId,
        name: &[u8],
        child_path: &[u8],
    ) -> FsResult<(u64, FileAttr)> {
        let st = self.layers[0].ds.statat(
            child_path,
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS,
        )?;
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        match self.create_and_register_child(pnode_id, name, &st, is_dir) {
            Some((_child_id, fuse_ino)) => {
                let mut attr = stat_to_attr(&st);
                attr.ino = INodeNo(fuse_ino);
                Ok((fuse_ino, attr))
            }
            None => Err(FsError(libc::ENOMEM)),
        }
    }

    /// Map a FUSE-provided UID to host UID for writing to disk.
    fn map_uid(&self, id: u32, config: &OverlayConfig) -> u32 {
        mapping::find_mapping(
            id,
            &config.uid_mappings,
            false,
            config.squash_to_root,
            config.squash_to_uid,
            self.overflow.uid,
        )
    }

    /// Map a FUSE-provided GID to host GID for writing to disk.
    fn map_gid(&self, id: u32, config: &OverlayConfig) -> u32 {
        mapping::find_mapping(
            id,
            &config.gid_mappings,
            false,
            config.squash_to_root,
            config.squash_to_gid,
            self.overflow.gid,
        )
    }

    /// Inherit POSIX ACL from parent directory to a newly created file/dir.
    fn inherit_acl(&self, parent_id: NodeId, target_fd: RawFd, config: &OverlayConfig) {
        if config.noacl {
            return;
        }
        let parent_path = self.node_path(parent_id);
        let parent = match self.nodes.get(&parent_id) {
            Some(n) => n,
            None => return,
        };
        let layer = match self.layers.get(parent.layer_idx) {
            Some(l) => l,
            None => return,
        };
        // Read default ACL from parent directory
        const ACL_XATTR: &str = "system.posix_acl_default";
        let mut buf = vec![0u8; 4096];
        let len = match layer.ds.getxattr(&parent_path, ACL_XATTR, &mut buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        if len == 0 {
            return;
        }
        // Apply to target
        let _ = crate::sys::xattr::fsetxattr(target_fd, ACL_XATTR, &buf[..len], 0);
    }

    /// Insert a child node into the arena and register it under the parent.
    /// Avoids the `unwrap()` pattern on re-reading child name / parent from the arena.
    fn insert_child_node(&mut self, parent_id: NodeId, child: OvlNode) -> NodeId {
        let name = child.name.clone();
        let child_id = self.nodes.insert(child);
        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.insert_child(name, child_id);
        }
        child_id
    }

    /// Build a child path from parent path and child name.
    fn child_path(parent_path: &[u8], name: &[u8]) -> Vec<u8> {
        if parent_path == b"." {
            name.to_vec()
        } else {
            let mut path = parent_path.to_vec();
            path.push(b'/');
            path.extend_from_slice(name);
            path
        }
    }

    /// Check if an entry is whiteout via .wh.<name> file on a given layer.
    fn is_wh_file(&self, layer_idx: usize, parent_path: &[u8], name: &[u8]) -> bool {
        let mut wh_path = if parent_path == b"." {
            b".wh.".to_vec()
        } else {
            let mut p = parent_path.to_vec();
            p.extend_from_slice(b"/.wh.");
            p
        };
        wh_path.extend_from_slice(name);
        matches!(self.layers[layer_idx].ds.file_exists(&wh_path), Ok(true))
    }

    /// Check if a name is a .wh. prefix whiteout entry (e.g. ".wh.foo" whiteouts "foo").
    /// Returns the whited-out name, or None if not a whiteout prefix.
    fn wh_prefix_name(name: &[u8]) -> Option<&[u8]> {
        if name.starts_with(b".wh.") && name != xattr::OPAQUE_WHITEOUT.as_bytes() {
            Some(&name[4..])
        } else {
            None
        }
    }

    /// Check if a stat result represents a char device (0,0) whiteout.
    fn is_chardev_whiteout(st: &libc::stat) -> bool {
        (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
            && libc::major(st.st_rdev) == 0
            && libc::minor(st.st_rdev) == 0
    }

    /// Look up a node by FUSE inode number. Returns the NodeId.
    fn lookup_node_id(&self, ino: u64) -> Option<NodeId> {
        if ino == u64::from(INodeNo::ROOT) {
            return Some(self.root_id);
        }
        // Find first live NodeId (skip removed hardlink nodes)
        let ovl_ino = self.inodes.fuse_to_ino(ino)?;
        ovl_ino
            .nodes
            .iter()
            .copied()
            .find(|id| self.nodes.contains_key(id))
    }

    /// Stat a node using a pre-computed path.
    fn do_stat_with_path(&self, node: &OvlNode, fd: RawFd, path: &[u8]) -> FsResult<libc::stat> {
        let layer = self.layer(node.layer_idx)?;
        if fd >= 0 {
            return layer.ds.fstat(fd, path, sstatx::STATX_BASIC_STATS);
        }
        if node.hidden {
            // hidden_path is always a counter string (valid UTF-8)
            let hp = node.hidden_path.as_deref().unwrap_or("");
            let c_path = crate::error::cstr(hp)?;
            return crate::sys::fs::fstatat(node.hidden_dirfd, &c_path, libc::AT_SYMLINK_NOFOLLOW);
        }
        layer
            .ds
            .statat(path, libc::AT_SYMLINK_NOFOLLOW, sstatx::STATX_BASIC_STATS)
    }

    /// Get the inode number for a node with a pre-computed path.
    /// Avoids redundant path computation when the caller already has the path.
    fn get_st_ino_with_path(&self, node: &OvlNode, path: &[u8], config: &OverlayConfig) -> u64 {
        let ino = if config.nfs_filehandles != 0 {
            let layer = match self.layer(node.layer_idx) {
                Ok(l) => l,
                Err(_) => return node.tmp_ino,
            };
            let fh = layer.ds.get_nfs_filehandle(path);
            if fh != 0 { fh } else { node.tmp_ino }
        } else {
            node.tmp_ino
        };
        let ino = crate::node::compute_fuse_ino(ino, node.tmp_dev, self.ino_passthrough);
        if config.ino_t_32 {
            ino as u32 as u64
        } else {
            ino
        }
    }

    fn get_fs_namemax(&self) -> usize {
        if self.layers.is_empty() {
            return 251;
        }
        let fd = self.layers[0].root_fd();
        match crate::sys::fs::fstatvfs(fd) {
            Ok(svfs) => {
                let namemax = svfs.f_namemax as usize;
                // Reserve space for ".wh." whiteout prefix (4 chars)
                if namemax > 4 { namemax - 4 } else { namemax }
            }
            Err(_) => 251,
        }
    }

    /// Full stat with UID/GID mapping and nlink computation, using a pre-computed path.
    fn rpl_stat_with_path(
        &self,
        node_id: NodeId,
        fd: RawFd,
        config: &OverlayConfig,
        path: &[u8],
    ) -> FsResult<libc::stat> {
        let node = self.nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
        let mut st = self.do_stat_with_path(node, fd, path)?;

        // Apply stat override from xattr (must be before UID/GID mapping)
        let layer = self.layer(node.layer_idx)?;
        if layer.stat_override_mode() != StatOverrideMode::None {
            let _ = override_mode(layer, fd, path, &mut st);
        }

        st.st_uid = mapping::find_mapping(
            st.st_uid,
            &config.uid_mappings,
            true,
            config.squash_to_root,
            config.squash_to_uid,
            self.overflow.uid,
        );
        st.st_gid = mapping::find_mapping(
            st.st_gid,
            &config.gid_mappings,
            true,
            config.squash_to_root,
            config.squash_to_gid,
            self.overflow.gid,
        );

        st.st_ino = self.get_st_ino_with_path(node, path, config) as _;

        // Compute nlink
        if node.is_loaded() && node.n_links > 0 {
            st.st_nlink = node.n_links as _;
        } else if node.is_dir() {
            if config.static_nlink {
                st.st_nlink = 1;
            } else {
                let mut nlink: u64 = 2;
                if let Some(children) = node.children() {
                    for child_id in children.values() {
                        if let Some(child) = self.nodes.get(child_id)
                            && child.is_dir()
                        {
                            nlink += 1;
                        }
                    }
                }
                st.st_nlink = nlink as _;
            }
        } else {
            // Count hardlinks via inode table
            if node.tmp_ino != 0 {
                let key = InodeKey {
                    ino: node.tmp_ino,
                    dev: node.tmp_dev,
                };
                if let Some(ovl_ino) = self.inodes.get_by_key(&key) {
                    let count = ovl_ino
                        .nodes
                        .iter()
                        .filter(|id| self.nodes.contains_key(id))
                        .count();
                    if count > 0 {
                        st.st_nlink = count as _;
                    }
                }
            }
        }

        Ok(st)
    }

    /// Full stat with UID/GID mapping and nlink computation (computes path internally).
    fn rpl_stat(&self, node_id: NodeId, fd: RawFd, config: &OverlayConfig) -> FsResult<libc::stat> {
        let node = self.nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
        let path = if node.hidden {
            node.hidden_path
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec()
        } else {
            self.node_path(node_id)
        };
        self.rpl_stat_with_path(node_id, fd, config, &path)
    }

    fn do_getattr(&self, node_id: NodeId, config: &OverlayConfig) -> Option<FileAttr> {
        match self.rpl_stat(node_id, -1, config) {
            Ok(st) => Some(stat_to_attr(&st)),
            Err(_) => None,
        }
    }

    fn ensure_root_loaded(&mut self, config: &OverlayConfig) {
        if self
            .nodes
            .get(&self.root_id)
            .map(|n| n.is_loaded())
            .unwrap_or(true)
        {
            return;
        }
        self.load_dir_entries(self.root_id, b".", config);
    }

    /// Load directory entries from all layers into a node.
    fn load_dir_entries(&mut self, parent_id: NodeId, path: &[u8], config: &OverlayConfig) {
        self.load_dir_impl(parent_id, path, None, config);
    }

    /// Shared implementation for loading directory entries from all layers.
    /// `last_layer_stop`: if Some(idx), stop after processing that layer index.
    fn load_dir_impl(
        &mut self,
        parent_id: NodeId,
        path: &[u8],
        last_layer_stop: Option<usize>,
        config: &OverlayConfig,
    ) {
        let mut stop_lookup = false;

        for layer_idx in 0..self.layers.len() {
            if stop_lookup {
                break;
            }
            if let Some(last) = last_layer_stop
                && last == layer_idx
                && layer_idx > 0
            {
                stop_lookup = true;
            }

            let stat_result = self.layers[layer_idx].ds.statat(
                path,
                libc::AT_SYMLINK_NOFOLLOW,
                sstatx::STATX_TYPE,
            );
            match stat_result {
                Ok(st) => {
                    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                        break;
                    }
                }
                Err(e) if e.0 == libc::ENOENT || e.0 == libc::ENOTDIR => continue,
                Err(_) => break,
            }

            let mut dir = match self.layers[layer_idx].ds.opendir(path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            while let Some(entry) = dir.next_entry() {
                if entry.name == b"."
                    || entry.name == b".."
                    || entry.name == xattr::OPAQUE_WHITEOUT.as_bytes()
                {
                    continue;
                }

                // If already seen from a higher layer, update last_layer_idx
                if let Some(existing_id) = self
                    .nodes
                    .get(&parent_id)
                    .and_then(|p| p.get_child(&entry.name))
                {
                    if let Some(existing) = self.nodes.get_mut(&existing_id) {
                        existing.last_layer_idx = layer_idx;
                    }
                    continue;
                }

                // If whited out by a higher layer, skip
                if self
                    .nodes
                    .get(&parent_id)
                    .map(|p| p.is_whiteout(&entry.name))
                    .unwrap_or(false)
                {
                    continue;
                }

                // Check for .wh.<name> file whiteout
                if self.is_wh_file(layer_idx, path, &entry.name) {
                    if let Some(parent) = self.nodes.get_mut(&parent_id) {
                        parent.insert_whiteout(entry.name);
                    }
                    continue;
                }

                // Check if entry itself is a .wh. prefix whiteout
                if let Some(whited_name) = Self::wh_prefix_name(&entry.name) {
                    // If the whited-out name already exists from a higher layer, skip
                    if self
                        .nodes
                        .get(&parent_id)
                        .and_then(|p| p.get_child(whited_name))
                        .is_some()
                    {
                        continue;
                    }
                    if let Some(parent) = self.nodes.get_mut(&parent_id) {
                        parent.insert_whiteout(whited_name.to_vec());
                    }
                    continue;
                }

                // Check for char device (0,0) whiteout
                if entry.dtype == libc::DT_CHR || entry.dtype == libc::DT_UNKNOWN {
                    let node_path = Self::child_path(path, &entry.name);
                    if let Ok(st) = self.layers[layer_idx].ds.statat(
                        &node_path,
                        libc::AT_SYMLINK_NOFOLLOW,
                        sstatx::STATX_TYPE,
                    ) && Self::is_chardev_whiteout(&st)
                    {
                        if let Some(parent) = self.nodes.get_mut(&parent_id) {
                            parent.insert_whiteout(entry.name);
                        }
                        continue;
                    }
                }

                // Normal entry
                let is_dir = entry.dtype == libc::DT_DIR;
                let node_path = Self::child_path(path, &entry.name);

                let (ino, dev, mode) = if config.fast_ino_check {
                    (entry.ino, 0, if is_dir { libc::S_IFDIR } else { 0 })
                } else {
                    match self.layers[layer_idx].ds.statat(
                        &node_path,
                        libc::AT_SYMLINK_NOFOLLOW,
                        sstatx::STATX_TYPE | sstatx::STATX_MODE | sstatx::STATX_INO,
                    ) {
                        Ok(st) => (st.st_ino as u64, st.st_dev as u64, st.st_mode),
                        Err(_) => (entry.ino, 0, if is_dir { libc::S_IFDIR } else { 0 }),
                    }
                };

                let actual_is_dir = (mode & libc::S_IFMT) == libc::S_IFDIR || is_dir;
                let mut child = OvlNode::new(entry.name, layer_idx, ino, dev, actual_is_dir);
                child.mode = mode;
                child.last_layer_idx = layer_idx;
                child.parent = Some(parent_id);
                self.insert_child_node(parent_id, child);
            }

            if let Ok(true) =
                whiteout::is_directory_opaque(self.layers[layer_idx].ds.as_ref(), path)
            {
                stop_lookup = true;
            }
        }

        if let Some(n) = self.nodes.get_mut(&parent_id) {
            n.mark_loaded();
        }
    }

    /// Look up a file by parent inode and name.
    fn do_lookup_file(
        &mut self,
        parent_ino: u64,
        name: Option<&[u8]>,
        config: &OverlayConfig,
    ) -> Option<NodeId> {
        let parent_id = self.lookup_node_id(parent_ino)?;

        let name = match name {
            Some(n) => n,
            None => return Some(parent_id),
        };

        // Check children first
        if let Some(child_id) = self.nodes.get(&parent_id).and_then(|p| p.get_child(name)) {
            return Some(child_id);
        }

        // Check if name is whiteout (deleted by upper layer)
        if self
            .nodes
            .get(&parent_id)
            .map(|p| p.is_whiteout(name))
            .unwrap_or(false)
        {
            return None;
        }

        // If not loaded, do a lazy lookup
        let loaded = self
            .nodes
            .get(&parent_id)
            .map(|n| n.is_loaded())
            .unwrap_or(true);
        if !loaded {
            self.do_lazy_lookup(parent_id, name, config)
        } else {
            None
        }
    }

    /// Perform lazy lookup for a single entry across layers.
    fn do_lazy_lookup(
        &mut self,
        parent_id: NodeId,
        name: &[u8],
        _config: &OverlayConfig,
    ) -> Option<NodeId> {
        let parent_path = self.node_path(parent_id);
        let last_layer_idx = self.nodes.get(&parent_id)?.last_layer_idx;
        let mut found_node: Option<OvlNode> = None;
        let mut stop_lookup = false;

        for layer_idx in 0..self.layers.len() {
            if stop_lookup {
                break;
            }
            if last_layer_idx == layer_idx && layer_idx > 0 {
                stop_lookup = true;
            }

            let path = Self::child_path(&parent_path, name);

            let stat_result = self.layers[layer_idx].ds.statat(
                &path,
                libc::AT_SYMLINK_NOFOLLOW,
                sstatx::STATX_TYPE | sstatx::STATX_MODE | sstatx::STATX_INO,
            );

            match stat_result {
                Err(e) if e.0 == libc::ENOENT || e.0 == libc::ENOTDIR || e.0 == libc::EACCES => {
                    if found_node.is_some() {
                        continue;
                    }
                    // Whiteout found: record in parent's whiteout set and stop
                    if self.is_wh_file(layer_idx, &parent_path, name) {
                        if let Some(parent) = self.nodes.get_mut(&parent_id) {
                            parent.insert_whiteout(name.to_vec());
                        }
                        return None;
                    }
                    continue;
                }
                Err(_) => return None,
                Ok(st) => {
                    if let Some(ref mut existing) = found_node {
                        existing.tmp_ino = st.st_ino as u64;
                        existing.tmp_dev = st.st_dev as u64;
                        existing.last_layer_idx = layer_idx;
                        continue;
                    }

                    // Whiteout found: record in parent's whiteout set and stop
                    if self.is_wh_file(layer_idx, &parent_path, name) {
                        if let Some(parent) = self.nodes.get_mut(&parent_id) {
                            parent.insert_whiteout(name.to_vec());
                        }
                        return None;
                    }

                    if let Some(whited) = Self::wh_prefix_name(name) {
                        if let Some(parent) = self.nodes.get_mut(&parent_id) {
                            parent.insert_whiteout(whited.to_vec());
                        }
                        return None;
                    }
                    if Self::is_chardev_whiteout(&st) {
                        if let Some(parent) = self.nodes.get_mut(&parent_id) {
                            parent.insert_whiteout(name.to_vec());
                        }
                        return None;
                    }

                    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
                    let mut child = OvlNode::new(
                        name.to_vec(),
                        layer_idx,
                        st.st_ino as u64,
                        st.st_dev as u64,
                        is_dir,
                    );
                    child.mode = st.st_mode;
                    child.last_layer_idx = layer_idx;
                    child.parent = Some(parent_id);

                    if is_dir
                        && matches!(
                            whiteout::is_directory_opaque(
                                self.layers[layer_idx].ds.as_ref(),
                                &path
                            ),
                            Ok(true)
                        )
                    {
                        child.last_layer_idx = layer_idx;
                        stop_lookup = true;
                    }

                    found_node = Some(child);
                }
            }
        }

        if let Some(child) = found_node {
            let child_name = child.name.clone();
            let tmp_ino = child.tmp_ino;
            let tmp_dev = child.tmp_dev;
            let mode = child.mode;

            let child_id = self.nodes.insert(child);

            if tmp_ino != 0 {
                self.inodes
                    .register(&self.nodes, child_id, tmp_ino, tmp_dev, mode);
            }

            self.nodes
                .get_mut(&parent_id)?
                .insert_child(child_name, child_id);
            Some(child_id)
        } else {
            None
        }
    }

    /// Reload a directory's children from all layers.
    fn reload_dir(&mut self, node_id: NodeId, config: &OverlayConfig) -> bool {
        if self
            .nodes
            .get(&node_id)
            .map(|n| n.is_loaded())
            .unwrap_or(true)
        {
            return true;
        }

        let path = self.node_path(node_id);
        let last_layer = match self.nodes.get(&node_id) {
            Some(n) => n.last_layer_idx,
            None => return false,
        };

        self.load_dir_impl(node_id, &path, Some(last_layer), config);
        true
    }

    fn build_dir_entries(&mut self, node_id: NodeId, config: &OverlayConfig) -> Vec<DirEntry> {
        self.reload_dir(node_id, config);

        let node = match self.nodes.get(&node_id) {
            Some(n) => n,
            None => return Vec::new(),
        };

        // Compute dir path once for all children (avoids N parent-chain walks)
        let dir_path = self.node_path(node_id);

        let mut entries = Vec::new();

        // "." entry
        let self_ino = self.get_st_ino_with_path(node, &dir_path, config);
        let self_attr = self
            .rpl_stat_with_path(node_id, -1, config, &dir_path)
            .ok()
            .map(|st| stat_to_attr(&st));
        entries.push(DirEntry {
            name: b".".to_vec(),
            ino: self_ino,
            mode: libc::S_IFDIR,
            attr: self_attr,
            node_id: Some(node_id),
        });

        // ".." entry
        let parent_id = node.parent;
        let (parent_ino, parent_attr) = if let Some(pid) = parent_id {
            if let Some(parent) = self.nodes.get(&pid) {
                let parent_path = self.node_path(pid);
                let ino = self.get_st_ino_with_path(parent, &parent_path, config);
                let attr = self
                    .rpl_stat_with_path(pid, -1, config, &parent_path)
                    .ok()
                    .map(|st| stat_to_attr(&st));
                (ino, attr)
            } else {
                (self_ino, self_attr)
            }
        } else {
            (self_ino, self_attr)
        };
        entries.push(DirEntry {
            name: b"..".to_vec(),
            ino: parent_ino,
            mode: libc::S_IFDIR,
            attr: parent_attr,
            node_id: parent_id,
        });

        // Collect child references without cloning names, sort by reference
        let mut child_ids: Vec<(&[u8], NodeId)> = node
            .children()
            .map(|ch| ch.iter().map(|(k, v)| (k.as_slice(), *v)).collect())
            .unwrap_or_default();
        child_ids.sort_unstable_by_key(|(a, _)| *a);

        // Reusable buffer for child paths (avoids N allocations)
        let mut path_buf = Vec::with_capacity(dir_path.len() + 256);
        for (child_name, child_id) in child_ids {
            if let Some(child) = self.nodes.get(&child_id)
                && !child.hidden
            {
                // Build child path in reusable buffer
                path_buf.clear();
                if dir_path != b"." {
                    path_buf.extend_from_slice(&dir_path);
                    path_buf.push(b'/');
                }
                path_buf.extend_from_slice(&child.name);

                let ino = self.get_st_ino_with_path(child, &path_buf, config);
                let attr = self
                    .rpl_stat_with_path(child_id, -1, config, &path_buf)
                    .ok()
                    .map(|st| stat_to_attr(&st));
                entries.push(DirEntry {
                    name: child_name.to_vec(),
                    ino,
                    mode: child.mode,
                    attr,
                    node_id: Some(child_id),
                });
            }
        }

        entries
    }

    fn next_wd_counter(&mut self) -> u64 {
        let c = self.wd_counter;
        self.wd_counter += 1;
        c
    }

    fn upper_layer(&self) -> Option<&OvlLayer> {
        self.layers.first().filter(|l| !l.low)
    }

    /// Ensure a node is on the upper layer (copy-up if needed).
    fn get_node_up(&mut self, node_id: NodeId) -> FsResult<()> {
        if self.upper_layer().is_none() {
            return Err(FsError(libc::EROFS));
        }
        let layer_idx = self
            .nodes
            .get(&node_id)
            .ok_or(FsError(libc::ENOENT))?
            .layer_idx;
        if layer_idx == 0 && !self.layer(0)?.low {
            return Ok(());
        }
        crate::copyup::copyup(
            &self.layers,
            &mut self.nodes,
            node_id,
            self.workdir_fd,
            &mut self.wd_counter,
        )
    }

    /// Hide a node: move it to workdir and create whiteout if needed.
    fn hide_node(&mut self, node_id: NodeId, unlink_src: bool) -> FsResult<()> {
        let upper_fd = self.upper()?.ds.root_fd();
        let newname = format!("{}", self.next_wd_counter());
        let c_newname = crate::error::cstr(newname.as_str())?;

        if unlink_src {
            let node_path = self.node_path(node_id);
            let node = self.nodes.get(&node_id).ok_or(FsError(libc::ENOENT))?;
            let node_name = node.name.clone();
            let last_layer_idx = node.last_layer_idx;
            let parent_id = node.parent;

            let needs_whiteout = last_layer_idx > 0
                || parent_id
                    .map(|pid| {
                        self.nodes
                            .get(&pid)
                            .map(|p| p.last_layer_idx > 0)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

            // Safely resolve the source path's parent to avoid symlink traversal
            let (_src_guard, src_dirfd, c_name) = safe_parent(upper_fd, &node_path)?;

            if needs_whiteout {
                const RENAME_WHITEOUT: u32 = 1 << 2;
                let rename_wh_ok = if self.can_mknod {
                    crate::sys::fs::renameat2(
                        src_dirfd,
                        &c_name,
                        self.workdir_fd,
                        &c_newname,
                        RENAME_WHITEOUT,
                    )
                    .is_ok()
                } else {
                    false
                };

                if !rename_wh_ok {
                    if let Some(pid) = parent_id {
                        let parent_path = self.node_path(pid);
                        whiteout::create_whiteout(
                            upper_fd,
                            &parent_path,
                            &node_name,
                            self.can_mknod,
                        )?;
                    }
                    crate::sys::fs::renameat(src_dirfd, &c_name, self.workdir_fd, &c_newname)?;
                }
            } else {
                crate::sys::fs::renameat(src_dirfd, &c_name, self.workdir_fd, &c_newname)?;
            }
        }

        // Update node state
        let node = self.nodes.get_mut(&node_id).ok_or(FsError(libc::ENOENT))?;
        node.hidden_dirfd = self.workdir_fd;
        node.hidden_path = Some(newname);
        node.hidden = true;
        let parent_id = node.parent;
        if node.is_dir() {
            node.do_rmdir = true;
        } else {
            node.do_unlink = true;
        }

        if let Some(pid) = parent_id
            && let Some(parent) = self.nodes.get_mut(&pid)
        {
            parent.mark_unloaded();
        }
        if let Some(n) = self.nodes.get_mut(&node_id) {
            n.parent = None;
        }

        Ok(())
    }

    /// Helper to get a node_id for write operations that need to find by FUSE ino.
    /// Resolve a FUSE inode to a NodeId, checking for existence and whiteouts.
    fn resolve_node(&self, ino: u64) -> FsResult<NodeId> {
        let node_id = self.lookup_node_id(ino).ok_or(FsError(libc::ENOENT))?;
        if self.is_whiteout_or_missing(&node_id) {
            return Err(FsError(libc::ENOENT));
        }
        Ok(node_id)
    }

    /// Resolve a FUSE inode to a NodeId for write operations (no whiteout check).
    fn resolve_node_for_write(&mut self, ino: u64) -> FsResult<NodeId> {
        self.lookup_node_id(ino).ok_or(FsError(libc::ENOENT))
    }

    /// Create a child node, insert into arena and parent, register in inode table.
    /// Returns (child_id, fuse_ino) or error.
    fn create_and_register_child(
        &mut self,
        parent_id: NodeId,
        name: &[u8],
        st: &libc::stat,
        is_dir: bool,
    ) -> Option<(NodeId, u64)> {
        let mut child = OvlNode::new(name.to_vec(), 0, st.st_ino as u64, st.st_dev as u64, is_dir);
        child.parent = Some(parent_id);
        child.mode = st.st_mode;
        if is_dir {
            child.mark_loaded();
        }

        let child_id = self.nodes.insert(child);
        let fuse_ino = self.inodes.register(
            &self.nodes,
            child_id,
            st.st_ino as u64,
            st.st_dev as u64,
            st.st_mode,
        )?;
        let key = InodeKey {
            ino: st.st_ino as u64,
            dev: st.st_dev as u64,
        };
        self.inodes.inc_lookup(&key);

        self.nodes
            .get_mut(&parent_id)?
            .insert_child(name.to_vec(), child_id);
        Some((child_id, fuse_ino))
    }
}

impl Filesystem for OverlayFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        debug!("init");

        let _ = config.add_capabilities(
            InitFlags::FUSE_DONT_MASK
                | InitFlags::FUSE_SPLICE_READ
                | InitFlags::FUSE_SPLICE_WRITE
                | InitFlags::FUSE_SPLICE_MOVE
                | InitFlags::FUSE_PARALLEL_DIROPS
                | InitFlags::FUSE_HANDLE_KILLPRIV
                | InitFlags::FUSE_CACHE_SYMLINKS
                | InitFlags::FUSE_DO_READDIRPLUS
                | InitFlags::FUSE_READDIRPLUS_AUTO,
        );
        // Passthrough and writeback cache are mutually exclusive in the kernel.
        // Prefer passthrough when available (direct kernel I/O, zero FUSE overhead).
        let no_passthrough = std::env::var("FUSE_OVERLAYFS_NO_PASSTHROUGH").is_ok();
        // Passthrough bypasses FUSE for data I/O, so the FUSE fsync handler is
        // never called.  When fsync=0 (volatile mode) we rely on FUSE returning
        // ENOSYS to suppress fsyncs.  Passthrough would defeat that optimisation.
        let passthrough = if no_passthrough {
            info!("FUSE passthrough disabled by FUSE_OVERLAYFS_NO_PASSTHROUGH");
            false
        } else if !self.config.fsync {
            info!("FUSE passthrough disabled: incompatible with volatile (fsync=0) mode");
            false
        } else {
            let _ = config.add_capabilities(InitFlags::FUSE_PASSTHROUGH);
            let _ = config.set_max_stack_depth(2);
            config.capabilities().contains(InitFlags::FUSE_PASSTHROUGH)
        };
        if !passthrough && self.config.writeback {
            let _ = config.add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE);
        }
        if !self.config.noacl {
            let _ = config.add_capabilities(InitFlags::FUSE_POSIX_ACL);
        }
        {
            let inner = self.inner.read();
            if !inner.ino_passthrough && self.config.nfs_filehandles == 0 {
                let _ = config.add_capabilities(InitFlags::FUSE_NO_EXPORT_SUPPORT);
            }
        }
        self.passthrough_enabled
            .store(passthrough, Ordering::Relaxed);
        node::STAT_PASSTHROUGH.store(passthrough, Ordering::Relaxed);
        info!(
            "FUSE passthrough: {}",
            if passthrough {
                "enabled"
            } else {
                "not supported by kernel"
            }
        );
        Ok(())
    }

    fn destroy(&mut self) {
        debug!("destroy");
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent = u64::from(parent);
        let name = name.as_bytes();
        debug!(
            "lookup(parent={}, name={})",
            parent,
            String::from_utf8_lossy(name)
        );

        if name.starts_with(b".wh.") {
            reply.error(Errno::ENOENT);
            return;
        }

        let timeout = self.timeout();

        // FAST PATH: read lock for cache hits (child exists + inode registered).
        // Avoids serializing all lookups behind a write lock.
        {
            let inner = self.inner.read();
            let parent_id = inner.lookup_node_id(parent);
            if let Some(parent_id) = parent_id {
                // Fast-path whiteout check: name is known-deleted
                if inner
                    .nodes
                    .get(&parent_id)
                    .map(|p| p.is_whiteout(name))
                    .unwrap_or(false)
                {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
            if let Some(parent_id) = parent_id
                && let Some(child_id) = inner.nodes.get(&parent_id).and_then(|p| p.get_child(name))
            {
                let node = match inner.nodes.get(&child_id) {
                    Some(n) if !n.hidden => n,
                    _ => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                };
                let key = InodeKey {
                    ino: node.tmp_ino,
                    dev: node.tmp_dev,
                };
                if let Some(fuse_ino) = inner.inodes.key_to_fuse_ino(&key) {
                    // Ensure this node is registered in the inode table's node set.
                    // Nodes loaded by readdir/readdirplus are in the tree but not
                    // registered; fall through to the slow path to register them
                    // so hardlink tracking works correctly.
                    let node_registered = inner
                        .inodes
                        .get_by_key(&key)
                        .map(|ovl_ino| ovl_ino.nodes.contains(&child_id))
                        .unwrap_or(false);
                    if node_registered {
                        let path = inner.node_path(child_id);
                        if let Ok(st) = inner.rpl_stat_with_path(child_id, -1, &self.config, &path)
                        {
                            inner.inodes.inc_lookup(&key);
                            let mut attr = stat_to_attr(&st);
                            attr.ino = INodeNo(fuse_ino);
                            reply.entry(&timeout, &attr, Generation(0));
                            return;
                        }
                    }
                }
            }
        }

        // SLOW PATH: write lock (cache miss, first inode registration, dir reload).
        let mut inner = self.inner.write();

        let node_id = match inner.do_lookup_file(parent, Some(name), &self.config) {
            Some(id) => id,
            None => {
                debug!(
                    "lookup({}, {:?}) -> ENOENT (no node)",
                    parent,
                    String::from_utf8_lossy(name)
                );
                reply.error(Errno::ENOENT);
                return;
            }
        };

        if inner.is_whiteout_or_missing(&node_id) {
            debug!(
                "lookup({}, {:?}) -> ENOENT (whiteout)",
                parent,
                String::from_utf8_lossy(name)
            );
            reply.error(Errno::ENOENT);
            return;
        }

        if !self.config.static_nlink
            && inner
                .nodes
                .get(&node_id)
                .map(|n| n.is_dir())
                .unwrap_or(false)
            && !inner.reload_dir(node_id, &self.config)
        {
            reply.error(Errno::EIO);
            return;
        }

        match inner.rpl_stat(node_id, -1, &self.config) {
            Ok(st) => {
                let node = match inner.node(&node_id) {
                    Ok(n) => n,
                    Err(e) => {
                        reply.error(Errno::from_i32(e.0));
                        return;
                    }
                };
                let tmp_ino = node.tmp_ino;
                let tmp_dev = node.tmp_dev;
                let is_dir = node.is_dir();

                let fuse_ino = if tmp_ino != 0 || is_dir {
                    let oi = &mut *inner;
                    if let Some(ino_val) = oi
                        .inodes
                        .register(&oi.nodes, node_id, tmp_ino, tmp_dev, st.st_mode)
                    {
                        let key = InodeKey {
                            ino: tmp_ino,
                            dev: tmp_dev,
                        };
                        oi.inodes.inc_lookup(&key);
                        ino_val
                    } else {
                        reply.error(Errno::ENOMEM);
                        return;
                    }
                } else {
                    u64::from(INodeNo::ROOT)
                };

                let mut attr = stat_to_attr(&st);
                attr.ino = INodeNo(fuse_ino);
                reply.entry(&timeout, &attr, Generation(0));
            }
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let ino = u64::from(ino);
        debug!("forget(ino={}, nlookup={})", ino, nlookup);
        let mut inner = self.inner.write();
        inner.inodes.forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = u64::from(ino);
        debug!("getattr(ino={})", ino);
        let inner = self.inner.read();

        if ino == u64::from(INodeNo::ROOT) {
            // Need write lock for ensure_root_loaded, upgrade
            drop(inner);
            let mut inner = self.inner.write();
            inner.ensure_root_loaded(&self.config);
            match inner.rpl_stat(inner.root_id, -1, &self.config) {
                Ok(st) => reply.attr(&self.timeout(), &stat_to_attr(&st)),
                Err(e) => reply.error(Errno::from_i32(e.0)),
            }
            return;
        }

        match inner.resolve_node(ino) {
            Err(e) => reply.error(Errno::from_i32(e.0)),
            Ok(node_id) => match inner.rpl_stat(node_id, -1, &self.config) {
                Ok(st) => reply.attr(&self.timeout(), &stat_to_attr(&st)),
                Err(e) => reply.error(Errno::from_i32(e.0)),
            },
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino = u64::from(ino);
        debug!("setattr(ino={})", ino);
        let mut inner = self.inner.write();

        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        if let Err(e) = inner.get_node_up(node_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        // Get fd from file handle, or safely open the file by path.
        // We always use fd-based operations to avoid symlink traversal in path components.
        let fh_fd = fh.and_then(|fh_val| self.get_file(u64::from(fh_val)));
        let safe_fd = if fh_fd.is_none() {
            let open_flags = libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if size.is_some() {
                    libc::O_WRONLY
                } else {
                    libc::O_RDONLY
                };
            layer.ds.openat(&path, open_flags, 0).ok()
        } else {
            None
        };
        let fd: RawFd = if let Some(ref f) = fh_fd {
            f.as_raw_fd()
        } else if let Some(ref sfd) = safe_fd {
            sfd.as_raw_fd()
        } else {
            -1
        };

        // Apply time changes
        let mut times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        ];
        if let Some(at) = atime {
            match at {
                TimeOrNow::SpecificTime(t) => {
                    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    times[0] = libc::timespec {
                        tv_sec: d.as_secs() as _,
                        tv_nsec: d.subsec_nanos() as _,
                    };
                }
                TimeOrNow::Now => {
                    times[0].tv_nsec = libc::UTIME_NOW;
                }
            }
        }
        if let Some(mt) = mtime {
            match mt {
                TimeOrNow::SpecificTime(t) => {
                    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    times[1] = libc::timespec {
                        tv_sec: d.as_secs() as _,
                        tv_nsec: d.subsec_nanos() as _,
                    };
                }
                TimeOrNow::Now => {
                    times[1].tv_nsec = libc::UTIME_NOW;
                }
            }
        }
        if times[0].tv_nsec != libc::UTIME_OMIT || times[1].tv_nsec != libc::UTIME_OMIT {
            let result = if fd >= 0 {
                crate::sys::fs::futimens(fd, &times)
            } else {
                // Safely resolve parent for path-based fallback
                match safe_parent(layer.ds.root_fd(), &path) {
                    Ok((_guard, dirfd, c_name)) => {
                        crate::sys::fs::utimensat(dirfd, &c_name, &times, libc::AT_SYMLINK_NOFOLLOW)
                    }
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = result {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        }

        // When stat_override_mode is set, store uid/gid/mode in xattr
        // instead of calling fchown/fchmod (which fail in user namespaces).
        let stat_override_mode = layer.stat_override_mode();
        if stat_override_mode != StatOverrideMode::None
            && (mode.is_some() || uid.is_some() || gid.is_some())
        {
            // Get current stat to fill in unchanged fields
            let current_st = if fd >= 0 {
                crate::sys::fs::fstat(fd)
            } else {
                layer.ds.statat(&path, libc::AT_SYMLINK_NOFOLLOW, 0xfff)
            };
            match current_st {
                Ok(st) => {
                    // Read existing override xattr if present
                    let xattr_name = match stat_override_mode {
                        StatOverrideMode::User | StatOverrideMode::Containers => {
                            datasource::XATTR_OVERRIDE_CONTAINERS_STAT
                        }
                        StatOverrideMode::Privileged => datasource::XATTR_PRIVILEGED_OVERRIDE_STAT,
                        StatOverrideMode::None => unreachable!(),
                    };
                    let (cur_uid, cur_gid, cur_mode) = if fd >= 0 {
                        let mut buf = [0u8; 64];
                        if let Ok(len) = sxattr::fgetxattr(fd, xattr_name, &mut buf) {
                            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                                parse_override_fields(s, &st)
                            } else {
                                (st.st_uid, st.st_gid, st.st_mode & 0o7777)
                            }
                        } else {
                            (st.st_uid, st.st_gid, st.st_mode & 0o7777)
                        }
                    } else {
                        (st.st_uid, st.st_gid, st.st_mode & 0o7777)
                    };

                    let new_uid = uid
                        .map(|u| inner.map_uid(u, &self.config))
                        .unwrap_or(cur_uid);
                    let new_gid = gid
                        .map(|g| inner.map_gid(g, &self.config))
                        .unwrap_or(cur_gid);
                    let new_mode = mode.map(|m| m & 0o7777).unwrap_or(cur_mode);

                    let override_val = format!("{}:{}:{:o}", new_uid, new_gid, new_mode);
                    let result = if fd >= 0 {
                        sxattr::fsetxattr(fd, xattr_name, override_val.as_bytes(), 0)
                    } else {
                        let full_path =
                            crate::sys::openat2::proc_fd_path(inner.layers[0].ds.root_fd(), &path);
                        sxattr::lsetxattr(&full_path, xattr_name, override_val.as_bytes(), 0)
                    };
                    if let Err(e) = result {
                        reply.error(Errno::from_i32(e.0));
                        return;
                    }
                }
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }
        } else {
            if let Some(new_mode) = mode {
                let result = if fd >= 0 {
                    crate::sys::fs::fchmod(fd, new_mode)
                } else {
                    match safe_parent(layer.ds.root_fd(), &path) {
                        Ok((_guard, dirfd, c_name)) => {
                            crate::sys::fs::fchmodat(dirfd, &c_name, new_mode, 0)
                        }
                        Err(e) => Err(e),
                    }
                };
                if let Err(e) = result {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }

            if uid.is_some() || gid.is_some() {
                let new_uid = uid
                    .map(|u| inner.map_uid(u, &self.config))
                    .unwrap_or(u32::MAX);
                let new_gid = gid
                    .map(|g| inner.map_gid(g, &self.config))
                    .unwrap_or(u32::MAX);
                let result = if fd >= 0 {
                    crate::sys::fs::fchown(fd, new_uid, new_gid)
                } else {
                    match safe_parent(layer.ds.root_fd(), &path) {
                        Ok((_guard, dirfd, c_name)) => crate::sys::fs::fchownat(
                            dirfd,
                            &c_name,
                            new_uid,
                            new_gid,
                            libc::AT_SYMLINK_NOFOLLOW,
                        ),
                        Err(e) => Err(e),
                    }
                };
                if let Err(e) = result {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }
        }

        if let Some(new_size) = size {
            let result = if fd >= 0 {
                crate::sys::io::ftruncate(fd, new_size as i64)
            } else {
                match safe_parent(layer.ds.root_fd(), &path) {
                    Ok((_guard, dirfd, c_name)) => {
                        let full_path = crate::sys::openat2::proc_fd_path(dirfd, c_name.to_bytes());
                        match CString::new(full_path) {
                            Ok(c) => crate::sys::fs::truncate(&c, new_size as i64),
                            Err(_) => Err(FsError(libc::EINVAL)),
                        }
                    }
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = result {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        }

        match inner.do_getattr(node_id, &self.config) {
            Some(attr) => reply.attr(&self.timeout(), &attr),
            None => reply.error(Errno::EIO),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let ino = u64::from(ino);
        debug!("readlink(ino={})", ino);
        let inner = self.inner.read();

        match inner.lookup_node_id(ino) {
            None => reply.error(Errno::ENOENT),
            Some(node_id) => {
                let path = inner.node_path(node_id);
                let (_node, layer) = match inner.node_and_layer(node_id) {
                    Ok(v) => v,
                    Err(e) => {
                        reply.error(Errno::from_i32(e.0));
                        return;
                    }
                };
                match layer.ds.readlinkat(&path) {
                    Ok(target) => reply.data(&target),
                    Err(e) => reply.error(Errno::from_i32(e.0)),
                }
            }
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        debug!(
            "mknod(parent={}, name={}, mode={:#o})",
            parent,
            String::from_utf8_lossy(name_bytes),
            mode
        );

        let mut inner = self.inner.write();
        if name_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        if let Some(eid) = inner.do_lookup_file(parent, Some(name_bytes), &self.config)
            && !inner.is_whiteout_or_missing(&eid)
        {
            reply.error(Errno::EEXIST);
            return;
        }

        let (pnode_id, pnode_path, upper_fd, child_path) =
            match inner.prepare_create_parent(parent, name_bytes, &self.config) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };

        let wd_name = format!("{}", inner.next_wd_counter());
        let c_wd = cstring!(wd_name.as_str(), reply);
        if let Err(e) = crate::sys::fs::mknodat(inner.workdir_fd, &c_wd, mode | 0o755, rdev as u64)
        {
            reply.error(Errno::from_i32(e.0));
            return;
        }
        let host_uid = inner.map_uid(req.uid(), &self.config);
        let host_gid = inner.map_gid(req.gid(), &self.config);
        let _ = crate::sys::fs::fchownat(
            inner.workdir_fd,
            &c_wd,
            host_uid,
            host_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        if let Ok(wd_fd) = crate::sys::openat2::safe_openat(
            inner.workdir_fd,
            wd_name.as_bytes(),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        ) {
            inner.inherit_acl(pnode_id, wd_fd.as_raw_fd(), &self.config);
        }

        // Safely resolve destination parent for rename
        let (_dst_guard, dst_dirfd, c_dst_name) = match safe_parent(upper_fd, &child_path) {
            Ok(v) => v,
            Err(e) => {
                let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        if let Err(e) = crate::sys::fs::renameat(inner.workdir_fd, &c_wd, dst_dirfd, &c_dst_name) {
            let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let _ = whiteout::delete_whiteout(upper_fd, Some(dst_dirfd), &pnode_path, name_bytes);

        match inner.stat_and_register_child(pnode_id, name_bytes, &child_path) {
            Ok((_fuse_ino, attr)) => reply.entry(&self.timeout(), &attr, Generation(0)),
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        debug!(
            "mkdir(parent={}, name={}, mode={:#o})",
            parent,
            String::from_utf8_lossy(name_bytes),
            mode
        );

        let mut inner = self.inner.write();
        if name_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        if let Some(eid) = inner.do_lookup_file(parent, Some(name_bytes), &self.config)
            && !inner.is_whiteout_or_missing(&eid)
        {
            reply.error(Errno::EEXIST);
            return;
        }

        let (pnode_id, pnode_path, upper_fd, child_path) =
            match inner.prepare_create_parent(parent, name_bytes, &self.config) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
        let pnode_last_layer = match inner.node(&pnode_id) {
            Ok(n) => n.last_layer_idx,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        let wd_name = format!("{}", inner.next_wd_counter());
        let c_wd = cstring!(wd_name.as_str(), reply);
        if let Err(e) = crate::sys::fs::mkdirat(inner.workdir_fd, &c_wd, mode) {
            reply.error(Errno::from_i32(e.0));
            return;
        }
        let host_uid = inner.map_uid(req.uid(), &self.config);
        let host_gid = inner.map_gid(req.gid(), &self.config);
        let _ = crate::sys::fs::fchownat(
            inner.workdir_fd,
            &c_wd,
            host_uid,
            host_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        if pnode_last_layer > 0
            && let Ok(fd) = crate::sys::openat2::safe_openat(
                inner.workdir_fd,
                wd_name.as_bytes(),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )
        {
            let _ = whiteout::set_fd_opaque(fd.as_raw_fd());
        }

        if let Ok(fd) = crate::sys::openat2::safe_openat(
            inner.workdir_fd,
            wd_name.as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            inner.inherit_acl(pnode_id, fd.as_raw_fd(), &self.config);
        }

        // Safely resolve destination parent for rename
        let (_dst_guard, dst_dirfd, c_dst_name) = match safe_parent(upper_fd, &child_path) {
            Ok(v) => v,
            Err(e) => {
                let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, libc::AT_REMOVEDIR);
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        match crate::sys::fs::renameat(inner.workdir_fd, &c_wd, dst_dirfd, &c_dst_name) {
            Ok(()) => {}
            Err(FsError(libc::ENOTDIR)) => {
                let _ = crate::sys::fs::unlinkat(dst_dirfd, &c_dst_name, 0);
                if let Err(e) =
                    crate::sys::fs::renameat(inner.workdir_fd, &c_wd, dst_dirfd, &c_dst_name)
                {
                    let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, libc::AT_REMOVEDIR);
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }
            Err(e) => {
                let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, libc::AT_REMOVEDIR);
                reply.error(Errno::from_i32(e.0));
                return;
            }
        }
        let _ = whiteout::delete_whiteout(upper_fd, Some(dst_dirfd), &pnode_path, name_bytes);

        match inner.stat_and_register_child(pnode_id, name_bytes, &child_path) {
            Ok((_fuse_ino, attr)) => reply.entry(&self.timeout(), &attr, Generation(0)),
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        debug!(
            "unlink(parent={}, name={:?})",
            parent,
            String::from_utf8_lossy(name_bytes)
        );
        self.do_rm(parent, name_bytes, false, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        debug!(
            "rmdir(parent={}, name={:?})",
            parent,
            String::from_utf8_lossy(name_bytes)
        );
        self.do_rm(parent, name_bytes, true, reply);
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        link: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        let link_bytes = std::os::unix::ffi::OsStrExt::as_bytes(link.as_os_str());
        debug!(
            "symlink(parent={}, name={:?}, link={:?})",
            parent,
            String::from_utf8_lossy(name_bytes),
            String::from_utf8_lossy(link_bytes)
        );

        let mut inner = self.inner.write();
        if name_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        if let Some(eid) = inner.do_lookup_file(parent, Some(name_bytes), &self.config)
            && !inner.is_whiteout_or_missing(&eid)
        {
            reply.error(Errno::EEXIST);
            return;
        }

        let (pnode_id, pnode_path, upper_fd, child_path) =
            match inner.prepare_create_parent(parent, name_bytes, &self.config) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };

        let wd_name = format!("{}", inner.next_wd_counter());
        let c_wd = cstring!(wd_name.as_str(), reply);
        let c_link = match crate::error::cstr_bytes(link_bytes) {
            Ok(c) => c,
            Err(_) => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        if let Err(e) = crate::sys::fs::symlinkat(&c_link, inner.workdir_fd, &c_wd) {
            reply.error(Errno::from_i32(e.0));
            return;
        }
        let host_uid = inner.map_uid(req.uid(), &self.config);
        let host_gid = inner.map_gid(req.gid(), &self.config);
        let _ = crate::sys::fs::fchownat(
            inner.workdir_fd,
            &c_wd,
            host_uid,
            host_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        // Safely resolve destination parent for rename
        let (_dst_guard, dst_dirfd, c_dst_name) = match safe_parent(upper_fd, &child_path) {
            Ok(v) => v,
            Err(e) => {
                let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        if let Err(e) = crate::sys::fs::renameat(inner.workdir_fd, &c_wd, dst_dirfd, &c_dst_name) {
            let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
            reply.error(Errno::from_i32(e.0));
            return;
        }
        let _ = whiteout::delete_whiteout(upper_fd, Some(dst_dirfd), &pnode_path, name_bytes);

        match inner.stat_and_register_child(pnode_id, name_bytes, &child_path) {
            Ok((_fuse_ino, attr)) => reply.entry(&self.timeout(), &attr, Generation(0)),
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let parent = u64::from(parent);
        let newparent = u64::from(newparent);
        let flags: u32 = flags.bits();
        let name_bytes = name.as_bytes();
        let newname_bytes = newname.as_bytes();
        debug!(
            "rename(parent={}, name={:?}, newparent={}, newname={:?})",
            parent,
            String::from_utf8_lossy(name_bytes),
            newparent,
            String::from_utf8_lossy(newname_bytes)
        );

        let mut inner = self.inner.write();
        if newname_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        let src_id = match inner.do_lookup_file(parent, Some(name_bytes), &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if inner.is_whiteout_or_missing(&src_id) {
            reply.error(Errno::ENOENT);
            return;
        }

        if let Some(node) = inner.nodes.get(&src_id)
            && node.is_dir()
        {
            inner.reload_dir(src_id, &self.config);
            let node = match inner.node(&src_id) {
                Ok(n) => n,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            if node.layer_idx > 0 || node.last_layer_idx > 0 {
                reply.error(Errno::from_i32(libc::EXDEV));
                return;
            }
        }

        if let Err(e) = inner.get_node_up(src_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let sparent_id = match inner.do_lookup_file(parent, None, &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if let Err(e) = inner.get_node_up(sparent_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let dparent_id = match inner.do_lookup_file(newparent, None, &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if let Err(e) = inner.get_node_up(dparent_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let upper_fd = inner.layers[0].ds.root_fd();
        let src_path = inner.node_path(src_id);
        let dparent_path = inner.node_path(dparent_id);
        let new_path = OverlayInner::child_path(&dparent_path, newname_bytes);

        if let Some(dst_id) = inner.do_lookup_file(newparent, Some(newname_bytes), &self.config)
            && !inner.is_whiteout_or_missing(&dst_id)
        {
            if flags & 1 != 0 {
                reply.error(Errno::EEXIST);
                return;
            }

            if flags & 2 == 0
                && let Some(node) = inner.nodes.get(&dst_id)
                && node.is_dir()
            {
                inner.reload_dir(dst_id, &self.config);
                if let Some(node) = inner.nodes.get(&dst_id)
                    && let Some(children) = node.children()
                {
                    let has_visible = children
                        .values()
                        .any(|cid| inner.nodes.get(cid).map(|c| !c.hidden).unwrap_or(false));
                    if has_visible {
                        reply.error(Errno::from_i32(libc::ENOTEMPTY));
                        return;
                    }
                }
                // Clean up any remaining files (whiteouts, hidden entries) on
                // the upper layer so that the underlying renameat() doesn't
                // fail with ENOTEMPTY.
                let dst_path = inner.node_path(dst_id);
                let _ = empty_upper_dir(&inner.layers[0], &dst_path);
            }
        }

        // If the source is a directory, remove any whiteout at the destination
        // so that renameat() doesn't fail with ENOTDIR.
        let src_is_dir = inner
            .nodes
            .get(&src_id)
            .map(|n| n.is_dir())
            .unwrap_or(false);
        if src_is_dir {
            let _ = whiteout::delete_whiteout(upper_fd, None, &dparent_path, newname_bytes);
        }

        // Safely resolve both source and destination parents
        let (_src_guard, src_dirfd, c_old) = match safe_parent(upper_fd, &src_path) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let (_dst_guard, dst_dirfd, c_new) = match safe_parent(upper_fd, &new_path) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let rename_result = if flags != 0 {
            crate::sys::fs::renameat2(src_dirfd, &c_old, dst_dirfd, &c_new, flags)
        } else {
            crate::sys::fs::renameat(src_dirfd, &c_old, dst_dirfd, &c_new)
        };
        if let Err(e) = rename_result {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let src_last_layer = match inner.nodes.get(&src_id) {
            Some(n) => n.last_layer_idx,
            None => 0,
        };

        if let Some(p) = inner.nodes.get_mut(&sparent_id) {
            p.mark_unloaded();
        }
        if dparent_id != sparent_id
            && let Some(p) = inner.nodes.get_mut(&dparent_id)
        {
            p.mark_unloaded();
        }

        if flags & 2 != 0 {
            let src_child = inner
                .nodes
                .get_mut(&sparent_id)
                .and_then(|p| p.remove_child(name_bytes));
            let dst_child = inner
                .nodes
                .get_mut(&dparent_id)
                .and_then(|p| p.remove_child(newname_bytes));

            let (sid, did) = match (src_child, dst_child) {
                (Some(s), Some(d)) => (s, d),
                _ => {
                    log::error!(
                        "RENAME_EXCHANGE: in-memory children missing after successful renameat2"
                    );
                    reply.error(Errno::EIO);
                    return;
                }
            };
            let (src_name_old, src_parent_old) = match inner.nodes.get(&sid) {
                Some(n) => (n.name.clone(), n.parent),
                None => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            let (dst_name_old, dst_parent_old) = match inner.nodes.get(&did) {
                Some(n) => (n.name.clone(), n.parent),
                None => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            if let Some(snode) = inner.nodes.get_mut(&sid) {
                snode.name = dst_name_old.clone();
                snode.name_hash = crate::node::fnv1a_name_hash_pub(&snode.name);
                snode.parent = dst_parent_old;
                if snode.is_dir() {
                    snode.mark_unloaded();
                }
            }
            if let Some(dnode) = inner.nodes.get_mut(&did) {
                dnode.name = src_name_old.clone();
                dnode.name_hash = crate::node::fnv1a_name_hash_pub(&dnode.name);
                dnode.parent = src_parent_old;
                if dnode.is_dir() {
                    dnode.mark_unloaded();
                }
            }

            if let Some(p) = inner.nodes.get_mut(&dparent_id) {
                p.insert_child(newname_bytes.to_vec(), sid);
            }
            if let Some(p) = inner.nodes.get_mut(&sparent_id) {
                p.insert_child(name_bytes.to_vec(), did);
            }
        } else {
            // Remove destination node if it exists (regular rename replaces it)
            if let Some(dst_id) = inner.do_lookup_file(newparent, Some(newname_bytes), &self.config)
                && !inner.is_whiteout_or_missing(&dst_id)
            {
                if let Some(node) = inner.nodes.get(&dst_id) {
                    let key = InodeKey {
                        ino: node.tmp_ino,
                        dev: node.tmp_dev,
                    };
                    inner.inodes.remove_node_id(&key, dst_id);
                }
                if let Some(p) = inner.nodes.get_mut(&dparent_id) {
                    p.remove_child(newname_bytes);
                }
                inner.nodes.remove(&dst_id);
            }

            let removed = inner
                .nodes
                .get_mut(&sparent_id)
                .and_then(|p| p.remove_child(name_bytes));
            if let Some(child_id) = removed {
                if let Some(child) = inner.nodes.get_mut(&child_id) {
                    child.name = newname_bytes.to_vec();
                    child.name_hash = crate::node::fnv1a_name_hash_pub(newname_bytes);
                    child.parent = Some(dparent_id);
                }
                if let Some(p) = inner.nodes.get_mut(&dparent_id) {
                    p.insert_child(newname_bytes.to_vec(), child_id);
                }
            }
        }

        if flags & 2 == 0 && src_last_layer > 0 {
            let sparent_path = inner.node_path(sparent_id);
            let _ = whiteout::create_whiteout(upper_fd, &sparent_path, name_bytes, inner.can_mknod);
        }

        reply.ok();
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let ino = u64::from(ino);
        let newparent = u64::from(newparent);
        let newname_bytes = newname.as_bytes();
        debug!(
            "link(ino={}, newparent={}, newname={:?})",
            ino,
            newparent,
            String::from_utf8_lossy(newname_bytes)
        );

        let mut inner = self.inner.write();
        if newname_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        let src_id = match inner.do_lookup_file(ino, None, &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if let Err(e) = inner.get_node_up(src_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let dparent_id = match inner.do_lookup_file(newparent, None, &self.config) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        // Check if destination already exists
        if let Some(dst_id) = inner.do_lookup_file(newparent, Some(newname_bytes), &self.config)
            && !inner.is_whiteout_or_missing(&dst_id)
        {
            reply.error(Errno::EEXIST);
            return;
        }

        if let Err(e) = inner.get_node_up(dparent_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let src_path = inner.node_path(src_id);
        let dparent_path = inner.node_path(dparent_id);
        let upper_fd = inner.layers[0].ds.root_fd();
        let new_path = OverlayInner::child_path(&dparent_path, newname_bytes);

        // Delete any whiteout at the destination
        let _ = whiteout::delete_whiteout(upper_fd, None, &dparent_path, newname_bytes);

        // Safely resolve both source and destination parents
        let (_src_guard, src_dirfd, c_old) = match safe_parent(upper_fd, &src_path) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let (_dst_guard, dst_dirfd, c_new_link) = match safe_parent(upper_fd, &new_path) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        if let Err(e) = crate::sys::fs::linkat(src_dirfd, &c_old, dst_dirfd, &c_new_link, 0) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let st = match inner.layers[0].ds.statat(
            &new_path,
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS,
        ) {
            Ok(s) => s,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        match inner.create_and_register_child(dparent_id, newname_bytes, &st, false) {
            Some((_child_id, fuse_ino)) => {
                let mut attr = stat_to_attr(&st);
                attr.ino = INodeNo(fuse_ino);
                reply.entry(&self.timeout(), &attr, Generation(0));
            }
            None => reply.error(Errno::ENOMEM),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let ino = u64::from(ino);
        let flags_raw: i32 = flags.0;
        debug!("open(ino={}, flags={:#x})", ino, flags_raw);

        let mut open_flags = flags_raw | libc::O_NOFOLLOW;
        open_flags &= !libc::O_DIRECT;
        if self.config.writeback {
            if (open_flags & libc::O_ACCMODE) == libc::O_WRONLY {
                open_flags = (open_flags & !libc::O_ACCMODE) | libc::O_RDWR;
            }
            open_flags &= !libc::O_APPEND;
        }

        let needs_write = (flags_raw
            & (libc::O_APPEND | libc::O_RDWR | libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC))
            != 0;

        // FAST PATH: read lock when no copy-up is needed (read-only or already on upper).
        {
            let inner = self.inner.read();
            let node_id = match inner.resolve_node(ino) {
                Ok(id) => id,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            let node = match inner.node(&node_id) {
                Ok(n) => n,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            let layer_idx = node.layer_idx;
            let is_low = inner.layers.get(layer_idx).map(|l| l.low).unwrap_or(false);

            if !needs_write || !is_low {
                // No copy-up needed: open directly under read lock
                let path = inner.node_path(node_id);
                let layer = match inner.layer(layer_idx) {
                    Ok(l) => l,
                    Err(e) => {
                        reply.error(Errno::from_i32(e.0));
                        return;
                    }
                };
                match layer.ds.openat(&path, open_flags, 0o700) {
                    Ok(safe_fd) => {
                        let owned_fd = safe_fd.into_owned();
                        drop(inner);
                        self.reply_open_maybe_passthrough(ino, owned_fd, reply);
                        return;
                    }
                    Err(e) => {
                        reply.error(Errno::from_i32(e.0));
                        return;
                    }
                }
            }
        }

        // SLOW PATH: write lock for copy-up (writable open on a lower-layer file).
        let mut inner = self.inner.write();

        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        if let Err(e) = inner.get_node_up(node_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }
        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        match layer.ds.openat(&path, open_flags, 0o700) {
            Ok(safe_fd) => {
                let owned_fd = safe_fd.into_owned();
                drop(inner);
                self.reply_open_maybe_passthrough(ino, owned_fd, reply);
            }
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let fh = u64::from(fh);
        debug!("read(fh={}, offset={}, size={})", fh, offset, size);
        match self.get_file(fh) {
            None => reply.error(Errno::EBADF),
            Some(fd) => {
                let alloc_size = std::cmp::min(size as usize, 1 << 21);
                thread_local! {
                    static READ_BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
                }
                READ_BUF.with(|cell| {
                    let mut buf = cell.borrow_mut();
                    if buf.len() < alloc_size {
                        buf.resize(alloc_size, 0);
                    }
                    match crate::sys::io::pread(
                        fd.as_raw_fd(),
                        &mut buf[..alloc_size],
                        offset as i64,
                    ) {
                        Err(e) => reply.error(Errno::from_i32(e.0)),
                        Ok(n) => reply.data(&buf[..n]),
                    }
                });
            }
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let fh = u64::from(fh);
        debug!("write(fh={}, offset={}, size={})", fh, offset, data.len());
        match self.get_file(fh) {
            None => reply.error(Errno::EBADF),
            Some(fd) => {
                let raw_fd = fd.as_raw_fd();

                // For writepage (cache flush), preserve setuid/setgid bits.
                // The kernel may clear them, but writepage isn't a user write.
                let restore_mode = if write_flags.contains(fuser::WriteFlags::FUSE_WRITE_CACHE) {
                    if let Ok(st) = crate::sys::fs::fstat(raw_fd) {
                        if st.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
                            Some(st.st_mode)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                match crate::sys::io::pwrite(raw_fd, data, offset as i64) {
                    Err(e) => reply.error(Errno::from_i32(e.0)),
                    Ok(n) => {
                        if let Some(mode) = restore_mode {
                            let _ = crate::sys::fs::fchmod(raw_fd, mode);
                        }
                        reply.written(n as u32);
                    }
                }
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let fh = u64::from(fh);
        let had_backing = if let Some(ino) = self.fh_to_ino.write().remove(&fh) {
            let mut backings = self.inode_backings.write();
            if let Some(entry) = backings.get_mut(&ino) {
                entry.1 -= 1;
                if entry.1 == 0 {
                    backings.remove(&ino);
                }
            }
            true
        } else {
            false
        };
        let had_file = self.open_files.write().remove(&fh).is_some();
        debug!(
            "release(fh={}, had_backing={}, had_file={})",
            fh, had_backing, had_file
        );
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        debug!("statfs");
        let inner = self.inner.read();
        if inner.layers.is_empty() {
            reply.error(Errno::ENOSYS);
            return;
        }
        let fd = inner.layers[0].root_fd();
        let svfs = match crate::sys::fs::fstatvfs(fd) {
            Ok(s) => s,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let name_max = if svfs.f_namemax > 4 {
            svfs.f_namemax - 4
        } else {
            svfs.f_namemax
        };
        reply.statfs(
            svfs.f_blocks as u64,
            svfs.f_bfree as u64,
            svfs.f_bavail as u64,
            svfs.f_files as u64,
            svfs.f_ffree as u64,
            svfs.f_bsize as u32,
            name_max as u32,
            svfs.f_frsize as u32,
        );
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let ino = u64::from(ino);
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        debug!("setxattr(ino={}, name={})", ino, name_str);
        if self.config.disable_xattrs {
            reply.error(Errno::ENOSYS);
            return;
        }

        let mut inner = self.inner.write();
        let node_id = match inner.resolve_node_for_write(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        if let Err(e) = inner.get_node_up(node_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let encoded = match xattr::encode_xattr_name(name_str, layer.stat_override_mode()) {
            Some(n) => n,
            None => {
                reply.error(Errno::EPERM);
                return;
            }
        };
        let full_path = crate::sys::openat2::proc_fd_path(inner.layers[0].ds.root_fd(), &path);
        match sxattr::lsetxattr(&full_path, &encoded, value, flags) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let ino = u64::from(ino);
        debug!("getxattr(ino={}, name={:?}, size={})", ino, name, size);
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        if self.config.disable_xattrs {
            reply.error(Errno::ENOTSUP);
            return;
        }

        let inner = self.inner.read();
        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let encoded = match xattr::encode_xattr_name(name_str, layer.stat_override_mode()) {
            Some(n) => n,
            None => {
                reply.error(Errno::ENODATA);
                return;
            }
        };

        if size == 0 {
            let mut buf = vec![0u8; 65536];
            match layer.ds.getxattr(&path, &encoded, &mut buf) {
                Ok(s) => reply.size(s as u32),
                Err(e) => reply.error(Errno::from_i32(e.0)),
            }
        } else {
            let alloc_size = std::cmp::min(size as usize, 65536);
            let mut buf = vec![0u8; alloc_size];
            match layer.ds.getxattr(&path, &encoded, &mut buf) {
                Ok(s) => {
                    buf.truncate(s);
                    reply.data(&buf);
                }
                Err(e) => reply.error(Errno::from_i32(e.0)),
            }
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let ino = u64::from(ino);
        debug!("listxattr(ino={}, size={})", ino, size);
        if self.config.disable_xattrs {
            reply.error(Errno::ENOTSUP);
            return;
        }

        let inner = self.inner.read();
        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let mut buf = vec![
            0u8;
            if size == 0 {
                65536
            } else {
                std::cmp::min(size as usize, 65536)
            }
        ];
        match layer.ds.listxattr(&path, &mut buf) {
            Ok(s) => {
                buf.truncate(s);
                let filtered = xattr::filter_xattr_list(&buf, layer.stat_override_mode());
                if size == 0 {
                    reply.size(filtered.len() as u32);
                } else if filtered.len() > size as usize {
                    reply.error(Errno::ERANGE);
                } else {
                    reply.data(&filtered);
                }
            }
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let ino = u64::from(ino);
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        debug!("removexattr(ino={}, name={})", ino, name_str);
        if self.config.disable_xattrs {
            reply.error(Errno::ENOSYS);
            return;
        }

        let mut inner = self.inner.write();
        let node_id = match inner.resolve_node_for_write(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        if let Err(e) = inner.get_node_up(node_id) {
            reply.error(Errno::from_i32(e.0));
            return;
        }

        let path = inner.node_path(node_id);
        let (_node, layer) = match inner.node_and_layer(node_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let encoded = match xattr::encode_xattr_name(name_str, layer.stat_override_mode()) {
            Some(n) => n,
            None => {
                reply.error(Errno::EPERM);
                return;
            }
        };
        let full_path = crate::sys::openat2::proc_fd_path(inner.layers[0].ds.root_fd(), &path);
        match sxattr::lremovexattr(&full_path, &encoded) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: fuser::AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent = u64::from(parent);
        let name_bytes = name.as_bytes();
        debug!(
            "create(parent={}, name={:?}, mode={:#o})",
            parent,
            String::from_utf8_lossy(name_bytes),
            mode
        );

        let mut inner = self.inner.write();
        if name_bytes.len() > inner.get_fs_namemax() {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }

        let is_whiteout =
            if let Some(eid) = inner.do_lookup_file(parent, Some(name_bytes), &self.config) {
                if !inner.is_whiteout_or_missing(&eid) {
                    reply.error(Errno::EEXIST);
                    return;
                }
                true
            } else {
                // do_lookup_file returns None for whiteouts (they're in the
                // whiteout set, not as nodes). Check the set so the
                // whiteout-aware creation path handles on-disk cleanup.
                let parent_id = inner.lookup_node_id(parent);
                parent_id
                    .and_then(|pid| inner.nodes.get(&pid))
                    .map(|p| p.is_whiteout(name_bytes))
                    .unwrap_or(false)
            };

        let (pnode_id, pnode_path, upper_fd, child_path) =
            match inner.prepare_create_parent(parent, name_bytes, &self.config) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };

        #[allow(unused_mut)]
        let mut open_flags = flags | libc::O_CREAT | libc::O_NOFOLLOW;
        open_flags &= !libc::O_DIRECT;
        if self.config.writeback {
            if (open_flags & libc::O_ACCMODE) == libc::O_WRONLY {
                open_flags = (open_flags & !libc::O_ACCMODE) | libc::O_RDWR;
            }
            open_flags &= !libc::O_APPEND;
        }

        let fd = if !is_whiteout {
            match inner.layers[0].ds.openat(&child_path, open_flags, mode) {
                Ok(f) => f,
                Err(e) => {
                    warn!(
                        "create({}, {:?}): openat failed: {}",
                        parent,
                        String::from_utf8_lossy(name_bytes),
                        e
                    );
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }
        } else {
            let wd_name = format!("{}", inner.next_wd_counter());
            let _wd_fd = match crate::sys::openat2::safe_openat(
                inner.workdir_fd,
                wd_name.as_bytes(),
                open_flags,
                mode,
            ) {
                Ok(f) => f,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            let c_wd = cstring!(wd_name.as_str(), reply);
            // Safely resolve destination parent for rename
            let (_dst_guard, dst_dirfd, c_dst_name) = match safe_parent(upper_fd, &child_path) {
                Ok(v) => v,
                Err(e) => {
                    let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            if let Err(e) =
                crate::sys::fs::renameat(inner.workdir_fd, &c_wd, dst_dirfd, &c_dst_name)
            {
                let _ = crate::sys::fs::unlinkat(inner.workdir_fd, &c_wd, 0);
                reply.error(Errno::from_i32(e.0));
                return;
            }
            let _ = whiteout::delete_whiteout(upper_fd, Some(dst_dirfd), &pnode_path, name_bytes);
            match inner.layers[0].ds.openat(
                &child_path,
                (open_flags & !libc::O_CREAT) | libc::O_RDWR,
                mode,
            ) {
                Ok(f) => f,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            }
        };
        let host_uid = inner.map_uid(req.uid(), &self.config);
        let host_gid = inner.map_gid(req.gid(), &self.config);
        let _ = crate::sys::fs::fchown(fd.as_raw_fd(), host_uid, host_gid);
        inner.inherit_acl(pnode_id, fd.as_raw_fd(), &self.config);

        let st =
            match inner.layers[0]
                .ds
                .fstat(fd.as_raw_fd(), &child_path, libc::STATX_BASIC_STATS)
            {
                Ok(s) => s,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };

        match inner.create_and_register_child(pnode_id, name_bytes, &st, false) {
            Some((_child_id, fuse_ino)) => {
                let owned_fd = fd.into_owned();
                let mut attr = stat_to_attr(&st);
                attr.ino = INodeNo(fuse_ino);
                let mut fuse_flags = FopenFlags::empty();
                if self.config.timeout > 0.0 {
                    fuse_flags |= FopenFlags::FOPEN_KEEP_CACHE;
                }

                if self.passthrough_enabled.load(Ordering::Relaxed) {
                    match reply.open_backing(&owned_fd) {
                        Ok(backing_id) => {
                            let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                            let backing_id = Arc::new(backing_id);
                            self.inode_backings
                                .write()
                                .insert(fuse_ino, (Arc::clone(&backing_id), 1));
                            self.open_files.write().insert(fh, Arc::new(owned_fd));
                            self.fh_to_ino.write().insert(fh, fuse_ino);
                            // FOPEN_KEEP_CACHE is incompatible with passthrough
                            reply.created_passthrough(
                                &self.timeout(),
                                &attr,
                                Generation(0),
                                FileHandle(fh),
                                FopenFlags::empty(),
                                &backing_id,
                            );
                            return;
                        }
                        Err(e) => {
                            info!("passthrough disabled at runtime (create): {}", e);
                            self.passthrough_enabled.store(false, Ordering::Relaxed);
                            node::STAT_PASSTHROUGH.store(false, Ordering::Relaxed);
                        }
                    }
                }

                let fh = self.alloc_fh(owned_fd);
                reply.created(
                    &self.timeout(),
                    &attr,
                    Generation(0),
                    FileHandle(fh),
                    fuse_flags,
                );
            }
            None => reply.error(Errno::ENOMEM),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let ino = u64::from(ino);
        debug!("opendir(ino={})", ino);
        let mut inner = self.inner.write();

        if ino == u64::from(INodeNo::ROOT) {
            inner.ensure_root_loaded(&self.config);
        }

        let node_id = match inner.lookup_node_id(ino) {
            Some(id) => id,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        if !inner
            .nodes
            .get(&node_id)
            .map(|n| n.is_dir())
            .unwrap_or(false)
        {
            reply.error(Errno::ENOTDIR);
            return;
        }

        if !inner
            .nodes
            .get(&node_id)
            .map(|n| n.is_loaded())
            .unwrap_or(true)
        {
            inner.reload_dir(node_id, &self.config);
        }

        let entries = inner.build_dir_entries(node_id, &self.config);
        let dh = self.alloc_dh(DirHandle { entries });
        let mut fuse_flags = FopenFlags::empty();
        if self.config.timeout > 0.0 {
            fuse_flags |= FopenFlags::FOPEN_KEEP_CACHE;
        }
        reply.opened(FileHandle(dh), fuse_flags);
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let fh = u64::from(fh);
        debug!("readdir(fh={}, offset={})", fh, offset);
        let dirs = self.open_dirs.read();
        let dh = match dirs.get(&fh) {
            Some(d) => d,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };
        let offset = offset as usize;
        for (i, entry) in dh.entries.iter().enumerate().skip(offset) {
            let kind = mode_to_filetype(entry.mode);
            if reply.add(
                INodeNo(entry.ino),
                (i + 1) as u64,
                kind,
                OsStr::from_bytes(&entry.name),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let fh = u64::from(fh);
        debug!("readdirplus(fh={}, offset={})", fh, offset);
        let dirs = self.open_dirs.read();
        let dh = match dirs.get(&fh) {
            Some(d) => d,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };
        let offset = offset as usize;
        let ttl = Duration::from_secs_f64(self.config.timeout);

        // Collect entries we need to emit (clone to release dirs lock before taking inner lock)
        let entries: Vec<_> = dh
            .entries
            .iter()
            .enumerate()
            .skip(offset)
            .map(|(i, e)| (i, e.name.clone(), e.ino, e.mode, e.attr, e.node_id))
            .collect();
        drop(dirs);

        // Register entries in inode table so FUSE inodes match what lookup would return
        let mut inner = self.inner.write();
        for (i, name, raw_ino, mode, attr, node_id) in &entries {
            let fuse_ino = if let Some(nid) = node_id {
                if let Some(node) = inner.nodes.get(nid) {
                    let tmp_ino = node.tmp_ino;
                    let tmp_dev = node.tmp_dev;
                    let nmode = node.mode;
                    let oi = &mut *inner;
                    if let Some(ino_val) =
                        oi.inodes.register(&oi.nodes, *nid, tmp_ino, tmp_dev, nmode)
                    {
                        let key = InodeKey {
                            ino: tmp_ino,
                            dev: tmp_dev,
                        };
                        oi.inodes.inc_lookup(&key);
                        ino_val
                    } else {
                        *raw_ino
                    }
                } else {
                    *raw_ino
                }
            } else {
                *raw_ino
            };

            let mut a = match attr {
                Some(a) => *a,
                None => FileAttr {
                    ino: INodeNo(fuse_ino),
                    size: 0,
                    blocks: 0,
                    atime: UNIX_EPOCH,
                    mtime: UNIX_EPOCH,
                    ctime: UNIX_EPOCH,
                    crtime: UNIX_EPOCH,
                    kind: mode_to_filetype(*mode),
                    perm: 0o755,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                },
            };
            a.ino = INodeNo(fuse_ino);
            if reply.add(
                INodeNo(fuse_ino),
                (*i + 1) as u64,
                OsStr::from_bytes(name),
                &ttl,
                &a,
                Generation(0),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let fh = u64::from(fh);
        debug!("releasedir(fh={})", fh);
        self.open_dirs.write().remove(&fh);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let fh = u64::from(fh);
        debug!("fsync(fh={}, datasync={})", fh, datasync);
        if !self.config.fsync {
            reply.error(Errno::ENOSYS);
            return;
        }
        match self.get_file(fh) {
            Some(fd) => {
                let result = if datasync {
                    crate::sys::io::fdatasync(fd.as_raw_fd())
                } else {
                    crate::sys::io::fsync(fd.as_raw_fd())
                };
                match result {
                    Err(e) => reply.error(Errno::from_i32(e.0)),
                    Ok(()) => reply.ok(),
                }
            }
            None => reply.error(Errno::EBADF),
        }
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let ino = u64::from(ino);
        debug!("fsyncdir(ino={}, datasync={})", ino, datasync);
        if !self.config.fsync {
            reply.error(Errno::ENOSYS);
            return;
        }

        let inner = self.inner.read();
        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let node = match inner.node(&node_id) {
            Ok(n) => n,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        if node.layer_idx != 0 || inner.layers.first().map(|l| l.low).unwrap_or(true) {
            reply.ok();
            return;
        }

        let path = inner.node_path(node_id);
        let layer = match inner.layer(node.layer_idx) {
            Ok(l) => l,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        match crate::sys::openat2::safe_openat(
            layer.root_fd(),
            &path,
            libc::O_NOFOLLOW | libc::O_DIRECTORY,
            0,
        ) {
            Ok(fd) => {
                let result = if datasync {
                    crate::sys::io::fdatasync(fd.as_raw_fd())
                } else {
                    crate::sys::io::fsync(fd.as_raw_fd())
                };
                match result {
                    Err(e) => reply.error(Errno::from_i32(e.0)),
                    Ok(()) => reply.ok(),
                }
            }
            Err(e) => reply.error(Errno::from_i32(e.0)),
        }
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let fh = u64::from(fh);
        debug!(
            "fallocate(fh={}, offset={}, length={}, mode={})",
            fh, offset, length, mode
        );
        match self.get_file(fh) {
            None => reply.error(Errno::EBADF),
            Some(fd) => {
                match crate::sys::fs::fallocate(fd.as_raw_fd(), mode, offset as i64, length as i64)
                {
                    Err(e) => reply.error(Errno::from_i32(e.0)),
                    Ok(()) => reply.ok(),
                }
            }
        }
    }

    fn lseek(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let fh = u64::from(fh);
        debug!("lseek(fh={}, offset={}, whence={})", fh, offset, whence);
        match self.get_file(fh) {
            None => reply.error(Errno::EBADF),
            Some(fd) => match crate::sys::io::lseek(fd.as_raw_fd(), offset, whence) {
                Ok(pos) => reply.offset(pos),
                Err(e) => reply.error(Errno::from_i32(e.0)),
            },
        }
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        _ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        _flags: fuser::CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let fh_in = u64::from(fh_in);
        let fh_out = u64::from(fh_out);
        debug!(
            "copy_file_range(fh_in={}, fh_out={}, len={})",
            fh_in, fh_out, len
        );
        let fd_in = match self.get_file(fh_in) {
            Some(f) => f,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };
        let fd_out = match self.get_file(fh_out) {
            Some(f) => f,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };
        let mut off_in = offset_in as i64;
        let mut off_out = offset_out as i64;
        let capped_len = std::cmp::min(len, u32::MAX as u64) as usize;
        match crate::sys::io::copy_file_range(
            fd_in.as_raw_fd(),
            &mut off_in,
            fd_out.as_raw_fd(),
            &mut off_out,
            capped_len,
        ) {
            Err(e) => reply.error(Errno::from_i32(e.0)),
            Ok(n) => reply.written(std::cmp::min(n, u32::MAX as usize) as u32),
        }
    }

    fn ioctl(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: fuser::IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        let ino = u64::from(ino);
        let fh = u64::from(fh);
        debug!("ioctl(ino={}, fh={}, cmd={})", ino, fh, cmd);

        if flags.contains(fuser::IoctlFlags::FUSE_IOCTL_COMPAT) {
            reply.error(Errno::ENOSYS);
            return;
        }

        let mut inner = self.inner.write();

        let node_id = match inner.resolve_node(ino) {
            Ok(id) => id,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        let cmd_ioctl = cmd as libc::Ioctl;
        let mut val: libc::c_long = 0;
        let is_set = cmd_ioctl == libc::FS_IOC_SETVERSION || cmd_ioctl == libc::FS_IOC_SETFLAGS;
        let is_get = cmd_ioctl == libc::FS_IOC_GETVERSION || cmd_ioctl == libc::FS_IOC_GETFLAGS;

        // Custom command: clear and re-scan a directory's children.
        if cmd_ioctl == FUSE_OVFS_IOC_REFRESH_DIR {
            let node = match inner.node(&node_id) {
                Ok(n) => n,
                Err(e) => {
                    reply.error(Errno::from_i32(e.0));
                    return;
                }
            };
            if !node.is_dir() {
                reply.error(Errno::ENOTDIR);
                return;
            }
            let path = inner.node_path(node_id);
            let last_layer = match inner.nodes.get(&node_id) {
                Some(n) => n.last_layer_idx,
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };
            if let Some(node) = inner.nodes.get_mut(&node_id) {
                node.clear_children();
            }
            inner.load_dir_impl(node_id, &path, Some(last_layer), &self.config);
            debug!("ioctl invalidate: directory ino={}", ino);
            reply.ioctl(0, &[]);
            return;
        }

        if !is_set && !is_get {
            reply.error(Errno::ENOSYS);
            return;
        }

        if is_set {
            if let Err(e) = inner.get_node_up(node_id) {
                reply.error(Errno::from_i32(e.0));
                return;
            }
            if in_data.len() >= std::mem::size_of::<libc::c_long>() {
                match in_data[..std::mem::size_of::<libc::c_long>()].try_into() {
                    Ok(bytes) => val = libc::c_long::from_ne_bytes(bytes),
                    Err(_) => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                }
            }
        }

        let node_path = inner.node_path(node_id);
        let node = match inner.node(&node_id) {
            Ok(n) => n,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let is_dir = node.is_dir();
        let layer_idx = node.layer_idx;

        if is_get
            && !is_dir
            && fh != 0
            && let Some(f) = self.get_file(fh)
        {
            if let Err(e) = crate::sys::io::ioctl_long(f.as_raw_fd(), cmd_ioctl, &mut val) {
                reply.error(Errno::from_i32(e.0));
            } else if out_size > 0 {
                reply.ioctl(0, &val.to_ne_bytes());
            } else {
                reply.ioctl(0, &[]);
            }
            return;
        }

        let layer = match inner.layer(layer_idx) {
            Ok(l) => l,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };
        let opened = match layer
            .ds
            .openat(&node_path, libc::O_RDONLY | libc::O_NONBLOCK, 0o755)
        {
            Ok(f) => f,
            Err(e) => {
                reply.error(Errno::from_i32(e.0));
                return;
            }
        };

        if let Err(e) = crate::sys::io::ioctl_long(opened.as_raw_fd(), cmd_ioctl, &mut val) {
            reply.error(Errno::from_i32(e.0));
        } else if out_size > 0 {
            reply.ioctl(0, &val.to_ne_bytes());
        } else {
            reply.ioctl(0, &[]);
        }
    }
}

/// Apply stat override from xattr if the layer has a stat_override_mode set.
/// Only applies to regular files and directories (matching C behavior).
/// Format: "uid:gid:mode" or "uid:gid:mode:type"
fn override_mode(layer: &OvlLayer, fd: RawFd, path: &[u8], st: &mut libc::stat) -> FsResult<()> {
    let file_type = st.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFDIR && file_type != libc::S_IFREG {
        return Ok(());
    }

    let xattr_name = match layer.stat_override_mode() {
        StatOverrideMode::None => return Ok(()),
        StatOverrideMode::User | StatOverrideMode::Containers => {
            datasource::XATTR_OVERRIDE_CONTAINERS_STAT
        }
        StatOverrideMode::Privileged => datasource::XATTR_PRIVILEGED_OVERRIDE_STAT,
    };

    let mut buf = [0u8; 64];
    let len = if fd >= 0 {
        match sxattr::fgetxattr(fd, xattr_name, &mut buf) {
            Ok(n) => n,
            Err(e) if e.0 == libc::ENODATA || e.0 == libc::ENOTSUP => return Ok(()),
            Err(e) => return Err(e),
        }
    } else {
        match layer.ds.getxattr(path, xattr_name, &mut buf) {
            Ok(n) => n,
            Err(e) if e.0 == libc::ENODATA || e.0 == libc::ENOTSUP => return Ok(()),
            Err(e) => return Err(e),
        }
    };

    let s = std::str::from_utf8(&buf[..len]).map_err(|_| FsError(libc::EINVAL))?;
    parse_and_apply_override(s, st)
}

/// Parse uid, gid, mode from an existing override xattr string,
/// falling back to the stat struct values if parsing fails.
fn parse_override_fields(s: &str, st: &libc::stat) -> (u32, u32, u32) {
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() < 3 {
        return (st.st_uid, st.st_gid, st.st_mode & 0o7777);
    }
    let uid = parts[0].parse().unwrap_or(st.st_uid);
    let gid = parts[1].parse().unwrap_or(st.st_gid);
    let mode = u32::from_str_radix(parts[2], 8).unwrap_or(st.st_mode & 0o7777);
    (uid, gid, mode)
}

/// Parse "uid:gid:mode[:type]" and apply to stat struct.
fn parse_and_apply_override(s: &str, st: &mut libc::stat) -> FsResult<()> {
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() < 3 {
        return Err(FsError(libc::EINVAL));
    }

    let uid: u32 = parts[0].parse().map_err(|_| FsError(libc::EINVAL))?;
    let gid: u32 = parts[1].parse().map_err(|_| FsError(libc::EINVAL))?;
    let mode: u32 = u32::from_str_radix(parts[2], 8).map_err(|_| FsError(libc::EINVAL))?;

    let final_mode = if parts.len() == 4 {
        let type_str = parts[3];
        if type_str.starts_with("dir") {
            mode | libc::S_IFDIR
        } else if type_str.starts_with("file") {
            mode | libc::S_IFREG
        } else if type_str.starts_with("symlink") {
            mode | libc::S_IFLNK
        } else if type_str.starts_with("pipe") {
            mode | libc::S_IFIFO
        } else if type_str.starts_with("socket") {
            mode | libc::S_IFSOCK
        } else if let Some(rest) = type_str.strip_prefix("block") {
            if let Some(dev) = parse_device(rest) {
                st.st_rdev = dev;
            }
            mode | libc::S_IFBLK
        } else if let Some(rest) = type_str.strip_prefix("char") {
            if let Some(dev) = parse_device(rest) {
                st.st_rdev = dev;
            }
            mode | libc::S_IFCHR
        } else {
            return Err(FsError(libc::EINVAL));
        }
    } else {
        mode | (st.st_mode & libc::S_IFMT)
    };

    st.st_uid = uid;
    st.st_gid = gid;
    st.st_mode = final_mode;
    Ok(())
}

/// Parse "MAJ:MIN" device string into a dev_t.
fn parse_device(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts[1].parse().ok()?;
    Some(libc::makedev(major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_override_3_fields() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFREG | 0o644;
        parse_and_apply_override("1000:1000:755", &mut st).unwrap();
        assert_eq!(st.st_uid, 1000);
        assert_eq!(st.st_gid, 1000);
        assert_eq!(st.st_mode, libc::S_IFREG | 0o755);
    }

    #[test]
    fn test_parse_override_with_dir_type() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFREG | 0o644;
        parse_and_apply_override("0:0:755:dir", &mut st).unwrap();
        assert_eq!(st.st_uid, 0);
        assert_eq!(st.st_gid, 0);
        assert_eq!(st.st_mode, libc::S_IFDIR | 0o755);
    }

    #[test]
    fn test_parse_override_with_file_type() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFDIR | 0o755;
        parse_and_apply_override("500:500:644:file", &mut st).unwrap();
        assert_eq!(st.st_uid, 500);
        assert_eq!(st.st_gid, 500);
        assert_eq!(st.st_mode, libc::S_IFREG | 0o644);
    }

    #[test]
    fn test_parse_override_block_device() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFREG | 0o644;
        parse_and_apply_override("0:0:660:block8:0", &mut st).unwrap();
        assert_eq!(st.st_uid, 0);
        assert_eq!(st.st_gid, 0);
        assert_eq!(st.st_mode, libc::S_IFBLK | 0o660);
        assert_eq!(libc::major(st.st_rdev), 8);
        assert_eq!(libc::minor(st.st_rdev), 0);
    }

    #[test]
    fn test_parse_override_char_device() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFREG | 0o644;
        parse_and_apply_override("0:6:666:char1:3", &mut st).unwrap();
        assert_eq!(st.st_uid, 0);
        assert_eq!(st.st_gid, 6);
        assert_eq!(st.st_mode, libc::S_IFCHR | 0o666);
        assert_eq!(libc::major(st.st_rdev), 1);
        assert_eq!(libc::minor(st.st_rdev), 3);
    }

    #[test]
    fn test_parse_override_symlink() {
        let mut st = crate::sys::fs::zeroed_stat();
        st.st_mode = libc::S_IFREG | 0o644;
        parse_and_apply_override("0:0:777:symlink", &mut st).unwrap();
        assert_eq!(st.st_mode, libc::S_IFLNK | 0o777);
    }

    #[test]
    fn test_parse_override_invalid_too_few_fields() {
        let mut st = crate::sys::fs::zeroed_stat();
        assert!(parse_and_apply_override("1000:1000", &mut st).is_err());
    }

    #[test]
    fn test_parse_override_invalid_type() {
        let mut st = crate::sys::fs::zeroed_stat();
        assert!(parse_and_apply_override("0:0:644:bogus", &mut st).is_err());
    }

    #[test]
    fn test_parse_override_invalid_uid() {
        let mut st = crate::sys::fs::zeroed_stat();
        assert!(parse_and_apply_override("abc:0:644", &mut st).is_err());
    }

    #[test]
    fn test_parse_device() {
        let dev = parse_device("8:0").unwrap();
        assert_eq!(libc::major(dev), 8);
        assert_eq!(libc::minor(dev), 0);

        let dev = parse_device("1:3").unwrap();
        assert_eq!(libc::major(dev), 1);
        assert_eq!(libc::minor(dev), 3);

        assert!(parse_device("").is_none());
        assert!(parse_device("abc").is_none());
    }
}

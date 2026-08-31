// SPDX-License-Identifier: GPL-2.0-or-later
//
// Node and inode management for the overlay filesystem.
//
// Uses a NodeId-based arena instead of raw pointers.
// All nodes live in a NodeArena (HashMap<NodeId, OvlNode>), referenced by
// opaque NodeId handles. Parent/child relationships use NodeIds.
//
// The FUSE protocol uses inode numbers to identify files. We maintain:
// - OvlIno: represents a unique (ino, dev) pair, tracks FUSE lookup count
// - OvlNode: represents a named entry in the overlay tree, linked to an OvlIno
//
// The FUSE inode number exposed to the kernel equals the underlying filesystem's
// st_ino (matching the C code's ovl_node_get_ino behavior).

use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Directory state for an overlay node.
/// Replaces the old `children: Option<HashMap> + loaded: bool` pattern,
/// making it impossible for non-directories to have children.
pub enum DirState {
    /// Not a directory (regular file, symlink, device, etc.).
    NotADir,
    /// A directory. `loaded` tracks whether the children map is exhaustive
    /// (fully scanned from disk). When `loaded=false`, known children are
    /// still valid but missing names may exist on lower layers.
    /// `whiteouts` tracks names that are hidden by a whiteout marker on an
    /// upper layer, without requiring a full OvlNode allocation per whiteout.
    Dir {
        children: FxHashMap<Vec<u8>, NodeId>,
        whiteouts: FxHashSet<Vec<u8>>,
        loaded: bool,
    },
}

/// Global node/inode statistics (for SIGUSR1 reporting).
pub static STAT_NODES: AtomicU64 = AtomicU64::new(0);
pub static STAT_INODES: AtomicU64 = AtomicU64::new(0);
/// Whether FUSE passthrough was negotiated (set by init(), read by SIGUSR1).
pub static STAT_PASSTHROUGH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Opaque handle for a node in the arena. Never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

/// Key for the inode hash table: (ino, dev) pair from the underlying filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeKey {
    pub ino: u64,
    pub dev: u64,
}

/// Arena that owns all OvlNode instances. Nodes are accessed by NodeId.
pub struct NodeArena {
    map: FxHashMap<NodeId, OvlNode>,
    next_id: u64,
}

impl NodeArena {
    pub fn new() -> Self {
        NodeArena {
            map: FxHashMap::default(),
            next_id: 1,
        }
    }

    /// Insert a node into the arena. Returns its NodeId.
    pub fn insert(&mut self, node: OvlNode) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        STAT_NODES.fetch_add(1, Ordering::Relaxed);
        self.map.insert(id, node);
        id
    }

    /// Get a shared reference to a node.
    pub fn get(&self, id: &NodeId) -> Option<&OvlNode> {
        self.map.get(id)
    }

    /// Get a mutable reference to a node.
    pub fn get_mut(&mut self, id: &NodeId) -> Option<&mut OvlNode> {
        self.map.get_mut(id)
    }

    /// Remove a node from the arena, returning it. Triggers Drop (cleanup).
    pub fn remove(&mut self, id: &NodeId) -> Option<OvlNode> {
        let node = self.map.remove(id);
        if node.is_some() {
            STAT_NODES.fetch_sub(1, Ordering::Relaxed);
        }
        node
    }

    /// Check if a node exists.
    pub fn contains_key(&self, id: &NodeId) -> bool {
        self.map.contains_key(id)
    }
}

/// Represents a unique inode in the overlay. Multiple OvlNodes (hardlinks)
/// can reference the same OvlIno.
pub struct OvlIno {
    /// NodeIds of nodes sharing this inode (hardlinks). HashSet for O(1) removal.
    pub nodes: FxHashSet<NodeId>,
    /// FUSE lookup count, decremented by forget(). Atomic to allow inc under read lock.
    pub lookups: std::sync::atomic::AtomicI64,
    /// File mode (used for type detection).
    pub mode: u32,
    /// The FUSE inode number assigned to this entry.
    pub fuse_ino: u64,
    /// True if this inode represents a lower-layer hardlink that was broken
    /// apart so each path gets its own FUSE inode.  Entry timeout is forced
    /// to zero so the kernel re-LOOKUPs and discovers the independent inode.
    pub underlying_hardlink: bool,
}

/// Represents a single named entry in the overlay directory tree.
pub struct OvlNode {
    /// Parent node (None for root).
    pub parent: Option<NodeId>,
    /// Directory state: not-a-dir, unloaded, or loaded with children map.
    pub dir_state: DirState,
    /// The layer this node resides on.
    pub layer_idx: usize,
    /// Index of the last layer where this name exists (for whiteout decisions).
    pub last_layer_idx: usize,
    /// Inode number from the underlying filesystem.
    pub tmp_ino: u64,
    /// Device number from the underlying filesystem.
    pub tmp_dev: u64,
    /// Link count from the underlying filesystem.  Used to detect lower-layer
    /// hardlinks at registration time so each alias gets its own FUSE inode.
    pub tmp_nlink: u64,
    /// The entry name (basename). Full path is computed on-demand via compute_path().
    pub name: Vec<u8>,
    /// When a node is hidden (moved to workdir for deferred deletion),
    /// this stores the temporary name used for cleanup in Drop.
    pub hidden_path: Option<String>,
    /// File descriptor for hidden nodes (moved to workdir).
    pub hidden_dirfd: i32,
    /// Hash of the name.
    pub name_hash: u64,
    /// Number of subdirectory links (for st_nlink).
    pub n_links: usize,
    /// File mode (S_IFREG, S_IFLNK, S_IFDIR, etc.) for readdir d_type.
    pub mode: u32,

    // Bit flags
    pub do_unlink: bool,
    pub do_rmdir: bool,
    pub hidden: bool,
}

impl OvlNode {
    /// Create a new node (not yet in the arena, call arena.insert() after).
    /// Set `parent` after insertion to link into the tree. Path is computed
    /// lazily via `compute_path()`.
    pub fn new(name: Vec<u8>, layer_idx: usize, ino: u64, dev: u64, is_dir: bool) -> Self {
        let name_hash = fnv1a_name_hash(&name);

        let dir_state = if is_dir {
            DirState::Dir {
                children: FxHashMap::default(),
                whiteouts: FxHashSet::default(),
                loaded: false,
            }
        } else {
            DirState::NotADir
        };

        OvlNode {
            parent: None,
            dir_state,
            layer_idx,
            last_layer_idx: layer_idx,
            tmp_ino: ino,
            tmp_dev: dev,
            tmp_nlink: 1,
            name,
            hidden_path: None,
            hidden_dirfd: -1,
            name_hash,
            n_links: 0,
            mode: if is_dir { libc::S_IFDIR } else { 0 },
            do_unlink: false,
            do_rmdir: false,
            hidden: false,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.dir_state, DirState::Dir { .. })
    }

    pub fn is_loaded(&self) -> bool {
        matches!(self.dir_state, DirState::Dir { loaded: true, .. })
    }

    pub fn mark_loaded(&mut self) {
        if let DirState::Dir { loaded, .. } = &mut self.dir_state {
            *loaded = true;
        }
    }

    /// Mark directory as needing re-scan. Preserves existing children;
    /// they remain valid, but missing names may exist on lower layers.
    pub fn mark_unloaded(&mut self) {
        if let DirState::Dir { loaded, .. } = &mut self.dir_state {
            *loaded = false;
        }
    }

    /// Look up a child by name, returning its NodeId.
    pub fn get_child(&self, name: &[u8]) -> Option<NodeId> {
        match &self.dir_state {
            DirState::Dir { children, .. } => children.get(name).copied(),
            DirState::NotADir => None,
        }
    }

    /// Get a reference to the children map (directories only).
    pub fn children(&self) -> Option<&FxHashMap<Vec<u8>, NodeId>> {
        match &self.dir_state {
            DirState::Dir { children, .. } => Some(children),
            DirState::NotADir => None,
        }
    }

    /// Get a mutable reference to the children map (directories only).
    pub fn children_mut(&mut self) -> Option<&mut FxHashMap<Vec<u8>, NodeId>> {
        match &mut self.dir_state {
            DirState::Dir { children, .. } => Some(children),
            DirState::NotADir => None,
        }
    }

    /// Insert a child NodeId. Returns the old child's NodeId if one existed.
    /// Also removes any whiteout for this name since the child now exists.
    pub fn insert_child(&mut self, name: Vec<u8>, child_id: NodeId) -> Option<NodeId> {
        if let DirState::Dir {
            children,
            whiteouts,
            ..
        } = &mut self.dir_state
        {
            whiteouts.remove(&name);
            return children.insert(name, child_id);
        }
        None
    }

    /// Remove a child by name, returning its NodeId.
    pub fn remove_child(&mut self, name: &[u8]) -> Option<NodeId> {
        self.children_mut()?.remove(name)
    }

    /// Check if a name is whiteout (deleted by an upper layer).
    pub fn is_whiteout(&self, name: &[u8]) -> bool {
        match &self.dir_state {
            DirState::Dir { whiteouts, .. } => whiteouts.contains(name),
            DirState::NotADir => false,
        }
    }

    /// Mark a name as whiteout (deleted by an upper layer).
    pub fn insert_whiteout(&mut self, name: Vec<u8>) {
        if let DirState::Dir { whiteouts, .. } = &mut self.dir_state {
            whiteouts.insert(name);
        }
    }
}

impl Drop for OvlNode {
    fn drop(&mut self) {
        // Clean up hidden files (moved to workdir for deferred deletion)
        if let Some(ref path) = self.hidden_path
            && let Ok(c_path) = std::ffi::CString::new(path.as_bytes())
        {
            if self.do_unlink {
                let _ = crate::sys::fs::unlinkat(self.hidden_dirfd, &c_path, 0);
            }
            if self.do_rmdir {
                let _ = crate::sys::fs::unlinkat(self.hidden_dirfd, &c_path, libc::AT_REMOVEDIR);
            }
        }
    }
}

/// Compute a FUSE inode number from an (ino, dev) pair.
/// When all layers are on the same device, we use the raw inode number.
/// When layers span devices, we hash (ino, dev) to produce a unique-ish value.
/// The result must never be 0 or 1 (FUSE_ROOT_ID).
pub fn compute_fuse_ino(ino: u64, dev: u64, same_device: bool) -> u64 {
    if same_device {
        if ino <= 1 { ino + 2 } else { ino }
    } else {
        let mut hash = ino;
        hash ^= dev.wrapping_mul(0x9e3779b97f4a7c15);
        hash = hash.wrapping_mul(0x517cc1b727220a95);
        hash ^= hash >> 32;
        if hash <= 1 { hash + 2 } else { hash }
    }
}

/// The inode table: maps (ino, dev) pairs to OvlIno structs.
pub struct InodeTable {
    /// Map from (ino, dev) key to a heap-allocated OvlIno.
    table: FxHashMap<InodeKey, Box<OvlIno>>,
    /// Reverse map from FUSE inode number to InodeKey.
    fuse_map: FxHashMap<u64, InodeKey>,
    /// Reverse map from NodeId to InodeKey (for broken hardlinks).
    node_map: FxHashMap<NodeId, InodeKey>,
    /// Whether all layers are on the same device.
    same_device: bool,
    /// Fallback counter for collision resolution.
    next_fallback: u64,
}

impl InodeTable {
    pub fn new() -> Self {
        STAT_INODES.store(0, Ordering::Relaxed);
        InodeTable {
            table: FxHashMap::default(),
            fuse_map: FxHashMap::default(),
            node_map: FxHashMap::default(),
            same_device: true,
            next_fallback: 0x8000_0000_0000_0000,
        }
    }

    pub fn set_same_device(&mut self, same: bool) {
        self.same_device = same;
    }

    /// Look up an OvlIno by its FUSE inode number.
    pub fn fuse_to_ino(&self, fuse_ino: u64) -> Option<&OvlIno> {
        let key = self.fuse_map.get(&fuse_ino)?;
        self.table.get(key).map(|b| b.as_ref())
    }

    /// Look up by InodeKey.
    pub fn get_by_key(&self, key: &InodeKey) -> Option<&OvlIno> {
        self.table.get(key).map(|b| b.as_ref())
    }

    /// Register a node in the inode table. If an inode with the same (ino, dev)
    /// already exists, the node is linked to it (hardlink tracking).
    /// Returns the FUSE inode number and the InodeKey to use for inc_lookup.
    pub fn register(
        &mut self,
        arena: &NodeArena,
        node_id: NodeId,
        ino: u64,
        dev: u64,
        mode: u32,
        is_lower: bool,
    ) -> Option<(u64, InodeKey)> {
        if let Some(existing_key) = self.node_map.get(&node_id) {
            if let Some(existing_ino) = self.table.get(existing_key) {
                return Some((existing_ino.fuse_ino, *existing_key));
            }
        }

        let key = InodeKey { ino, dev };

        // Break lower-layer hardlinks eagerly.  A lower-layer non-directory with
        // more than one link may be reachable under several paths in the merged
        // tree.  If such aliases shared a FUSE inode we could not tell which path
        // a copy-up/chmod targets, and using the raw inode number as the FUSE
        // inode is unsafe: it is non-deterministic which alias registers first
        // (concurrent readdirplus), and once that node is forgotten the raw
        // number can be reused for a different alias, so the kernel's cached
        // path->inode mapping would resolve to the wrong file.  Giving every
        // lower hardlink alias its own stable, never-reused FUSE inode (as the C
        // implementation does via per-node inode identity) avoids all of this.
        let is_dir_mode = (mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_lower && !is_dir_mode {
            let nlink = arena.get(&node_id).map(|n| n.tmp_nlink).unwrap_or(1);
            if nlink > 1 {
                if let Some(existing_ino) = self.table.get_mut(&key) {
                    existing_ino.nodes.retain(|id| arena.contains_key(id));
                    if !existing_ino.nodes.is_empty() {
                        existing_ino.underlying_hardlink = true;
                    }
                }
                return self.register_broken_hardlink(node_id, key, mode);
            }
        }

        if let Some(existing_ino) = self.table.get_mut(&key) {
            // Prune dead nodes (removed from arena but not yet forgotten)
            existing_ino.nodes.retain(|id| arena.contains_key(id));

            if !existing_ino.nodes.is_empty() {
                // Check if this is a duplicate (same path or directory)
                let new_path = compute_path(arena, node_id);
                for &existing_id in &existing_ino.nodes {
                    if let Some(existing_node) = arena.get(&existing_id)
                        && (existing_node.is_dir() || compute_path(arena, existing_id) == new_path)
                    {
                        return Some((existing_ino.fuse_ino, key));
                    }
                }

                if is_lower {
                    existing_ino.underlying_hardlink = true;
                    return self.register_broken_hardlink(node_id, key, mode);
                }

                // New hardlink to the same physical inode (upper layer)
                existing_ino.nodes.insert(node_id);
                existing_ino.mode = mode;
                return Some((existing_ino.fuse_ino, key));
            }

            // All nodes are dead: the filesystem recycled this inode number.
            // Remove the table entry but keep the fuse_map entry as a
            // tombstone so that compute_fuse_ino's collision check forces a
            // different FUSE inode number.  Reusing the old number would let
            // the kernel serve stale icache data (ESTALE / ENOENT).
            // The tombstone is cleaned up when the kernel sends forget().
            self.table.remove(&key);
            STAT_INODES.fetch_sub(1, Ordering::Relaxed);
        }

        // Compute FUSE inode from the real (ino, dev) pair
        let mut fuse_ino = compute_fuse_ino(key.ino, key.dev, self.same_device);

        // Handle collisions, skipping reserved FUSE inode values 0 and 1
        while self.fuse_map.contains_key(&fuse_ino) || fuse_ino <= 1 {
            fuse_ino = self.next_fallback;
            self.next_fallback = self.next_fallback.wrapping_add(1);
            // Skip reserved values on wraparound
            if self.next_fallback <= 1 {
                self.next_fallback = 2;
            }
        }

        let ino_entry = Box::new(OvlIno {
            nodes: FxHashSet::from_iter([node_id]),
            lookups: std::sync::atomic::AtomicI64::new(0),
            mode,
            fuse_ino,
            underlying_hardlink: false,
        });

        STAT_INODES.fetch_add(1, Ordering::Relaxed);
        self.fuse_map.insert(fuse_ino, key);
        self.table.insert(key, ino_entry);
        Some((fuse_ino, key))
    }

    /// Allocate a separate OvlIno for a lower-layer hardlink so it gets
    /// its own FUSE inode.  Mirrors kernel overlayfs which breaks hardlinks
    /// on copy-up.
    fn register_broken_hardlink(
        &mut self,
        node_id: NodeId,
        _real_key: InodeKey,
        mode: u32,
    ) -> Option<(u64, InodeKey)> {
        // Always allocate from the monotonic fallback counter, never from the
        // raw inode number.  The raw number is shared by every hardlink alias
        // and is recyclable once forgotten; using it here would let a freed
        // number be handed to a different alias, so the kernel's cached
        // path->inode mapping could resolve to the wrong file.  Fallback values
        // are effectively never reused, giving each alias a stable identity.
        let mut fuse_ino = self.next_fallback;
        self.next_fallback = self.next_fallback.wrapping_add(1);
        if self.next_fallback <= 1 {
            self.next_fallback = 2;
        }
        while self.fuse_map.contains_key(&fuse_ino) || fuse_ino <= 1 {
            fuse_ino = self.next_fallback;
            self.next_fallback = self.next_fallback.wrapping_add(1);
            if self.next_fallback <= 1 {
                self.next_fallback = 2;
            }
        }
        let synthetic_key = InodeKey {
            ino: fuse_ino,
            dev: u64::MAX,
        };
        let ino_entry = Box::new(OvlIno {
            nodes: FxHashSet::from_iter([node_id]),
            lookups: std::sync::atomic::AtomicI64::new(0),
            mode,
            fuse_ino,
            underlying_hardlink: true,
        });
        STAT_INODES.fetch_add(1, Ordering::Relaxed);
        self.fuse_map.insert(fuse_ino, synthetic_key);
        self.node_map.insert(node_id, synthetic_key);
        self.table.insert(synthetic_key, ino_entry);
        Some((fuse_ino, synthetic_key))
    }

    /// Check whether a FUSE inode is a broken-out lower-layer hardlink.
    pub fn is_underlying_hardlink(&self, fuse_ino: u64) -> bool {
        self.fuse_to_ino(fuse_ino)
            .map(|ino| ino.underlying_hardlink)
            .unwrap_or(false)
    }

    /// Get the FUSE inode for a given InodeKey (if registered).
    pub fn key_to_fuse_ino(&self, key: &InodeKey) -> Option<u64> {
        self.table.get(key).map(|ino| ino.fuse_ino)
    }

    /// Check if a node is already registered (via natural key or node_map)
    /// and return (fuse_ino, key) if so.  Used by the lookup fast path.
    pub fn lookup_registered(
        &self,
        node_id: NodeId,
        ino: u64,
        dev: u64,
    ) -> Option<(u64, InodeKey)> {
        if let Some(key) = self.node_map.get(&node_id) {
            if let Some(ovl_ino) = self.table.get(key) {
                return Some((ovl_ino.fuse_ino, *key));
            }
        }
        let key = InodeKey { ino, dev };
        let ovl_ino = self.table.get(&key)?;
        if ovl_ino.nodes.contains(&node_id) {
            Some((ovl_ino.fuse_ino, key))
        } else {
            None
        }
    }

    /// Remove a NodeId from the inode entry's node list (e.g., when a hardlink is deleted).
    pub fn remove_node_id(&mut self, key: &InodeKey, node_id: NodeId) {
        if let Some(ino) = self.table.get_mut(key) {
            ino.nodes.remove(&node_id);
        }
    }

    /// Increment the lookup count for a FUSE inode.
    /// Uses atomic operation, safe to call under read lock.
    pub fn inc_lookup(&self, key: &InodeKey) {
        if let Some(ino) = self.table.get(key) {
            ino.lookups.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Process a FUSE forget: decrement lookup count and free if zero.
    pub fn forget(&mut self, fuse_ino: u64, nlookup: u64) -> bool {
        if fuse_ino == u64::from(fuser::INodeNo::ROOT) || fuse_ino == 0 {
            return false;
        }

        let key = match self.fuse_map.get(&fuse_ino) {
            Some(k) => *k,
            None => return false,
        };

        if let Some(ino) = self.table.get_mut(&key) {
            if ino.fuse_ino != fuse_ino {
                // Stale forget for a recycled inode — just clean up the
                // fuse_map tombstone left by register().
                self.fuse_map.remove(&fuse_ino);
                return true;
            }
            let prev = ino.lookups.fetch_sub(nlookup as i64, Ordering::Relaxed);
            if prev - nlookup as i64 <= 0 {
                for nid in &ino.nodes {
                    self.node_map.remove(nid);
                }
                STAT_INODES.fetch_sub(1, Ordering::Relaxed);
                self.fuse_map.remove(&fuse_ino);
                self.table.remove(&key);
            }
            true
        } else {
            // Table entry already removed (recycled inode) — clean up tombstone.
            self.fuse_map.remove(&fuse_ino);
            true
        }
    }
}

/// Compute the path of a node by walking parent pointers.
/// Returns b"." for the root node, b"name" for direct children of root,
/// b"parent/name" for deeper nodes.
pub fn compute_path(arena: &NodeArena, id: NodeId) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut current = id;
    while let Some(node) = arena.get(&current) {
        if node.parent.is_none() {
            if parts.is_empty() {
                return b".".to_vec();
            }
            break;
        }
        parts.push(&node.name);
        current = match node.parent {
            Some(pid) => pid,
            None => break,
        };
    }
    parts.reverse();
    let mut result = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            result.push(b'/');
        }
        result.extend_from_slice(part);
    }
    result
}

/// FNV-1a hash for node names.
pub fn fnv1a_name_hash_pub(name: &[u8]) -> u64 {
    fnv1a_name_hash(name)
}

fn fnv1a_name_hash(name: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_node() {
        let node = OvlNode::new(b"file".to_vec(), 0, 100, 1, false);
        assert_eq!(node.name, b"file");
        assert!(!node.is_dir());
    }

    #[test]
    fn test_create_dir_node() {
        let mut arena = NodeArena::new();
        let mut dir = OvlNode::new(b"dir".to_vec(), 0, 200, 1, true);
        assert!(dir.is_dir());

        let child = OvlNode::new(b"file".to_vec(), 0, 300, 1, false);
        let child_id = arena.insert(child);
        dir.insert_child(b"file".to_vec(), child_id);

        assert!(dir.get_child(b"file").is_some());
        assert!(dir.get_child(b"nonexistent").is_none());
    }

    #[test]
    fn test_node_arena() {
        let mut arena = NodeArena::new();
        let node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let id = arena.insert(node);
        assert!(arena.contains_key(&id));
        assert_eq!(arena.get(&id).unwrap().name, b"a");

        let removed = arena.remove(&id);
        assert!(removed.is_some());
        assert!(!arena.contains_key(&id));
    }

    #[test]
    fn test_inode_table_register() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        let node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let node_id = arena.insert(node);
        let (fuse_ino, _key) = table
            .register(&arena, node_id, 100, 1, 0o100644, false)
            .unwrap();
        assert_eq!(fuse_ino, 100);
    }

    #[test]
    fn test_inode_table_forget() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        let node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let node_id = arena.insert(node);
        let (fuse_ino, _key) = table
            .register(&arena, node_id, 100, 1, 0o100644, false)
            .unwrap();

        table.inc_lookup(&InodeKey { ino: 100, dev: 1 });
        assert!(table.forget(fuse_ino, 1));
    }

    #[test]
    fn test_inode_table_hardlink_upper() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        let node1 = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let id1 = arena.insert(node1);
        let (fuse1, _) = table
            .register(&arena, id1, 100, 1, 0o100644, false)
            .unwrap();

        let node2 = OvlNode::new(b"b".to_vec(), 0, 100, 1, false);
        let id2 = arena.insert(node2);
        let (fuse2, _) = table
            .register(&arena, id2, 100, 1, 0o100644, false)
            .unwrap();

        assert_eq!(fuse1, fuse2);
    }

    #[test]
    fn test_inode_table_hardlink_lower_broken() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        let parent = OvlNode::new(b"root".to_vec(), 0, 1, 1, true);
        let parent_id = arena.insert(parent);

        let mut node1 = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        node1.parent = Some(parent_id);
        let id1 = arena.insert(node1);
        let (fuse1, _) = table.register(&arena, id1, 100, 1, 0o100644, true).unwrap();

        let mut node2 = OvlNode::new(b"b".to_vec(), 0, 100, 1, false);
        node2.parent = Some(parent_id);
        let id2 = arena.insert(node2);
        let (fuse2, _) = table.register(&arena, id2, 100, 1, 0o100644, true).unwrap();

        assert_ne!(fuse1, fuse2);
        assert!(table.is_underlying_hardlink(fuse1));
        assert!(table.is_underlying_hardlink(fuse2));
    }

    // A lower-layer file with nlink > 1 must be broken out into its own FUSE
    // inode on the very first registration, so the raw inode number is never
    // used (nor later reused) as a FUSE inode for a hardlink alias.
    #[test]
    fn test_inode_table_lower_hardlink_broken_eagerly() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        let mut node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        node.tmp_nlink = 2;
        let id = arena.insert(node);
        let (fuse, _) = table.register(&arena, id, 100, 1, 0o100644, true).unwrap();

        // Not the raw inode number, and flagged as a broken hardlink.
        assert_ne!(fuse, 100);
        assert!(table.is_underlying_hardlink(fuse));

        // Re-registering the same node is idempotent (stable per-node inode).
        let (fuse2, _) = table.register(&arena, id, 100, 1, 0o100644, true).unwrap();
        assert_eq!(fuse, fuse2);
    }

    // A lower-layer file with a single link keeps the raw inode number as its
    // FUSE inode (passthrough / ino stability preserved).
    #[test]
    fn test_inode_table_lower_single_link_natural() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        let mut node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        node.tmp_nlink = 1;
        let id = arena.insert(node);
        let (fuse, _) = table.register(&arena, id, 100, 1, 0o100644, true).unwrap();

        assert_eq!(fuse, 100);
        assert!(!table.is_underlying_hardlink(fuse));
    }

    // Helper: resolve a fuse_ino to a node the way overlay::lookup_node_id does.
    fn resolve(table: &InodeTable, arena: &NodeArena, fuse_ino: u64) -> Option<NodeId> {
        let ovl = table.fuse_to_ino(fuse_ino)?;
        ovl.nodes.iter().copied().find(|id| arena.contains_key(id))
    }

    // Build the test-11 tree: three lower hardlinks o/orig, usr/lib/link,
    // usr/share/x/l3, all sharing (ino=500, dev=9). Returns their NodeIds.
    fn build_tree(arena: &mut NodeArena) -> (NodeId, NodeId, NodeId) {
        let root = OvlNode::new(b"".to_vec(), 1, 1, 9, true);
        let root_id = arena.insert(root);
        let mk_dir = |arena: &mut NodeArena, name: &[u8], ino: u64, parent: NodeId| {
            let mut d = OvlNode::new(name.to_vec(), 1, ino, 9, true);
            d.parent = Some(parent);
            let id = arena.insert(d);
            arena
                .get_mut(&parent)
                .unwrap()
                .insert_child(name.to_vec(), id);
            id
        };
        let mk_file = |arena: &mut NodeArena, name: &[u8], parent: NodeId| {
            let mut f = OvlNode::new(name.to_vec(), 1, 500, 9, false);
            f.parent = Some(parent);
            // Three hardlinks share inode 500 in the lower layer.
            f.tmp_nlink = 3;
            let id = arena.insert(f);
            arena
                .get_mut(&parent)
                .unwrap()
                .insert_child(name.to_vec(), id);
            id
        };
        let o = mk_dir(arena, b"o", 10, root_id);
        let usr = mk_dir(arena, b"usr", 11, root_id);
        let lib = mk_dir(arena, b"lib", 12, usr);
        let share = mk_dir(arena, b"share", 13, usr);
        let x = mk_dir(arena, b"x", 14, share);
        let orig = mk_file(arena, b"orig", o);
        let link = mk_file(arena, b"link", lib);
        let l3 = mk_file(arena, b"l3", x);
        (orig, link, l3)
    }

    // Register a lower hardlink the way lookup/readdirplus does and inc its lookup.
    fn reg(table: &mut InodeTable, arena: &NodeArena, id: NodeId) -> u64 {
        let (fuse, key) = table.register(arena, id, 500, 9, 0o100664, true).unwrap();
        table.inc_lookup(&key);
        fuse
    }

    // Every alias must resolve back to its own node, no matter the order of
    // registration and forget cycles.  This mirrors test-11 in test-hardlinks.sh.
    #[test]
    fn test_lower_hardlink_alias_resolution_all_orders() {
        let orders: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for order in orders {
            let mut table = InodeTable::new();
            let mut arena = NodeArena::new();
            let (orig, link, l3) = build_tree(&mut arena);
            let nodes = [orig, link, l3];
            let paths = [
                b"o/orig".to_vec(),
                b"usr/lib/link".to_vec(),
                b"usr/share/x/l3".to_vec(),
            ];

            // Register all three in this order (simulates readdirplus of dirs).
            let mut fuse = [0u64; 3];
            for &i in &order {
                fuse[i] = reg(&mut table, &arena, nodes[i]);
            }

            // Each alias's fuse_ino must resolve to the correct node/path.
            for i in 0..3 {
                let resolved = resolve(&table, &arena, fuse[i]).expect("resolves");
                assert_eq!(
                    compute_path(&arena, resolved),
                    paths[i],
                    "order {:?}: alias {} (fuse {:#x}) resolved to wrong node",
                    order,
                    i,
                    fuse[i]
                );
            }
        }
    }

    // Simulate the kernel forgetting the broken aliases (entry_timeout=0) and
    // then re-looking-up "link" at chmod time.  It must still resolve to link.
    #[test]
    fn test_lower_hardlink_forget_then_relookup() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        let (orig, link, l3) = build_tree(&mut arena);

        // readdirplus registers all three; every lower hardlink is broken out
        // into its own FUSE inode, so none of them shares the raw inode number.
        let f_orig = reg(&mut table, &arena, orig);
        let f_link = reg(&mut table, &arena, link);
        let f_l3 = reg(&mut table, &arena, l3);

        // Broken aliases have entry_timeout 0 -> kernel forgets them.
        assert!(table.is_underlying_hardlink(f_link));
        assert!(table.is_underlying_hardlink(f_l3));
        table.forget(f_link, 1);
        table.forget(f_l3, 1);

        // chmod re-looks-up "link".
        let f_link2 = reg(&mut table, &arena, link);
        let resolved = resolve(&table, &arena, f_link2).expect("resolves");
        assert_eq!(compute_path(&arena, resolved), b"usr/lib/link");
        // And orig must still resolve to orig.
        let r_orig = resolve(&table, &arena, f_orig).expect("resolves");
        assert_eq!(compute_path(&arena, r_orig), b"o/orig");
    }

    #[test]
    fn test_fuse_ino_matches_fs_ino() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        for ino in [100, 200, 40000000, 40000001] {
            let node = OvlNode::new(format!("f{}", ino).into_bytes(), 0, ino, 1, false);
            let node_id = arena.insert(node);
            let (fuse_ino, _key) = table
                .register(&arena, node_id, ino, 1, 0o100644, false)
                .unwrap();
            assert_eq!(fuse_ino, ino);
        }
    }

    #[test]
    fn test_multi_device_no_collision() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        table.set_same_device(false);

        let node1 = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let id1 = arena.insert(node1);
        let (fuse1, _) = table
            .register(&arena, id1, 100, 1, 0o100644, false)
            .unwrap();

        let node2 = OvlNode::new(b"b".to_vec(), 0, 100, 2, false);
        let id2 = arena.insert(node2);
        let (fuse2, _) = table
            .register(&arena, id2, 100, 2, 0o100644, false)
            .unwrap();

        assert_ne!(fuse1, fuse2);
    }

    #[test]
    fn test_compute_path_root() {
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);
        assert_eq!(compute_path(&arena, root_id), b".");
    }

    #[test]
    fn test_compute_path_direct_child() {
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);

        let mut child = OvlNode::new(b"foo".to_vec(), 0, 2, 1, false);
        child.parent = Some(root_id);
        let child_id = arena.insert(child);
        arena
            .get_mut(&root_id)
            .unwrap()
            .insert_child(b"foo".to_vec(), child_id);

        assert_eq!(compute_path(&arena, child_id), b"foo");
    }

    #[test]
    fn test_compute_path_deep_tree() {
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);

        let mut dir_a = OvlNode::new(b"a".to_vec(), 0, 2, 1, true);
        dir_a.parent = Some(root_id);
        let dir_a_id = arena.insert(dir_a);
        arena
            .get_mut(&root_id)
            .unwrap()
            .insert_child(b"a".to_vec(), dir_a_id);

        let mut dir_b = OvlNode::new(b"b".to_vec(), 0, 3, 1, true);
        dir_b.parent = Some(dir_a_id);
        let dir_b_id = arena.insert(dir_b);
        arena
            .get_mut(&dir_a_id)
            .unwrap()
            .insert_child(b"b".to_vec(), dir_b_id);

        let mut file_c = OvlNode::new(b"c".to_vec(), 0, 4, 1, false);
        file_c.parent = Some(dir_b_id);
        let file_c_id = arena.insert(file_c);
        arena
            .get_mut(&dir_b_id)
            .unwrap()
            .insert_child(b"c".to_vec(), file_c_id);

        // Verify compute_path matches stored path for all nodes
        assert_eq!(compute_path(&arena, root_id), b".");
        assert_eq!(compute_path(&arena, dir_a_id), b"a");
        assert_eq!(compute_path(&arena, dir_b_id), b"a/b");
        assert_eq!(compute_path(&arena, file_c_id), b"a/b/c");
    }

    #[test]
    fn test_compute_path_after_rename() {
        // Simulate renaming a/b/c -> a/d/c by changing parent
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);

        let mut dir_a = OvlNode::new(b"a".to_vec(), 0, 2, 1, true);
        dir_a.parent = Some(root_id);
        let dir_a_id = arena.insert(dir_a);

        let mut dir_b = OvlNode::new(b"b".to_vec(), 0, 3, 1, true);
        dir_b.parent = Some(dir_a_id);
        let dir_b_id = arena.insert(dir_b);

        let mut file_c = OvlNode::new(b"c".to_vec(), 0, 4, 1, false);
        file_c.parent = Some(dir_b_id);
        let file_c_id = arena.insert(file_c);
        arena
            .get_mut(&dir_b_id)
            .unwrap()
            .insert_child(b"c".to_vec(), file_c_id);

        // "Rename" dir_b from "b" to "d" (just change name + parent stays)
        arena.get_mut(&dir_b_id).unwrap().name = b"d".to_vec();

        // compute_path reflects the rename immediately, no descendant walk needed
        assert_eq!(compute_path(&arena, dir_b_id), b"a/d");
        assert_eq!(compute_path(&arena, file_c_id), b"a/d/c");
    }

    #[test]
    fn test_compute_path_reparent() {
        // Move dir_b from under dir_a to under root
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);

        let mut dir_a = OvlNode::new(b"a".to_vec(), 0, 2, 1, true);
        dir_a.parent = Some(root_id);
        let dir_a_id = arena.insert(dir_a);

        let mut dir_b = OvlNode::new(b"b".to_vec(), 0, 3, 1, true);
        dir_b.parent = Some(dir_a_id);
        let dir_b_id = arena.insert(dir_b);

        let mut file = OvlNode::new(b"f".to_vec(), 0, 4, 1, false);
        file.parent = Some(dir_b_id);
        let file_id = arena.insert(file);

        assert_eq!(compute_path(&arena, file_id), b"a/b/f");

        // Reparent dir_b to root
        arena.get_mut(&dir_b_id).unwrap().parent = Some(root_id);
        assert_eq!(compute_path(&arena, dir_b_id), b"b");
        assert_eq!(compute_path(&arena, file_id), b"b/f");
    }

    #[test]
    fn test_rename_lazy_paths() {
        // With lazy path computation, rename only updates name + parent.
        // All descendant paths are automatically correct via compute_path().
        let mut arena = NodeArena::new();
        let root = OvlNode::new(b"".to_vec(), 0, 1, 1, true);
        let root_id = arena.insert(root);

        let mut src_parent = OvlNode::new(b"src_parent".to_vec(), 0, 2, 1, true);
        src_parent.parent = Some(root_id);
        let src_parent_id = arena.insert(src_parent);

        let mut dst_parent = OvlNode::new(b"dst_parent".to_vec(), 0, 3, 1, true);
        dst_parent.parent = Some(root_id);
        let dst_parent_id = arena.insert(dst_parent);

        let mut old_dir = OvlNode::new(b"old_dir".to_vec(), 0, 10, 1, true);
        old_dir.parent = Some(src_parent_id);
        let dir_id = arena.insert(old_dir);
        arena
            .get_mut(&src_parent_id)
            .unwrap()
            .insert_child(b"old_dir".to_vec(), dir_id);

        let mut sub_dir = OvlNode::new(b"sub_dir".to_vec(), 0, 20, 1, true);
        sub_dir.parent = Some(dir_id);
        let sub_dir_id = arena.insert(sub_dir);
        arena
            .get_mut(&dir_id)
            .unwrap()
            .insert_child(b"sub_dir".to_vec(), sub_dir_id);

        let mut deep_file = OvlNode::new(b"deep_file".to_vec(), 0, 30, 1, false);
        deep_file.parent = Some(sub_dir_id);
        let deep_file_id = arena.insert(deep_file);
        arena
            .get_mut(&sub_dir_id)
            .unwrap()
            .insert_child(b"deep_file".to_vec(), deep_file_id);

        let mut file_txt = OvlNode::new(b"file.txt".to_vec(), 0, 40, 1, false);
        file_txt.parent = Some(dir_id);
        let file_txt_id = arena.insert(file_txt);
        arena
            .get_mut(&dir_id)
            .unwrap()
            .insert_child(b"file.txt".to_vec(), file_txt_id);

        // Before rename
        assert_eq!(compute_path(&arena, dir_id), b"src_parent/old_dir");
        assert_eq!(
            compute_path(&arena, sub_dir_id),
            b"src_parent/old_dir/sub_dir"
        );
        assert_eq!(
            compute_path(&arena, deep_file_id),
            b"src_parent/old_dir/sub_dir/deep_file"
        );
        assert_eq!(
            compute_path(&arena, file_txt_id),
            b"src_parent/old_dir/file.txt"
        );

        // Rename: just update name + parent. O(1), no descendant walk
        if let Some(node) = arena.get_mut(&dir_id) {
            node.name = b"new_dir".to_vec();
            node.name_hash = fnv1a_name_hash(b"new_dir");
            node.parent = Some(dst_parent_id);
        }

        // All paths automatically correct
        assert_eq!(compute_path(&arena, dir_id), b"dst_parent/new_dir");
        assert_eq!(
            compute_path(&arena, sub_dir_id),
            b"dst_parent/new_dir/sub_dir"
        );
        assert_eq!(
            compute_path(&arena, deep_file_id),
            b"dst_parent/new_dir/sub_dir/deep_file"
        );
        assert_eq!(
            compute_path(&arena, file_txt_id),
            b"dst_parent/new_dir/file.txt"
        );

        // Children maps preserved
        assert!(arena.get(&dir_id).unwrap().get_child(b"sub_dir").is_some());
        assert!(arena.get(&dir_id).unwrap().get_child(b"file.txt").is_some());
        assert!(
            arena
                .get(&sub_dir_id)
                .unwrap()
                .get_child(b"deep_file")
                .is_some()
        );
    }

    #[test]
    fn test_hardlink_removal_still_finds_live_node() {
        // Simulate two hardlinks (perl, perl5.36.0) sharing the same inode.
        // After removing one hardlink, fuse_to_ino should still return the
        // remaining node via the OvlIno.nodes set.
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        // Create parent directory
        let mut parent = OvlNode::new(b"bin".to_vec(), 0, 50, 1, true);
        parent.parent = None;
        let parent_id = arena.insert(parent);

        // Create two hardlinks: perl and perl5.36.0 (same ino=100, dev=1)
        let mut perl = OvlNode::new(b"perl".to_vec(), 0, 100, 1, false);
        perl.parent = Some(parent_id);
        let perl_id = arena.insert(perl);
        arena
            .get_mut(&parent_id)
            .unwrap()
            .insert_child(b"perl".to_vec(), perl_id);

        let mut perl536 = OvlNode::new(b"perl5.36.0".to_vec(), 0, 100, 1, false);
        perl536.parent = Some(parent_id);
        let perl536_id = arena.insert(perl536);
        arena
            .get_mut(&parent_id)
            .unwrap()
            .insert_child(b"perl5.36.0".to_vec(), perl536_id);

        // Register both on upper layer — they share the same (ino, dev) = (100, 1)
        let (fuse1, _) = table
            .register(&arena, perl_id, 100, 1, 0o100755, false)
            .unwrap();
        let (fuse2, _) = table
            .register(&arena, perl536_id, 100, 1, 0o100755, false)
            .unwrap();
        assert_eq!(fuse1, fuse2, "hardlinks must share the same FUSE inode");

        // Verify both nodes are in OvlIno.nodes
        let key = InodeKey { ino: 100, dev: 1 };
        let ovl_ino = table.get_by_key(&key).unwrap();
        assert!(ovl_ino.nodes.contains(&perl_id));
        assert!(ovl_ino.nodes.contains(&perl536_id));

        // Simulate unlink of "perl": remove from OvlIno.nodes and arena
        table.remove_node_id(&key, perl_id);
        arena.remove(&perl_id);

        // The remaining node (perl5.36.0) should still be findable
        let ovl_ino = table.get_by_key(&key).unwrap();
        assert!(
            !ovl_ino.nodes.contains(&perl_id),
            "removed node should not be in nodes set"
        );
        assert!(
            ovl_ino.nodes.contains(&perl536_id),
            "remaining node should still be in nodes set"
        );

        // Iterate through nodes and find the first live one (what lookup_node_id does)
        let live_node = ovl_ino
            .nodes
            .iter()
            .copied()
            .find(|id| arena.contains_key(id));
        assert_eq!(
            live_node,
            Some(perl536_id),
            "should find the remaining live node"
        );
    }
}

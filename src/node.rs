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

    /// Clear all children and whiteouts. Used by cache invalidation to
    /// force a full re-scan of the directory.
    pub fn clear_children(&mut self) {
        if let DirState::Dir {
            children,
            whiteouts,
            ..
        } = &mut self.dir_state
        {
            children.clear();
            whiteouts.clear();
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
    /// Returns the FUSE inode number.
    pub fn register(
        &mut self,
        arena: &NodeArena,
        node_id: NodeId,
        ino: u64,
        dev: u64,
        mode: u32,
    ) -> Option<u64> {
        let key = InodeKey { ino, dev };

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
                        return Some(existing_ino.fuse_ino);
                    }
                }

                // New hardlink to the same physical inode
                existing_ino.nodes.insert(node_id);
                existing_ino.mode = mode;
                return Some(existing_ino.fuse_ino);
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
        });

        STAT_INODES.fetch_add(1, Ordering::Relaxed);
        self.fuse_map.insert(fuse_ino, key);
        self.table.insert(key, ino_entry);
        Some(fuse_ino)
    }

    /// Get the FUSE inode for a given InodeKey (if registered).
    pub fn key_to_fuse_ino(&self, key: &InodeKey) -> Option<u64> {
        self.table.get(key).map(|ino| ino.fuse_ino)
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
        let fuse_ino = table.register(&arena, node_id, 100, 1, 0o100644).unwrap();
        assert_eq!(fuse_ino, 100);
    }

    #[test]
    fn test_inode_table_forget() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        let node = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let node_id = arena.insert(node);
        let fuse_ino = table.register(&arena, node_id, 100, 1, 0o100644).unwrap();

        table.inc_lookup(&InodeKey { ino: 100, dev: 1 });
        assert!(table.forget(fuse_ino, 1));
    }

    #[test]
    fn test_inode_table_hardlink() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();

        let node1 = OvlNode::new(b"a".to_vec(), 0, 100, 1, false);
        let id1 = arena.insert(node1);
        let fuse1 = table.register(&arena, id1, 100, 1, 0o100644).unwrap();

        let node2 = OvlNode::new(b"b".to_vec(), 0, 100, 1, false);
        let id2 = arena.insert(node2);
        let fuse2 = table.register(&arena, id2, 100, 1, 0o100644).unwrap();

        assert_eq!(fuse1, fuse2);
    }

    #[test]
    fn test_fuse_ino_matches_fs_ino() {
        let mut table = InodeTable::new();
        let mut arena = NodeArena::new();
        for ino in [100, 200, 40000000, 40000001] {
            let node = OvlNode::new(format!("f{}", ino).into_bytes(), 0, ino, 1, false);
            let node_id = arena.insert(node);
            let fuse_ino = table.register(&arena, node_id, ino, 1, 0o100644).unwrap();
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
        let fuse1 = table.register(&arena, id1, 100, 1, 0o100644).unwrap();

        let node2 = OvlNode::new(b"b".to_vec(), 0, 100, 2, false);
        let id2 = arena.insert(node2);
        let fuse2 = table.register(&arena, id2, 100, 2, 0o100644).unwrap();

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

        // Register both — they share the same (ino, dev) = (100, 1)
        let fuse1 = table.register(&arena, perl_id, 100, 1, 0o100755).unwrap();
        let fuse2 = table
            .register(&arena, perl536_id, 100, 1, 0o100755)
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

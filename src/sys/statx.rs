// SPDX-License-Identifier: GPL-2.0-or-later
//
// Safe wrapper for the statx syscall.

/// Convert a statx result to a traditional stat struct.
pub fn statx_to_stat(stx: &libc::statx) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor) as _;
    st.st_ino = stx.stx_ino as _;
    st.st_mode = stx.stx_mode as libc::mode_t;
    st.st_nlink = stx.stx_nlink as libc::nlink_t;
    st.st_uid = stx.stx_uid;
    st.st_gid = stx.stx_gid;
    st.st_rdev = libc::makedev(stx.stx_rdev_major, stx.stx_rdev_minor) as _;
    st.st_size = stx.stx_size as libc::off_t;
    #[cfg(not(target_os = "android"))]
    {
        st.st_blksize = stx.stx_blksize as libc::blksize_t;
        st.st_blocks = stx.stx_blocks as libc::blkcnt_t;
    }

    #[cfg(target_os = "android")]
    {
        st.st_blksize = stx.stx_blksize as _;
        st.st_blocks = stx.stx_blocks as _;
    }

    st.st_atime = stx.stx_atime.tv_sec as _;
    st.st_atime_nsec = stx.stx_atime.tv_nsec as _;
    st.st_mtime = stx.stx_mtime.tv_sec as _;
    st.st_mtime_nsec = stx.stx_mtime.tv_nsec as _;
    st.st_ctime = stx.stx_ctime.tv_sec as _;
    st.st_ctime_nsec = stx.stx_ctime.tv_nsec as _;
    st
}

// statx mask constants (also defined in libc but re-exported for convenience)
pub const STATX_TYPE: libc::c_uint = 0x0000_0001;
pub const STATX_MODE: libc::c_uint = 0x0000_0002;
pub const STATX_NLINK: libc::c_uint = 0x0000_0004;
pub const STATX_INO: libc::c_uint = 0x0000_0100;
pub const STATX_BASIC_STATS: libc::c_uint = 0x0000_07ff;

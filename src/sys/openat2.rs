// SPDX-License-Identifier: GPL-2.0-or-later
//
// safe_openat: openat2 with RESOLVE_IN_ROOT to prevent path traversal.
// SafeFd: newtype that can only be constructed through safe_openat.

use crate::error::{FsError, FsResult};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const RESOLVE_IN_ROOT: u64 = 0x10;

/// openat2(2) syscall number — 437 on all Linux architectures.
const SYS_OPENAT2: libc::c_long = libc::SYS_openat2;

/// Valid open flags mask (matching the C code's VALID_OPEN_FLAGS).
const VALID_OPEN_FLAGS: u64 = (libc::O_RDONLY
    | libc::O_WRONLY
    | libc::O_RDWR
    | libc::O_CREAT
    | libc::O_EXCL
    | libc::O_NOCTTY
    | libc::O_TRUNC
    | libc::O_APPEND
    | libc::O_NONBLOCK
    | libc::O_SYNC
    | libc::O_DSYNC
    | libc::O_DIRECT
    | libc::O_LARGEFILE
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_NOATIME
    | libc::O_CLOEXEC
    | libc::O_PATH
    | libc::O_TMPFILE) as u64;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn syscall_openat2(
    dirfd: RawFd,
    path: &std::ffi::CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> libc::c_int {
    let how = OpenHow {
        flags: flags & VALID_OPEN_FLAGS,
        mode: if (flags & libc::O_CREAT as u64) != 0 {
            mode & 0o7777
        } else {
            0
        },
        resolve,
    };
    // SAFETY: path is a valid CStr (null-terminated), dirfd is a valid fd,
    // and `how` is a repr(C) struct with the correct size for the syscall.
    unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
            0,
        ) as libc::c_int
    }
}

/// A file descriptor that was opened through safe_openat (openat2 with RESOLVE_IN_ROOT).
/// Cannot be constructed from a raw fd, only via `safe_openat()`.
pub struct SafeFd(OwnedFd);

impl SafeFd {
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub fn into_owned(self) -> OwnedFd {
        self.0
    }
}

impl AsRawFd for SafeFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Open a file relative to dirfd, using openat2 with RESOLVE_IN_ROOT to prevent
/// path traversal attacks. Returns an error if openat2 is not supported.
pub fn safe_openat(
    dirfd: RawFd,
    pathname: &[u8],
    flags: libc::c_int,
    mode: libc::mode_t,
) -> FsResult<SafeFd> {
    let c_path = crate::error::cstr_bytes(pathname)?;

    let ret = syscall_openat2(dirfd, &c_path, flags as u64, mode as u64, RESOLVE_IN_ROOT);
    if ret >= 0 {
        // SAFETY: ret is a valid, newly-opened fd returned by the kernel.
        return Ok(SafeFd(unsafe { OwnedFd::from_raw_fd(ret) }));
    }
    Err(FsError::last())
}

/// Open a trusted path (not user-controlled). Used only for:
/// - Mount-time layer directory opens
/// - Workdir initialization
/// - /proc reads
/// - Plugin directory scanning
pub fn open_trusted(path: &str, flags: libc::c_int, mode: libc::mode_t) -> FsResult<OwnedFd> {
    let c_path = crate::error::cstr(path)?;
    // SAFETY: c_path is a valid null-terminated string.
    let ret = unsafe { libc::open(c_path.as_ptr(), flags, mode as libc::c_uint) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        // SAFETY: ret is a valid, newly-opened fd.
        Ok(unsafe { OwnedFd::from_raw_fd(ret) })
    }
}

/// Open the parent directory of a multi-component path safely (via safe_openat),
/// returning (parent_fd, basename). For single-component paths, returns None
/// (meaning the dirfd itself is the parent).
///
/// This is used to convert unsafe multi-component operations like
/// `mknodat(root_fd, "a/b/c", ...)` into safe sequences:
/// `open_parent_safe(root_fd, "a/b/c")` → `(fd_for_a/b, "c")`
/// then `mknodat(fd_for_a/b, "c", ...)`.
pub fn open_parent_safe(dirfd: RawFd, path: &[u8]) -> FsResult<(Option<SafeFd>, &[u8])> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(pos) => {
            let parent = &path[..pos];
            let basename = &path[pos + 1..];
            let parent_fd = safe_openat(dirfd, parent, libc::O_DIRECTORY | libc::O_PATH, 0)?;
            Ok((Some(parent_fd), basename))
        }
        None => Ok((None, path)),
    }
}

/// Like `open_parent_safe` but also converts the basename to CString.
pub fn open_parent_safe_cstr(
    dirfd: RawFd,
    path: &[u8],
) -> FsResult<(Option<SafeFd>, RawFd, std::ffi::CString)> {
    let (parent_fd, basename) = open_parent_safe(dirfd, path)?;
    let dirfd_raw = parent_fd.as_ref().map(|f| f.as_raw_fd()).unwrap_or(dirfd);
    let c_name = crate::error::cstr_bytes(basename)?;
    Ok((parent_fd, dirfd_raw, c_name))
}

/// Build a `/proc/self/fd/<fd>/<basename>` path as raw bytes.
pub fn proc_fd_path(fd: RawFd, basename: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut path = Vec::with_capacity(20 + basename.len());
    write!(path, "/proc/self/fd/{}/", fd).unwrap();
    path.extend_from_slice(basename);
    path
}

/// Check if a file exists at the given path relative to dirfd.
pub fn file_exists_at(dirfd: RawFd, pathname: &[u8]) -> bool {
    let c_path = match std::ffi::CString::new(pathname) {
        Ok(p) => p,
        Err(_) => return false,
    };

    #[cfg(not(target_os = "android"))]
    let at_eaccess = libc::AT_EACCESS;

    #[cfg(target_os = "android")]
    let at_eaccess = 0x200; // Fallback for Bionic

    let ret = unsafe {
        libc::faccessat(
            dirfd,
            c_path.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW | at_eaccess,
        )
    };

    #[cfg(not(target_os = "android"))]
    let current_errno = unsafe { *libc::__errno_location() };

    #[cfg(target_os = "android")]
    let current_errno = unsafe { *libc::__errno() };

    if ret < 0 && current_errno == libc::EINVAL {
        let mut buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret =
            unsafe { libc::fstatat(dirfd, c_path.as_ptr(), &mut buf, libc::AT_SYMLINK_NOFOLLOW) };
        return ret == 0;
    }
    ret == 0
}

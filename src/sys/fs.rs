// SPDX-License-Identifier: GPL-2.0-or-later
//
// Safe wrappers for filesystem syscalls.
// All unsafe libc FFI calls are contained here.
//
// SAFETY (applies to all functions in this module):
// Each function wraps a single libc FFI call. The safety invariants are:
// - CStr pointers come from Rust CStr/CString types (guaranteed null-terminated, valid UTF-8 or lossy).
// - RawFd values are valid open file descriptors (or AT_FDCWD), enforced by callers.
// - Output structs (stat, statx, statvfs, statfs) are zero-initialized before the syscall.
// - Return values are checked; errno is captured via FsError::last() on failure.

use crate::error::{FsError, FsResult};
use std::ffi::CStr;
use std::os::fd::RawFd;

/// Return a zero-initialized libc::stat.
#[cfg(test)]
pub fn zeroed_stat() -> libc::stat {
    // SAFETY: libc::stat is a C struct of integer/time fields; all-zeros is valid.
    unsafe { std::mem::zeroed() }
}

pub fn fstat(fd: RawFd) -> FsResult<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut st) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(st)
    }
}

pub fn fstatat(dirfd: RawFd, path: &CStr, flags: i32) -> FsResult<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(dirfd, path.as_ptr(), &mut st, flags) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(st)
    }
}

pub fn fstatvfs(fd: RawFd) -> FsResult<libc::statvfs> {
    let mut svfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatvfs(fd, &mut svfs) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(svfs)
    }
}

pub fn statfs(path: &CStr) -> FsResult<libc::statfs> {
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statfs(path.as_ptr(), &mut sfs) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(sfs)
    }
}

pub fn statvfs(path: &CStr) -> FsResult<libc::statvfs> {
    let mut svfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(path.as_ptr(), &mut svfs) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(svfs)
    }
}

pub fn statx(dirfd: RawFd, path: &CStr, flags: i32, mask: u32) -> FsResult<libc::statx> {
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    #[cfg(not(target_os = "android"))]
    let ret = unsafe { libc::statx(dirfd, path.as_ptr(), flags, mask, &mut stx) };

    #[cfg(target_os = "android")]
    let ret = unsafe {
        libc::syscall(libc::SYS_statx, dirfd, path.as_ptr(), flags, mask, &mut stx) as libc::c_int
    };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(stx)
    }
}

pub fn fchown(fd: RawFd, uid: u32, gid: u32) -> FsResult<()> {
    let ret = unsafe { libc::fchown(fd, uid, gid) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn fchownat(dirfd: RawFd, path: &CStr, uid: u32, gid: u32, flags: i32) -> FsResult<()> {
    let ret = unsafe { libc::fchownat(dirfd, path.as_ptr(), uid, gid, flags) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn fchmod(fd: RawFd, mode: u32) -> FsResult<()> {
    let ret = unsafe { libc::fchmod(fd, mode) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn fchmodat(dirfd: RawFd, path: &CStr, mode: u32, flags: i32) -> FsResult<()> {
    let ret = unsafe { libc::fchmodat(dirfd, path.as_ptr(), mode, flags) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn futimens(fd: RawFd, times: &[libc::timespec; 2]) -> FsResult<()> {
    let ret = unsafe { libc::futimens(fd, times.as_ptr()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn utimensat(
    dirfd: RawFd,
    path: &CStr,
    times: &[libc::timespec; 2],
    flags: i32,
) -> FsResult<()> {
    let ret = unsafe { libc::utimensat(dirfd, path.as_ptr(), times.as_ptr(), flags) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn mkdirat(dirfd: RawFd, path: &CStr, mode: u32) -> FsResult<()> {
    let ret = unsafe { libc::mkdirat(dirfd, path.as_ptr(), mode) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn mknodat(dirfd: RawFd, path: &CStr, mode: u32, dev: u64) -> FsResult<()> {
    let ret = unsafe { libc::mknodat(dirfd, path.as_ptr(), mode, dev) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn unlinkat(dirfd: RawFd, path: &CStr, flags: i32) -> FsResult<()> {
    let ret = unsafe { libc::unlinkat(dirfd, path.as_ptr(), flags) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn linkat(
    olddirfd: RawFd,
    oldpath: &CStr,
    newdirfd: RawFd,
    newpath: &CStr,
    flags: i32,
) -> FsResult<()> {
    let ret = unsafe {
        libc::linkat(
            olddirfd,
            oldpath.as_ptr(),
            newdirfd,
            newpath.as_ptr(),
            flags,
        )
    };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn symlinkat(target: &CStr, dirfd: RawFd, linkpath: &CStr) -> FsResult<()> {
    let ret = unsafe { libc::symlinkat(target.as_ptr(), dirfd, linkpath.as_ptr()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn readlinkat(dirfd: RawFd, path: &CStr) -> FsResult<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let ret =
        unsafe { libc::readlinkat(dirfd, path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        buf.truncate(ret as usize);
        Ok(buf)
    }
}

pub fn renameat(olddirfd: RawFd, oldpath: &CStr, newdirfd: RawFd, newpath: &CStr) -> FsResult<()> {
    let ret = unsafe { libc::renameat(olddirfd, oldpath.as_ptr(), newdirfd, newpath.as_ptr()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn renameat2(
    olddirfd: RawFd,
    oldpath: &CStr,
    newdirfd: RawFd,
    newpath: &CStr,
    flags: u32,
) -> FsResult<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldpath.as_ptr(),
            newdirfd,
            newpath.as_ptr(),
            flags,
        ) as i32
    };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn fallocate(fd: RawFd, mode: i32, offset: i64, len: i64) -> FsResult<()> {
    let ret = unsafe { libc::fallocate(fd, mode, offset as _, len as _) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn truncate(path: &CStr, length: i64) -> FsResult<()> {
    let ret = unsafe { libc::truncate(path.as_ptr(), length as _) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

pub fn realpath(path: &CStr) -> FsResult<String> {
    let real = unsafe { libc::realpath(path.as_ptr(), std::ptr::null_mut()) };
    if real.is_null() {
        return Err(FsError::last());
    }
    let resolved = unsafe { CStr::from_ptr(real).to_string_lossy().into_owned() };
    unsafe { libc::free(real as *mut _) };
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_fstat() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let st = fstat(fd).unwrap();
        assert!(st.st_ino > 0);
    }

    #[test]
    fn test_fstatat() {
        let dir = tempfile::tempdir().unwrap();
        let _file = std::fs::File::create(dir.path().join("testfile")).unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let dirfd = unsafe { libc::open(c_dir.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };
        assert!(dirfd >= 0);
        let c_name = CString::new("testfile").unwrap();
        let st = fstatat(dirfd, &c_name, 0).unwrap();
        assert!(st.st_ino > 0);
        unsafe { libc::close(dirfd) };
    }

    #[test]
    fn test_mkdirat_unlinkat() {
        let dir = tempfile::tempdir().unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let dirfd = unsafe { libc::open(c_dir.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };
        assert!(dirfd >= 0);
        let c_name = CString::new("subdir").unwrap();
        mkdirat(dirfd, &c_name, 0o755).unwrap();
        // Verify it exists
        let st = fstatat(dirfd, &c_name, 0).unwrap();
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR);
        // Remove it
        unlinkat(dirfd, &c_name, libc::AT_REMOVEDIR).unwrap();
        assert!(fstatat(dirfd, &c_name, 0).is_err());
        unsafe { libc::close(dirfd) };
    }

    #[test]
    fn test_symlinkat_readlinkat() {
        let dir = tempfile::tempdir().unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let dirfd = unsafe { libc::open(c_dir.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };
        assert!(dirfd >= 0);
        let target = CString::new("/tmp/target").unwrap();
        let linkname = CString::new("mylink").unwrap();
        symlinkat(&target, dirfd, &linkname).unwrap();
        let read_target = readlinkat(dirfd, &linkname).unwrap();
        assert_eq!(read_target, b"/tmp/target");
        unlinkat(dirfd, &linkname, 0).unwrap();
        unsafe { libc::close(dirfd) };
    }

    #[test]
    fn test_fchmod_fchown() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        // fchmod should succeed
        let result = fchmod(fd, 0o644);
        assert!(result.is_ok());
        let st = fstat(fd).unwrap();
        assert_eq!(st.st_mode & 0o777, 0o644);
    }

    #[test]
    fn test_fstatvfs() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let svfs = fstatvfs(fd).unwrap();
        assert!(svfs.f_namemax > 0);
    }

    #[test]
    fn test_renameat() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::File::create(dir.path().join("a")).unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let dirfd = unsafe { libc::open(c_dir.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };
        assert!(dirfd >= 0);
        let c_old = CString::new("a").unwrap();
        let c_new = CString::new("b").unwrap();
        renameat(dirfd, &c_old, dirfd, &c_new).unwrap();
        assert!(fstatat(dirfd, &c_old, 0).is_err());
        assert!(fstatat(dirfd, &c_new, 0).is_ok());
        unsafe { libc::close(dirfd) };
    }

    use std::os::fd::AsRawFd;
}

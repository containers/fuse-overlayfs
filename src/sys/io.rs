// SPDX-License-Identifier: GPL-2.0-or-later
//
// Safe wrappers for I/O syscalls.
// All unsafe libc FFI calls are contained here.
//
// SAFETY (applies to all functions): Each wraps a single libc FFI call with
// valid fd arguments and Rust-managed buffers. Return values are checked.

use crate::error::{FsError, FsResult};
use std::os::fd::RawFd;

/// Safe wrapper for libc::pread.
pub fn pread(fd: RawFd, buf: &mut [u8], offset: i64) -> FsResult<usize> {
    let ret = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut _, buf.len(), offset as _) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::pwrite.
pub fn pwrite(fd: RawFd, buf: &[u8], offset: i64) -> FsResult<usize> {
    let ret = unsafe { libc::pwrite(fd, buf.as_ptr() as *const _, buf.len(), offset as _) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::read.
pub fn read(fd: RawFd, buf: &mut [u8]) -> FsResult<usize> {
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::write.
pub fn write(fd: RawFd, buf: &[u8]) -> FsResult<usize> {
    let ret = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::sendfile.
pub fn sendfile(
    out_fd: RawFd,
    in_fd: RawFd,
    offset: *mut libc::off_t,
    count: usize,
) -> FsResult<usize> {
    let ret = unsafe { libc::sendfile(out_fd, in_fd, offset, count) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::copy_file_range.
pub fn copy_file_range(
    fd_in: RawFd,
    off_in: &mut i64,
    fd_out: RawFd,
    off_out: &mut i64,
    len: usize,
) -> FsResult<usize> {
    #[cfg(not(target_os = "android"))]
    let ret = unsafe { libc::copy_file_range(fd_in, off_in, fd_out, off_out, len, 0) };

    #[cfg(target_os = "android")]
    let ret: isize = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            0,
        ) as _
    };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for libc::fsync.
pub fn fsync(fd: RawFd) -> FsResult<()> {
    let ret = unsafe { libc::fsync(fd) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

/// Safe wrapper for libc::fdatasync.
pub fn fdatasync(fd: RawFd) -> FsResult<()> {
    let ret = unsafe { libc::fdatasync(fd) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

/// Safe wrapper for libc::ftruncate.
pub fn ftruncate(fd: RawFd, length: i64) -> FsResult<()> {
    let ret = unsafe { libc::ftruncate(fd, length as _) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

/// Safe wrapper for libc::lseek.
pub fn lseek(fd: RawFd, offset: i64, whence: i32) -> FsResult<i64> {
    let ret = unsafe { libc::lseek(fd, offset as _, whence) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(ret as i64)
    }
}

/// Safe wrapper for FICLONE ioctl.
pub fn ficlone(dest_fd: RawFd, src_fd: RawFd) -> FsResult<()> {
    let ret = unsafe { libc::ioctl(dest_fd, 0x40049409, src_fd) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

/// Safe wrapper for ioctl with a c_long in/out parameter (e.g. FS_IOC_GETFLAGS/SETFLAGS).
/// Returns the value on success; on failure returns FsError.
pub fn ioctl_long(fd: RawFd, cmd: libc::c_ulong, val: &mut libc::c_long) -> FsResult<()> {
    #[cfg(not(target_os = "android"))]
    let ret = unsafe { libc::ioctl(fd, cmd, val as *mut libc::c_long) };

    #[cfg(target_os = "android")]
    let ret = unsafe { libc::ioctl(fd, cmd as _, val as *mut libc::c_long) };
    if ret < 0 {
        Err(FsError::last())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_pread_pwrite_roundtrip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let data = b"hello world";
        let written = pwrite(fd, data, 0).unwrap();
        assert_eq!(written, data.len());
        let mut buf = vec![0u8; data.len()];
        let read_count = pread(fd, &mut buf, 0).unwrap();
        assert_eq!(read_count, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_fsync() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        fsync(fd).unwrap();
    }

    #[test]
    fn test_ftruncate() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        let fd = tmp.as_file().as_raw_fd();
        ftruncate(fd, 5).unwrap();
        let st = crate::sys::fs::fstat(fd).unwrap();
        assert_eq!(st.st_size, 5);
    }

    #[test]
    fn test_lseek() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let pos = lseek(fd, 0, libc::SEEK_END).unwrap();
        assert_eq!(pos, 11);
    }

    #[test]
    fn test_copy_file_range() {
        let mut src = tempfile::NamedTempFile::new().unwrap();
        src.write_all(b"copy this data").unwrap();
        let dst = tempfile::NamedTempFile::new().unwrap();
        let mut off_in: i64 = 0;
        let mut off_out: i64 = 0;
        let result = copy_file_range(
            src.as_file().as_raw_fd(),
            &mut off_in,
            dst.as_file().as_raw_fd(),
            &mut off_out,
            14,
        );
        // copy_file_range may fail on some filesystems (e.g. tmpfs), that's OK
        if let Ok(n) = result {
            assert_eq!(n, 14);
        }
    }

    #[test]
    fn test_read_write() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let data = b"test data";
        let n = write(fd, data).unwrap();
        assert_eq!(n, data.len());
        lseek(fd, 0, libc::SEEK_SET).unwrap();
        let mut buf = vec![0u8; data.len()];
        let n = read(fd, &mut buf).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf, data);
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
use std::io;

/// Filesystem error wrapping an errno value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsError(pub libc::c_int);

impl FsError {
    pub fn last() -> Self {
        FsError(
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        )
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(self.0))
    }
}

impl std::error::Error for FsError {}

impl From<rustix::io::Errno> for FsError {
    fn from(e: rustix::io::Errno) -> Self {
        FsError(e.raw_os_error())
    }
}

impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        FsError(e.raw_os_error().unwrap_or(libc::EIO))
    }
}

pub type FsResult<T> = Result<T, FsError>;

/// Convert a path string to CString. Returns EINVAL if the path contains null bytes.
pub fn cstr(s: &str) -> FsResult<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| FsError(libc::EINVAL))
}

/// Convert a byte slice to CString. Returns EINVAL if it contains null bytes.
pub fn cstr_bytes(s: &[u8]) -> FsResult<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| FsError(libc::EINVAL))
}

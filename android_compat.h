#pragma once

#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <stdint.h>

/* ───── statx ───── */
#ifndef __NR_statx
#define __NR_statx 291
#endif

#ifndef STATX_BASIC_STATS
struct statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t __reserved; };
struct statx {
  uint32_t stx_mask, stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink, stx_uid, stx_gid, stx_mode;
  uint16_t __spare0[1];
  uint64_t stx_ino, stx_size, stx_blocks;
  uint64_t stx_attributes_mask;
  struct statx_timestamp stx_atime, stx_btime, stx_ctime, stx_mtime;
  uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
  uint64_t stx_mnt_id;
  uint64_t __spare2[9];
};
#define STATX_TYPE        0x00000001U
#define STATX_MODE        0x00000002U
#define STATX_NLINK       0x00000004U
#define STATX_UID         0x00000008U
#define STATX_GID         0x00000010U
#define STATX_ATIME       0x00000020U
#define STATX_MTIME       0x00000040U
#define STATX_CTIME       0x00000080U
#define STATX_INO         0x00000100U
#define STATX_SIZE        0x00000200U
#define STATX_BLOCKS      0x00000400U
#define STATX_BASIC_STATS 0x000007ffU
#define STATX_BTIME       0x00000800U
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC   0x2000
#define AT_STATX_DONT_SYNC    0x4000
#endif

#ifdef __ANDROID__
static inline int statx(int dfd, const char *path, int flags,
                         unsigned int mask, struct statx *buf) {
  return syscall(__NR_statx, dfd, path, flags, mask, buf);
}
#endif

/* ───── file_handle / name_to_handle_at ───── */
#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 264
#define __NR_open_by_handle_at 265
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
struct file_handle {
  unsigned int  handle_bytes;
  int           handle_type;
  unsigned char f_handle[0];
};
#endif

#ifdef __ANDROID__
static inline int name_to_handle_at(int dfd, const char *name,
                                     struct file_handle *handle,
                                     int *mnt_id, int flags) {
  return syscall(__NR_name_to_handle_at, dfd, name, handle, mnt_id, flags);
}
#endif

/* ───── copy_file_range ───── */
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 285
#endif

#ifdef __ANDROID__
static inline ssize_t copy_file_range(int fd_in, off_t *off_in,
                                       int fd_out, off_t *off_out,
                                       size_t len, unsigned int flags) {
  return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
}
#endif

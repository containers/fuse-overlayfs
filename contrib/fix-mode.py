#!/bin/python

import os
import sys
import stat
import errno

XATTR_OVERRIDE_STAT_PRIVILEGED = "security.fuseoverlayfs.override_stat"
XATTR_OVERRIDE_CONTAINERS_STAT = "user.fuseoverlayfs.override_stat"

if os.geteuid() == 0:
    xattr_name = XATTR_OVERRIDE_STAT_PRIVILEGED
else:
    xattr_name = XATTR_OVERRIDE_CONTAINERS_STAT

cwd_fd = os.open(".", os.O_PATH)

def fix_path(path):
    st = os.lstat(path)
    content = "%s:%s:%o" % (st.st_uid, st.st_gid,  stat.S_IMODE(st.st_mode))

    try:
        os.setxattr(path, xattr_name, str.encode(content), flags=os.XATTR_CREATE, follow_symlinks=False)
    except Exception as e:
        if e.errno == errno.EEXIST:
            print("attr %s already present for %s: %s" % (xattr_name, path, e.errno))
            return
        raise e

    fd = os.open(path, os.O_PATH|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        proc_path = "/proc/self/fd/%d" % fd
        os.chmod(proc_path, 0o755)
    except Exception as e:
        if e.errno != errno.ENOTSUP:
            raise e
    finally:
        os.close(fd)


def fix_mode_directory(d):
    for root, dirs, files in os.walk(d, topdown=False):
        for i in dirs+files:
            path = os.path.join(root, i)
            fix_path(path)
    fix_path(d)

for i in sys.argv[1:]:
    fix_mode_directory(i)

        

SUBDIRS = lib

bin_PROGRAMS = fuse-overlayfs

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = m4/gnulib-cache.m4 rpm/fuse-overlayfs.spec.template autogen.sh fuse-overlayfs.1.md utils.h NEWS tests/suid-test.c plugin.h plugin-manager.h fuse-overlayfs.h fuse_overlayfs_error.h

AM_CPPFLAGS = -DPKGLIBEXECDIR='"$(pkglibexecdir)"'

fuse_overlayfs_CFLAGS = -I . -I $(abs_srcdir)/lib $(FUSE_CFLAGS)
fuse_overlayfs_LDFLAGS =
fuse_overlayfs_LDADD = lib/libgnu.a $(FUSE_LIBS)
fuse_overlayfs_SOURCES = main.c direct.c utils.c plugin-manager.c

WD := $(shell pwd)

man1_MANS = fuse-overlayfs.1

fuse-overlayfs.1:
if HAVE_MD2MAN
	go-md2man -in $(abs_srcdir)/fuse-overlayfs.1.md -out fuse-overlayfs.1
endif HAVE_MD2MAN

generate-man: fuse-overlayfs.1

fuse-overlayfs.spec: $(srcdir)/rpm/fuse-overlayfs.spec.template
	sed -e 's|#VERSION#|$(VERSION)|g' < $< > $@

rpm: dist-gzip fuse-overlayfs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" fuse-overlayfs.spec

srpm: dist-gzip fuse-overlayfs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -bs --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" fuse-overlayfs.spec

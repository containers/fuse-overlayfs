SUBDIRS = lib

bin_PROGRAMS = containerfs

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = m4/gnulib-cache.m4 rpm/containerfs.spec.template autogen.sh

containerfs_CFLAGS = -I . -I lib $(FUSE_CFLAGS)
containerfs_LDFLAGS = $(FUSE_LIBS)
containerfs_LDADD = lib/libgnu.a
containerfs_SOURCES = main.c

WD := $(shell pwd)

containerfs.spec: $(srcdir)/rpm/containerfs.spec.template
	sed -e 's|#VERSION#|$(VERSION)|g' < $< > $@

rpm: dist-gzip containerfs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" containerfs.spec

srpm: dist-gzip containerfs.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -bs --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" containerfs.spec

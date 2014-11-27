include $(top_srcdir)/config/rpm.am
include $(top_srcdir)/config/deb.am
include $(top_srcdir)/config/tgz.am
include $(top_srcdir)/config/arch.am

if CONFIG_USER
USER_DIR = scripts
endif
if CONFIG_KERNEL
KERNEL_DIR = module include
endif
SUBDIRS = $(USER_DIR) $(KERNEL_DIR)

AUTOMAKE_OPTIONS = foreign
EXTRA_DIST  = autogen.sh spl.spec.in spl-modules.spec.in META DISCLAIMER
EXTRA_DIST += config/config.awk config/rpm.am config/deb.am config/tgz.am
EXTRA_DIST += dkms.postinst copy-builtin
noinst_HEADERS = spl_config.h spl.release

distclean-local::
	-$(RM) -R autom4te*.cache
	-find . \( -name SCCS -o -name BitKeeper -o -name .svn -o -name CVS \
		-o -name .pc -o -name .hg -o -name .git \) -prune -o \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '.*.rej' -o -name 'aclocal.m4' -o -size 0 \
		-o -name '*%' -o -name '.*.cmd' -o -name 'core' \
		-o -name 'Makefile' \
		-o -name '*.order' -o -name '*.markers' \) \
		-type f -print | xargs $(RM)

if CONFIG_KERNEL
install-data-local:
	release=$(SPL_META_VERSION)-$(SPL_META_RELEASE); \
	instdest=$(DESTDIR)/usr/src/spl-$$release/$(KERNEL_VERSION); \
	for instfile in $(noinst_HEADERS); do \
		parentdir=`dirname $$instdest/$$instfile`; \
		mkdir -p $$parentdir; \
		$(INSTALL) $$instfile $$instdest/$$instfile; \
	done
endif

dist-hook:
	sed -i 's/Release:[[:print:]]*/Release:      $(RELEASE)/' \
		$(distdir)/META

ctags:
	$(RM) $(top_srcdir)/tags
	find $(top_srcdir) -name .git -prune -o -name '*.[hc]' | xargs ctags

etags:
	$(RM) $(top_srcdir)/TAGS
	find $(top_srcdir) -name .pc -prune -o -name '*.[hc]' | xargs etags -a

tags: ctags etags

pkg: @DEFAULT_PACKAGE@
pkg-modules: @DEFAULT_PACKAGE@-modules
pkg-utils: @DEFAULT_PACKAGE@-utils

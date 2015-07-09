include $(top_srcdir)/config/Rules.am

INFO_PLIST = Info.plist
PLIST_STRING = InfoPlist.strings

SUBDIRS = KernelExports
AUTOMAKE_OPTIONS = subdir-objects

CFLAGS_KMOD = \
	$(AM_CFLAGS) \
	-Wall \
	-nostdinc \
	-mkernel \
	-fno-builtin-printf \
	-D_KERNEL \
	-DKERNEL \
	-DKERNEL_PRIVATE \
	-DDRIVER_PRIVATE \
	-DAPPLE \
	-DNeXT \
	-I$(top_srcdir)/include \
	-I@KERNEL_HEADERS@/Headers \
	-I@KERNEL_HEADERS@/PrivateHeaders

LINKFLAGS_KMOD = \
	-Xlinker \
	-kext \
	-nostdlib \
	-lkmodc++ \
	-lkmod \
	-lcc_kext

bin_PROGRAMS = spl.kext
noinst_PROGRAMS = spl

spl_kext_SOURCE =

spl_SOURCES = 	\
	crypto/edonr/edonr.c \
	crypto/skein/skein.c \
	crypto/skein/skein_iv.c \
	crypto/skein/skein_block.c \
	crypto/sha2/sha2.c \
	spl-atomic.c \
	spl-avl.c \
	spl-condvar.c \
	spl-cred.c \
	spl-ddi.c \
	spl-err.c \
	spl-kmem.c \
	spl-kobj.c \
	spl-kstat.c \
	spl-list.c \
	spl-mutex.c \
	spl-osx.c \
	spl-policy.c \
	spl-proc.c \
	spl-processor.c \
	spl-rwlock.c \
	spl-seg_kmem.c \
	spl-taskq.c \
	spl-thread.c \
	spl-time.c \
	spl-tsd.c \
    spl-vmem.c \
	spl-vnode.c \
	spl-xdr.c

spl_CPPFLAGS=$(CFLAGS_KMOD)
spl_LDFLAGS=$(LINKFLAGS_KMOD)

KERNEL_MODDIR=	$(DESTDIR)@KERNEL_MODPREFIX@/spl.kext

dist_noinst_DATA = $(PLIST_STRING) $(INFO_PLIST)

spl.kext$(EXEEXT): spl $(PLIST_STRING) $(INFO_PLIST)
	@echo ""
	@mkdir -p spl.kext/Contents/Resources/English.lproj spl.kext/Contents/MacOS
	@cp -f $(INFO_PLIST) spl.kext/Contents/
	/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $(SPL_META_VERSION)" spl.kext/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(SPL_META_VERSION)" spl.kext/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Delete :OSBundleLibraries:net.lundman.kernel.dependencies" spl.kext/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Add :OSBundleLibraries:net.lundman.kernel.dependencies.$(SPL_KERNEL_DEPENDENCIES) string 12.5.0" spl.kext/Contents/Info.plist
	if [ "0$(SPL_BOOT)" -eq 1 ]; then /usr/libexec/PlistBuddy -c "Add :OSBundleRequired string Root" spl.kext/Contents/Info.plist; fi
	@cp -f $(PLIST_STRING) spl.kext/Contents/Resources/English.lproj/
	@cp -f spl spl.kext/Contents/MacOS/
	@mkdir -p spl.kext/Contents/PlugIns/KernelExports.kext/
	@cd KernelExports && $(MAKE)
	@cp -f KernelExports/KernelExports spl.kext/Contents/PlugIns/KernelExports.kext/
	cp -f KernelExports/Info.plist spl.kext/Contents/PlugIns/KernelExports.kext/
	/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier net.lundman.kernel.dependencies.$(SPL_KERNEL_DEPENDENCIES)" spl.kext/Contents/PlugIns/KernelExports.kext/Info.plist
	cp -f KernelExports/version.plist spl.kext/Contents/PlugIns/KernelExports.kext/
	mkdir -p KernelExports.kext
	cp -f spl.kext/Contents/PlugIns/KernelExports.kext/KernelExports KernelExports.kext/
	cp -f spl.kext/Contents/PlugIns/KernelExports.kext/Info.plist  KernelExports.kext/
	@kextlibs -undef-symbols -xml spl.kext/ || echo "Ignoring errors.."

install-exec-local: spl.kext
	rm -rf $(KERNEL_MODDIR)
	mkdir -p $(KERNEL_MODDIR)
	rsync -r spl.kext/ $(KERNEL_MODDIR)
	chown -R root:wheel $(KERNEL_MODDIR) || echo "Unable to chown root:wheel $(KERNEL_MODDIR)"
	@echo
	@echo "To load module: kextload -v $(KERNEL_MODDIR)"
	@echo "To uninstall module: rm -rf $(KERNEL_MODDIR)"
	@echo

uninstall-am:
	rm -rf $(KERNEL_MODDIR)

clean:
	rm -rf spl.kext/
	rm -f *.o *.lo spl
	@cd KernelExports && $(MAKE) clean

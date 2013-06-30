
INFO_PLIST = Info.plist
PLIST_STRING = InfoPlist.strings

CFLAGS_KMOD = \
	${AM_CFLAGS} \
	-Wall \
	-nostdinc \
	-mkernel \
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
	spl-atomic.c \
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
	spl-proc.c \
	spl-rwlock.c \
	spl-taskq.c \
	spl-thread.c \
	spl-time.c \
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
	@cp -f $(PLIST_STRING) spl.kext/Contents/Resources/English.lproj/
	@cp -f spl spl.kext/Contents/MacOS/
	@kextlibs -undef-symbols -xml spl.kext/

install-exec-local: spl.kext
	rm -rf $(KERNEL_MODDIR)
	mkdir -p $(KERNEL_MODDIR)
	rsync -r spl.kext/ $(KERNEL_MODDIR)
	chown -R root:wheel $(KERNEL_MODDIR)
	@echo
	@echo "To load module: kextload -v $(KERNEL_MODDIR)"
	@echo "To uninstall module: rm -rf $(KERNEL_MODDIR)"
	@echo

uninstall-am:
	rm -rf /System/Library/Extensions/spl.kext

clean:
	rm -rf spl.kext/
	rm -f *.o *.lo spl

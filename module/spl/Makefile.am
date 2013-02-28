
INFO_PLIST = Info.plist
PLIST_STRING = InfoPlist.strings

CFLAGS_KMOD = \
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
	-I/System/Library/Frameworks/Kernel.framework/PrivateHeaders \
	-I/System/Library/Frameworks/Kernel.framework/Headers

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

spl_SOURCES = \
	spl-atomic.c \
	spl-condvar.c \
	spl-cred.c \
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

dist_noinst_DATA = $(PLIST_STRING) $(INFO_PLIST)

spl.kext : spl $(PLIST_STRING) $(INFO_PLIST)
	@echo ""
	@mkdir -p spl.kext/Contents/Resources/English.lproj spl.kext/Contents/MacOS
	@cp -f $(INFO_PLIST) spl.kext/Contents/
	@cp -f $(PLIST_STRING) spl.kext/Contents/Resources/English.lproj/
	@cp -f spl spl.kext/Contents/MacOS/
	@kextlibs -undef-symbols -xml spl.kext/ || echo "delay kmem_alloc kmem_free kernel_map are known missing symbols. Someone fix.."
	@echo ""
	@echo "To load module, use;"
	@echo "    rsync -ar --delete module/spl/spl.kext/ /tmp/spl.kext/"
	@echo "    chown -R root:wheel /tmp/spl.kext"
	@echo "    kextload -v /tmp/spl.kext/"
	@echo ""

install-exec-local :
	echo "There is no install yet, don't do it."
	exit 1

clean:
	rm -rf spl.kext/
	rm -f *.o *.lo

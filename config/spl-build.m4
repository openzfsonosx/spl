###############################################################################
# Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
# Copyright (C) 2007 The Regents of the University of California.
# Written by Brian Behlendorf <behlendorf1@llnl.gov>.
###############################################################################
# SPL_AC_CONFIG_KERNEL: Default SPL kernel configuration.
###############################################################################

AC_DEFUN([SPL_AC_CONFIG_KERNEL], [
	SPL_AC_KERNEL

	AC_SUBST(KERNELMAKE_PARAMS)

	KERNELCPPFLAGS="$KERNELCPPFLAGS -Wstrict-prototypes"
	AC_SUBST(KERNELCPPFLAGS)

	SPL_AC_DEBUG
	SPL_AC_DEBUG_LOG
	SPL_AC_DEBUG_KMEM
	SPL_AC_DEBUG_KMEM_TRACKING
	SPL_AC_TEST_MODULE
])

AC_DEFUN([SPL_AC_KERNEL], [
	AC_MSG_CHECKING([mach_kernel])
	AS_IF([test -z "$machkernel"], [
		AS_IF([test -e "/System/Library/Kernels/kernel"], [
			machkernel="/System/Library/Kernels/kernel"
		], [test -e "/mach_kernel"], [
			machkernel="/mach_kernel"
		], [
			machkernel="[Not found]"
		])
		AS_IF([test ! -f "$machkernel"], [
			AC_MSG_ERROR([
	*** mach_kernel file not found. For 10.9 and prior, this should be
	*** '/mach_kernel' and for 10.10 and following, this should be
	*** '/System/Library/Kernels/kernel'])
		])
	])
	AC_MSG_RESULT($machkernel)

	AC_ARG_WITH([kernel-modprefix],
		AS_HELP_STRING([--with-kernel-modprefix=PATH],
		[Path to kernel module prefix]),
		[KERNEL_MODPREFIX="$withval"])
	AC_MSG_CHECKING([kernel module prefix])
	AS_IF([test -z "$KERNEL_MODPREFIX"], [
		KERNEL_MODPREFIX="/System/Library/Extensions"
	])
	AC_MSG_RESULT([$KERNEL_MODPREFIX])

	AC_ARG_WITH([kernel-headers],
		AS_HELP_STRING([--with-kernel-headers=PATH],
		[Path to kernel source]),
		[KERNEL_HEADERS="$withval"])

	AC_MSG_CHECKING([kernel header directory])
	AS_IF([test -z "$KERNEL_HEADERS"], [
		AS_IF([test -d "/System/Library/Frameworks/Kernel.framework/Headers"], [
			KERNEL_HEADERS="/System/Library/Frameworks/Kernel.framework"
		])
	])
	AS_IF([test -z "$KERNEL_HEADERS"], [
		tmpdir=`xcrun --show-sdk-path`
		AS_IF([test -d "$tmpdir/System/Library/Frameworks/Kernel.framework/"], [
			KERNEL_HEADERS="$tmpdir/System/Library/Frameworks/Kernel.framework/"
		])
	])
	AS_IF([test -z "$KERNEL_HEADERS"], [
		AS_IF([test -d "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/System/Library/Frameworks/Kernel.framework"], [
			KERNEL_HEADERS="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/System/Library/Frameworks/Kernel.framework"
		])
	])
	AS_IF([test ! -d "$KERNEL_HEADERS/Headers/IOKit"], [
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([*** Kernel header directory not found!])
	])
	AC_MSG_RESULT([$KERNEL_HEADERS])

	AC_MSG_CHECKING([kernel source version])
	KERNEL_VERSION=`uname -r`
	AC_MSG_RESULT([$KERNEL_VERSION])

	MACH_KERNEL=${machkernel}

	AC_SUBST(MACH_KERNEL)
	AC_SUBST(KERNEL_HEADERS)
	AC_SUBST(KERNEL_MODPREFIX)
	AC_SUBST(KERNEL_VERSION)
])

dnl #
dnl # Default SPL user configuration
dnl #
AC_DEFUN([SPL_AC_CONFIG_USER], [])

dnl #
dnl # Check for rpm+rpmbuild to build RPM packages.  If these tools
dnl # are missing it is non-fatal but you will not be able to build
dnl # RPM packages and will be warned if you try too.
dnl #
AC_DEFUN([SPL_AC_RPM], [
	RPM=rpm
	RPMBUILD=rpmbuild

	AC_MSG_CHECKING([whether $RPM is available])
	AS_IF([tmp=$($RPM --version 2>/dev/null)], [
		RPM_VERSION=$(echo $tmp | $AWK '/RPM/ { print $[3] }')
		HAVE_RPM=yes
		AC_MSG_RESULT([$HAVE_RPM ($RPM_VERSION)])
	],[
		HAVE_RPM=no
		AC_MSG_RESULT([$HAVE_RPM])
	])

	AC_MSG_CHECKING([whether $RPMBUILD is available])
	AS_IF([tmp=$($RPMBUILD --version 2>/dev/null)], [
		RPMBUILD_VERSION=$(echo $tmp | $AWK '/RPM/ { print $[3] }')
		HAVE_RPMBUILD=yes
		AC_MSG_RESULT([$HAVE_RPMBUILD ($RPMBUILD_VERSION)])
	],[
		HAVE_RPMBUILD=no
		AC_MSG_RESULT([$HAVE_RPMBUILD])
	])

	AC_SUBST(HAVE_RPM)
	AC_SUBST(RPM)
	AC_SUBST(RPM_VERSION)

	AC_SUBST(HAVE_RPMBUILD)
	AC_SUBST(RPMBUILD)
	AC_SUBST(RPMBUILD_VERSION)
])

dnl #
dnl # Check for dpkg+dpkg-buildpackage to build DEB packages.  If these
dnl # tools are missing it is non-fatal but you will not be able to build
dnl # DEB packages and will be warned if you try too.
dnl #
AC_DEFUN([SPL_AC_DPKG], [
	DPKG=dpkg
	DPKGBUILD=dpkg-buildpackage

	AC_MSG_CHECKING([whether $DPKG is available])
	AS_IF([tmp=$($DPKG --version 2>/dev/null)], [
		DPKG_VERSION=$(echo $tmp | $AWK '/Debian/ { print $[7] }')
		HAVE_DPKG=yes
		AC_MSG_RESULT([$HAVE_DPKG ($DPKG_VERSION)])
	],[
		HAVE_DPKG=no
		AC_MSG_RESULT([$HAVE_DPKG])
	])

	AC_MSG_CHECKING([whether $DPKGBUILD is available])
	AS_IF([tmp=$($DPKGBUILD --version 2>/dev/null)], [
		DPKGBUILD_VERSION=$(echo $tmp | \
		    $AWK '/Debian/ { print $[4] }' | cut -f-4 -d'.')
		HAVE_DPKGBUILD=yes
		AC_MSG_RESULT([$HAVE_DPKGBUILD ($DPKGBUILD_VERSION)])
	],[
		HAVE_DPKGBUILD=no
		AC_MSG_RESULT([$HAVE_DPKGBUILD])
	])

	AC_SUBST(HAVE_DPKG)
	AC_SUBST(DPKG)
	AC_SUBST(DPKG_VERSION)

	AC_SUBST(HAVE_DPKGBUILD)
	AC_SUBST(DPKGBUILD)
	AC_SUBST(DPKGBUILD_VERSION)
])

dnl #
dnl # Check for pacman+makepkg to build Arch Linux packages.  If these
dnl # tools are missing it is non-fatal but you will not be able to
dnl # build Arch Linux packages and will be warned if you try too.
dnl #
AC_DEFUN([SPL_AC_PACMAN], [
	PACMAN=pacman
	MAKEPKG=makepkg

	AC_MSG_CHECKING([whether $PACMAN is available])
	tmp=$($PACMAN --version 2>/dev/null)
	AS_IF([test -n "$tmp"], [
		PACMAN_VERSION=$(echo $tmp |
		                 $AWK '/Pacman/ { print $[3] }' |
		                 $SED 's/^v//')
		HAVE_PACMAN=yes
		AC_MSG_RESULT([$HAVE_PACMAN ($PACMAN_VERSION)])
	],[
		HAVE_PACMAN=no
		AC_MSG_RESULT([$HAVE_PACMAN])
	])

	AC_MSG_CHECKING([whether $MAKEPKG is available])
	tmp=$($MAKEPKG --version 2>/dev/null)
	AS_IF([test -n "$tmp"], [
		MAKEPKG_VERSION=$(echo $tmp | $AWK '/makepkg/ { print $[3] }')
		HAVE_MAKEPKG=yes
		AC_MSG_RESULT([$HAVE_MAKEPKG ($MAKEPKG_VERSION)])
	],[
		HAVE_MAKEPKG=no
		AC_MSG_RESULT([$HAVE_MAKEPKG])
	])

	AC_SUBST(HAVE_PACMAN)
	AC_SUBST(PACMAN)
	AC_SUBST(PACMAN_VERSION)

	AC_SUBST(HAVE_MAKEPKG)
	AC_SUBST(MAKEPKG)
	AC_SUBST(MAKEPKG_VERSION)
])

dnl #
dnl # Until native packaging for various different packing systems
dnl # can be added the least we can do is attempt to use alien to
dnl # convert the RPM packages to the needed package type.  This is
dnl # a hack but so far it has worked reasonable well.
dnl #
AC_DEFUN([SPL_AC_ALIEN], [
	ALIEN=alien

	AC_MSG_CHECKING([whether $ALIEN is available])
	AS_IF([tmp=$($ALIEN --version 2>/dev/null)], [
		ALIEN_VERSION=$(echo $tmp | $AWK '{ print $[3] }')
		HAVE_ALIEN=yes
		AC_MSG_RESULT([$HAVE_ALIEN ($ALIEN_VERSION)])
	],[
		HAVE_ALIEN=no
		AC_MSG_RESULT([$HAVE_ALIEN])
	])

	AC_SUBST(HAVE_ALIEN)
	AC_SUBST(ALIEN)
	AC_SUBST(ALIEN_VERSION)
])

dnl #
dnl # Using the VENDOR tag from config.guess set the default
dnl # package type for 'make pkg': (rpm | deb | tgz)
dnl #
AC_DEFUN([SPL_AC_DEFAULT_PACKAGE], [
	AC_MSG_CHECKING([linux distribution])
	if test -f /etc/toss-release ; then
		VENDOR=toss ;
	elif test -f /etc/fedora-release ; then
		VENDOR=fedora ;
	elif test -f /etc/redhat-release ; then
		VENDOR=redhat ;
	elif test -f /etc/gentoo-release ; then
		VENDOR=gentoo ;
	elif test -f /etc/arch-release ; then
		VENDOR=arch ;
	elif test -f /etc/SuSE-release ; then
		VENDOR=sles ;
	elif test -f /etc/slackware-version ; then
		VENDOR=slackware ;
	elif test -f /etc/lunar.release ; then
		VENDOR=lunar ;
	elif test -f /etc/lsb-release ; then
		VENDOR=ubuntu ;
	elif test -f /etc/debian_version ; then
		VENDOR=debian ;
	else
		VENDOR= ;
	fi
	AC_MSG_RESULT([$VENDOR])
	AC_SUBST(VENDOR)

	AC_MSG_CHECKING([default package type])
	case "$VENDOR" in
		toss)       DEFAULT_PACKAGE=rpm  ;;
		redhat)     DEFAULT_PACKAGE=rpm  ;;
		fedora)     DEFAULT_PACKAGE=rpm  ;;
		gentoo)     DEFAULT_PACKAGE=tgz  ;;
		arch)       DEFAULT_PACKAGE=arch ;;
		sles)       DEFAULT_PACKAGE=rpm  ;;
		slackware)  DEFAULT_PACKAGE=tgz  ;;
		lunar)      DEFAULT_PACKAGE=tgz  ;;
		ubuntu)     DEFAULT_PACKAGE=deb  ;;
		debian)     DEFAULT_PACKAGE=deb  ;;
		*)          DEFAULT_PACKAGE=rpm  ;;
	esac

	AC_MSG_RESULT([$DEFAULT_PACKAGE])
	AC_SUBST(DEFAULT_PACKAGE)
])

dnl #
dnl # Default SPL user configuration
dnl #
AC_DEFUN([SPL_AC_PACKAGE], [
	SPL_AC_DEFAULT_PACKAGE
	SPL_AC_RPM
	SPL_AC_DPKG
	SPL_AC_ALIEN

	AS_IF([test "$VENDOR" = "arch"], [SPL_AC_PACMAN])
])

AC_DEFUN([SPL_AC_LICENSE], [
	AC_MSG_CHECKING([spl license])
	LICENSE=GPL
	AC_MSG_RESULT([$LICENSE])
	KERNELCPPFLAGS="${KERNELCPPFLAGS} -DHAVE_GPL_ONLY_SYMBOLS"
	AC_SUBST(LICENSE)
])

AC_DEFUN([SPL_AC_CONFIG], [
	SPL_CONFIG=all
	AC_ARG_WITH([config],
		AS_HELP_STRING([--with-config=CONFIG],
		[Config file 'kernel|user|all|srpm']),
		[SPL_CONFIG="$withval"])
	AC_ARG_ENABLE([linux-builtin],
		[AC_HELP_STRING([--enable-linux-builtin],
		[Configure for builtin in-tree kernel modules @<:@default=no@:>@])],
		[],
		[enable_linux_builtin=no])

	AC_MSG_CHECKING([spl config])
	AC_MSG_RESULT([$SPL_CONFIG]);
	AC_SUBST(SPL_CONFIG)

	case "$SPL_CONFIG" in
		kernel) SPL_AC_CONFIG_KERNEL ;;
		user)   SPL_AC_CONFIG_USER   ;;
		all)    SPL_AC_CONFIG_KERNEL
		        SPL_AC_CONFIG_USER   ;;
		srpm)                        ;;
		*)
		AC_MSG_RESULT([Error!])
		AC_MSG_ERROR([Bad value "$SPL_CONFIG" for --with-config,
		             user kernel|user|all|srpm]) ;;
	esac

	AM_CONDITIONAL([CONFIG_USER],
	               [test "$SPL_CONFIG" = user -o "$SPL_CONFIG" = all])
	AM_CONDITIONAL([CONFIG_KERNEL],
	               [test "$SPL_CONFIG" = kernel -o "$SPL_CONFIG" = all] &&
	               [test "x$enable_linux_builtin" != xyes ])
])

dnl #
dnl # Enable if the SPL should be compiled with internal debugging enabled.
dnl # By default this support is disabled.
dnl #
AC_DEFUN([SPL_AC_DEBUG], [
	AC_MSG_CHECKING([whether strict compile is enabled])
	AC_ARG_ENABLE([strict-compile],
		[AS_HELP_STRING([--enable-strict-compile],
		[Enable strict compile checking @<:@default=no@:>@])],
		[strict_compile=yes],
		[strict_compile=no])
	AS_IF([test "x$strict_compile" = xyes],
	[
		DEBUG_CFLAGS="${DEBUG_CFLAGS} -Werror"
	])
	AC_MSG_RESULT([$strict_compile])

	AC_MSG_CHECKING([whether debugging is enabled])
	AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug],
		[Enable generic debug support @<:@default=no@:>@])],
		[],
		[enable_debug=no])

	AS_IF([test "x$enable_debug" = xyes],
	[
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DDEBUG"
		DEBUG_CFLAGS="-DDEBUG"
		DEBUG_SPL="_with_debug"
	], [
		DEBUG_CFLAGS=""
		DEBUG_SPL="_without_debug"
	])

	AC_SUBST(DEBUG_CFLAGS)
	AC_SUBST(DEBUG_SPL)
	AC_MSG_RESULT([$enable_debug])
])

dnl #
dnl # Enabled by default it provides a basic debug log infrastructure.
dnl # Each subsystem registers itself with a name and logs messages
dnl # using predefined types.  If the debug mask it set to allow the
dnl # message type it will be written to the internal log.  The log
dnl # can be dumped to a file by echoing 1 to the 'dump' proc entry,
dnl # after dumping the log it must be decoded using the spl utility.
dnl #
dnl # echo 1 >/proc/sys/kernel/spl/debug/dump
dnl # spl /tmp/spl-log.xxx.yyy /tmp/spl-log.xxx.yyy.txt
dnl #
AC_DEFUN([SPL_AC_DEBUG_LOG], [
	AC_ARG_ENABLE([debug-log],
		[AS_HELP_STRING([--enable-debug-log],
		[Enable basic debug logging @<:@default=no@:>@])],
		[],
		[enable_debug_log=no])

	AS_IF([test "x$enable_debug_log" = xyes],
	[
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DDEBUG_LOG"
		DEBUG_LOG="_with_debug_log"
		AC_DEFINE([DEBUG_LOG], [1],
		[Define to 1 to enable basic debug logging])
	], [
		DEBUG_LOG="_without_debug_log"
	])

	AC_SUBST(DEBUG_LOG)
	AC_MSG_CHECKING([whether basic debug logging is enabled])
	AC_MSG_RESULT([$enable_debug_log])
])

dnl #
dnl # Enabled by default it provides a minimal level of memory tracking.
dnl # A total count of bytes allocated is kept for each alloc and free.
dnl # Then at module unload time a report to the console will be printed
dnl # if memory was leaked.  Additionally, /proc/spl/kmem/slab will exist
dnl # and provide an easy way to inspect the kmem based slab.
dnl #
AC_DEFUN([SPL_AC_DEBUG_KMEM], [
	AC_ARG_ENABLE([debug-kmem],
		[AS_HELP_STRING([--enable-debug-kmem],
		[Enable basic kmem accounting @<:@default=yes@:>@])],
		[],
		[enable_debug_kmem=yes])

	AS_IF([test "x$enable_debug_kmem" = xyes],
	[
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DDEBUG_KMEM"
		DEBUG_KMEM="_with_debug_kmem"
		AC_DEFINE([DEBUG_KMEM], [1],
		[Define to 1 to enable basic kmem accounting])
	], [
		DEBUG_KMEM="_without_debug_kmem"
	])

	AC_SUBST(DEBUG_KMEM)
	AC_MSG_CHECKING([whether basic kmem accounting is enabled])
	AC_MSG_RESULT([$enable_debug_kmem])
])

dnl #
dnl # Disabled by default it provides detailed memory tracking.  This
dnl # feature also requires --enable-debug-kmem to be set.  When enabled
dnl # not only will total bytes be tracked but also the location of every
dnl # alloc and free.  When the SPL module is unloaded a list of all leaked
dnl # addresses and where they were allocated will be dumped to the console.
dnl # Enabling this feature has a significant impact on performance but it
dnl # makes finding memory leaks pretty straight forward.
dnl #
AC_DEFUN([SPL_AC_DEBUG_KMEM_TRACKING], [
	AC_ARG_ENABLE([debug-kmem-tracking],
		[AS_HELP_STRING([--enable-debug-kmem-tracking],
		[Enable detailed kmem tracking  @<:@default=no@:>@])],
		[],
		[enable_debug_kmem_tracking=no])

	AS_IF([test "x$enable_debug_kmem_tracking" = xyes],
	[
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DDEBUG_KMEM_TRACKING"
		DEBUG_KMEM_TRACKING="_with_debug_kmem_tracking"
		AC_DEFINE([DEBUG_KMEM_TRACKING], [1],
		[Define to 1 to enable detailed kmem tracking])
	], [
		DEBUG_KMEM_TRACKING="_without_debug_kmem_tracking"
	])

	AC_SUBST(DEBUG_KMEM_TRACKING)
	AC_MSG_CHECKING([whether detailed kmem tracking is enabled])
	AC_MSG_RESULT([$enable_debug_kmem_tracking])
])

dnl #
dnl # SPL_CHECK_SYMBOL_HEADER
dnl # check if a symbol prototype is defined in listed headers.
dnl #
AC_DEFUN([SPL_CHECK_SYMBOL_HEADER], [
	AC_MSG_CHECKING([whether symbol $1 exists in header])
	header=0
	for file in $3; do
		grep -q "$2" "$KERNEL_HEADERS/$file" 2>/dev/null
		rc=$?
		if test $rc -eq 0; then
			header=1
			break;
		fi
	done
	if test $header -eq 0; then
		AC_MSG_RESULT([no])
		$5
	else
		AC_MSG_RESULT([yes])
		$4
	fi
])

dnl #
dnl # SPL_CHECK_HEADER
dnl # check whether header exists and define HAVE_$2_HEADER
dnl #
AC_DEFUN([SPL_CHECK_HEADER],
	[AC_MSG_CHECKING([whether header $1 exists])
	AC_TRY_COMPILE([
		#include <$1>
	],[
		return 0;
	],[
		AC_DEFINE(HAVE_$2_HEADER, 1, [$1 exists])
		AC_MSG_RESULT(yes)
		$3
	],[
		AC_MSG_RESULT(no)
		$4
	])
])

dnl #
dnl # Basic toolchain sanity check.
dnl #
AC_DEFUN([SPL_AC_TEST_MODULE],
	[AC_MSG_CHECKING([whether modules can be built])
	AC_TRY_COMPILE([],[],[
		AC_MSG_RESULT([yes])
	],[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([*** Unable to build an empty module.])
	])
])

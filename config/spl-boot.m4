AC_DEFUN([SPL_AC_BOOT], [
	AC_ARG_ENABLE([boot],
		[AS_HELP_STRING([--enable-boot],
		[Enable boot @<:@default=no@:>@])],
		[],
		[enable_boot=no])

	AS_IF([test "x$enable_boot" != xno],
	[
		enable_boot=yes
		SPL_BOOT=1
		AM_CONDITIONAL(SPL_BOOT, true)
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DSPL_BOOT"
		CFLAGS_KMOD="${CFLAGS_KMOD} -DSPL_BOOT"
		AC_DEFINE(SPL_BOOT, 1,
		[Define SPL_BOOT to enable kext load at boot])
		AC_SUBST([SPL_BOOT])
	],
	[
		AM_CONDITIONAL(SPL_BOOT, false)
	])

	AC_MSG_CHECKING([whether kext load at boot is enabled])
	AC_MSG_RESULT([$enable_boot])
])

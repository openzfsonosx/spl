###############################################################################
# SPL AutoConf Configuration
###############################################################################
# Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
# Copyright (C) 2007 The Regents of the University of California.
# Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
# Written by Brian Behlendorf <behlendorf1@llnl.gov>.
# UCRL-CODE-235197
#
# This file is part of the SPL, Solaris Porting Layer.
# For details, see <http://github.com/behlendorf/spl/>.
#
# The SPL is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# The SPL is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with the SPL.  If not, see <http://www.gnu.org/licenses/>.
###############################################################################

AC_INIT(m4_esyscmd([awk '/^Name:/ {print $2}' META | tr -d '\n']),
	m4_esyscmd([awk '/^Version:/ {print $2}' META | tr -d '\n']))
AC_LANG(C)
SPL_AC_META
SPL_AC_CONFIG
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_SYSTEM
AM_MAINTAINER_MODE
AM_SILENT_RULES
#AC_INIT([$SPL_META_NAME], [$SPL_META_VERSION])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([spl_config.h], [
	(mv spl_config.h spl_config.h.tmp &&
	awk -f ${ac_srcdir}/config/config.awk spl_config.h.tmp >spl_config.h &&
	rm spl_config.h.tmp) || exit 1])

AC_PROG_INSTALL

dnl save $CFLAGS since AC_PROG_CC likes to insert "-g -O2"
dnl if $CFLAGS is blank
cflags_save="$CFLAGS"
AC_PROG_CC
CFLAGS="$cflags_save"
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

AM_CONDITIONAL([CONFIG_KERNEL], [ true ])
AM_CONDITIONAL([CONFIG_USER], [ true ])

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	cmd/Makefile
	module/Makefile
	module/spl/Makefile
	module/splat/Makefile
	include/Makefile
	scripts/Makefile
	spl.spec
	spl-modules.spec
	PKGBUILD-spl
	PKGBUILD-spl-modules
	spl.release
	dkms.conf
])

AC_OUTPUT

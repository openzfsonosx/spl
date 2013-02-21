/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://github.com/behlendorf/spl/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
\*****************************************************************************/

#ifndef _SPL_TYPES_H
#define	_SPL_TYPES_H

// Linux kernel optimization
#define unlikely
#define likely

#include_next <sys/types.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <libkern/libkern.h>

//#include <linux/uaccess_compat.h>
//#include <linux/file_compat.h>
//#include <linux/list_compat.h>
//#include <linux/time_compat.h>
//#include <linux/bitops_compat.h>
//#include <linux/smp_compat.h>
//#include <linux/workqueue_compat.h>
//#include <linux/kallsyms_compat.h>
//#include <linux/mutex_compat.h>
//#include <linux/module_compat.h>
//#include <linux/sysctl_compat.h>
//#include <linux/proc_compat.h>
//#include <linux/math64_compat.h>
//#include <linux/zlib_compat.h>




#if 0
#ifndef HAVE_UINTPTR_T
typedef unsigned long			uintptr_t;
#endif
#endif

#ifndef ULLONG_MAX
#define ULLONG_MAX			(~0ULL)
#endif

#ifndef LLONG_MAX
#define LLONG_MAX			((long long)(~0ULL>>1))
#endif

#if 0
typedef unsigned long			intptr_t;
typedef unsigned long long		u_offset_t;
typedef struct task_struct		kthread_t;
typedef struct task_struct		proc_t;
typedef struct vmem { }			vmem_t;
typedef struct timespec			timestruc_t; /* definition per SVr4 */
typedef struct timespec			timespec_t;
typedef u_longlong_t			len_t;
typedef longlong_t			diskaddr_t;
typedef ushort_t			o_mode_t;
typedef uint_t				major_t;
typedef uint_t				minor_t;
typedef ulong_t				pfn_t;
typedef long				spgcnt_t;
typedef short				index_t;
typedef int				id_t;

extern proc_t p0;
typedef enum { B_FALSE=0, B_TRUE=1 }	boolean_t;
#endif

enum { B_FALSE=0, B_TRUE=1 };
typedef short				pri_t;
typedef unsigned long			ulong_t;
typedef unsigned long long		u_longlong_t;
typedef unsigned long long		rlim64_t;
typedef unsigned long long		loff_t;
typedef long long			longlong_t;
typedef unsigned char			uchar_t;
typedef unsigned int			uint_t;
typedef unsigned short			ushort_t;
typedef void *spinlock_t;
typedef long long			offset_t;
typedef struct timespec			timestruc_t; /* definition per SVr4 */
typedef struct timespec			timespec_t;
typedef ulong_t				pgcnt_t;
typedef unsigned int umode_t ;


#define EBADE EBADMACHO

#include  <sys/fcntl.h>
#define FCREAT          O_CREAT
#define FTRUNC          O_TRUNC
#define FEXCL           O_EXCL
#define FNOCTTY         O_NOCTTY
//#define       FASYNC          O_SYNC
#define FNOFOLLOW       O_NOFOLLOW

#define FSYNC           0x10    /* file (data+inode) integrity while writing */
#define FDSYNC          0x40    /* file data only integrity while writing */
#define FRSYNC          0x8000  /* sync read operations at same level of */
                                /* integrity as specified for writes by */
                                /* FSYNC and FDSYNC flags */
#define FOFFMAX         0x2000  /* large file */

#define EXPORT_SYMBOL(X)
#define module_param(X,Y,Z)
#define MODULE_PARM_DESC(X,Y)

#ifdef __GNUC__
#define member_type(type, member) __typeof__ (((type *)0)->member)
#else
#define member_type(type, member) void
#endif

#define container_of(ptr, type, member) ((type *)(                      \
      (char *)(member_type(type, member) *){ ptr } - offsetof(type, member)))

#endif	/* _SPL_TYPES_H */

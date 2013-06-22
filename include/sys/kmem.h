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

#ifndef _SPL_KMEM_H
#define	_SPL_KMEM_H

//#include <linux/module.h>
//#include <linux/slab.h>
//#include <linux/vmalloc.h>
//#include <linux/mm_compat.h>
//#include <linux/spinlock.h>
//#include <linux/rwsem.h>
//#include <linux/hash.h>
//#include <linux/ctype.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/vmsystm.h>
#include <sys/kstat.h>
#include <sys/malloc.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern uint64_t physmem;

#define KERN_MAP_MIN_SIZE (8192+1)

/*
 * Used internally, the kernel does not need to support this flag
 */
#ifndef __GFP_ZERO
# define __GFP_ZERO                     0x8000
#endif

/*
 * PF_NOFS is a per-process debug flag which is set in current->flags to
 * detect when a process is performing an unsafe allocation.  All tasks
 * with PF_NOFS set must strictly use KM_PUSHPAGE for allocations because
 * if they enter direct reclaim and initiate I/O the may deadlock.
 *
 * When debugging is disabled, any incorrect usage will be detected and
 * a call stack with warning will be printed to the console.  The flags
 * will then be automatically corrected to allow for safe execution.  If
 * debugging is enabled this will be treated as a fatal condition.
 *
 * To avoid any risk of conflicting with the existing PF_ flags.  The
 * PF_NOFS bit shadows the rarely used PF_MUTEX_TESTER bit.  Only when
 * CONFIG_RT_MUTEX_TESTER is not set, and we know this bit is unused,
 * will the PF_NOFS bit be valid.  Happily, most existing distributions
 * ship a kernel with CONFIG_RT_MUTEX_TESTER disabled.
 */
#if !defined(CONFIG_RT_MUTEX_TESTER) && defined(PF_MUTEX_TESTER)
# define PF_NOFS			PF_MUTEX_TESTER

static inline void
sanitize_flags(struct task_struct *p, gfp_t *flags)
{
	if (unlikely((p->flags & PF_NOFS) && (*flags & (__GFP_IO|__GFP_FS)))) {
# ifdef NDEBUG
		SDEBUG_LIMIT(SD_CONSOLE | SD_WARNING, "Fixing allocation for "
		   "task %s (%d) which used GFP flags 0x%x with PF_NOFS set\n",
		    p->comm, p->pid, flags);
		spl_debug_dumpstack(p);
		*flags &= ~(__GFP_IO|__GFP_FS);
# else
		PANIC("FATAL allocation for task %s (%d) which used GFP "
		    "flags 0x%x with PF_NOFS set\n", p->comm, p->pid, flags);
# endif /* NDEBUG */
	}
}
#else
# define PF_NOFS			0x00000000
# define sanitize_flags(p, fl)		((void)0)
#endif /* !defined(CONFIG_RT_MUTEX_TESTER) && defined(PF_MUTEX_TESTER) */

/*
 * __GFP_NOFAIL looks like it will be removed from the kernel perhaps as
 * early as 2.6.32.  To avoid this issue when it occurs in upstream kernels
 * we retry the allocation here as long as it is not __GFP_WAIT (GFP_ATOMIC).
 * I would prefer the caller handle the failure case cleanly but we are
 * trying to emulate Solaris and those are not the Solaris semantics.
 */

#define POINTER_IS_VALID(p)     (!((uintptr_t)(p) & 0x3))
#define POINTER_INVALIDATE(pp)  (*(pp) = (void *)((uintptr_t)(*(pp)) | 0x1))

#define KM_SLEEP                M_WAITOK
#define KM_PUSHPAGE             M_WAITOK
#define KM_NOSLEEP              M_NOWAIT
#define KM_ZERO                 M_ZERO
#define KM_NODEBUG              0
#define    KMC_NODEBUG     0x00020000
#define KMC_NOTOUCH             0

typedef struct kmem_cache {
        char            kc_name[32];
        size_t          kc_size;
        int             (*kc_constructor)(void *, void *, int);
        void            (*kc_destructor)(void *, void *);
        void            *kc_private;
} kmem_cache_t;

#define vmem_t  void

void *zfs_kmem_alloc(size_t size, int kmflags);
void zfs_kmem_free(void *buf, size_t size);
uint64_t kmem_size(void);
uint64_t kmem_used(void);
kmem_cache_t *kmem_cache_create(char *name, size_t bufsize, size_t align,
    int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
    void (*reclaim)(void *) __unused, void *_private, vmem_t *vmp, int cflags);
void kmem_cache_destroy(kmem_cache_t *cache);
void *kmem_cache_alloc(kmem_cache_t *cache, int flags);
void kmem_cache_free(kmem_cache_t *cache, void *buf);
void kmem_cache_reap_now(kmem_cache_t *cache);
void kmem_reap(void);
int kmem_debugging(void);
void *calloc(size_t n, size_t s);

#define	vmem_alloc(size, vmflag)	zfs_kmem_alloc((size), (vmflag))
#define vmem_zalloc(sz, fl)         zfs_kmem_alloc((sz), (fl)|M_ZERO)
#define	vmem_free(vaddr, size)		zfs_kmem_free((vaddr), (size))

#define kmem_alloc(size, kmflags)   zfs_kmem_alloc((size), (kmflags))
#define kmem_zalloc(size, kmflags)  zfs_kmem_alloc((size), (kmflags) | M_ZERO)
#define kmem_free(buf, size)        zfs_kmem_free((buf), (size))

#define kmem_cache_set_move(cache, movefunc)    do { } while (0)


extern void *zfs_kmem_zalloc(size_t size, int kmflags);
extern char *kmem_asprintf(const char *fmt, ...);
extern void strfree(char *str);
extern char *kmem_vasprintf(const char *fmt, va_list ap);

void spl_kmem_init(void);
void spl_kmem_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SPL_KMEM_H */

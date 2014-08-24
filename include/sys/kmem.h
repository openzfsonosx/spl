/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *
 * Copyright (C) 2008 MacZFS Project
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */



#ifndef _SPL_KMEM_H
#define	_SPL_KMEM_H

#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/vmsystm.h>
#include <sys/kstat.h>
#include <sys/malloc.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
    extern uint64_t physmem;
    
#define KERN_MAP_MIN_SIZE (8192+1)
    
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
    
#define KMC_NOTOUCH     0x00010000
#define KMC_NODEBUG     0x00020000
#define KMC_NOMAGAZINE  0x00040000
#define KMC_NOHASH      0x00080000
#define KMC_QCACHE      0x00100000
#define KMC_KMEM_ALLOC  0x00200000      /* internal use only */
#define KMC_IDENTIFIER  0x00400000      /* internal use only */
#define KMC_PREFILL     0x00800000
    
#define KM_SLEEP                M_WAITOK
#define KM_PUSHPAGE             M_WAITOK
#define KM_NOSLEEP              M_NOWAIT
#define KM_ZERO                 M_ZERO
#define KM_NODEBUG              0
    
    /*
     * Cache callback function types
     */
    typedef int (*constructor_fn_t)(void*, void*, int);
    typedef void (*destructor_fn_t)(void*, void*);
    typedef void (*reclaim_fn_t)(void*);
    
    /*
     *   Cache internal strategys
     */
    typedef void* (*cache_alloc_strategy_t)();
    typedef void (*cache_free_strategy_t)();
    
    /*
     * Magazine
     */
    typedef struct kmem_magazine {
        list_node_t mag_node;     /* Unused Magazines cached */
        void       *mag_round[1]; /* Magazine round(s) */
    } kmem_magazine_t;
    
    /*
     * The magazine lists used in the depot.
     */
    typedef struct kmem_maglist {
        list_t      ml_list;       /* magazine list */
        long        ml_total;      /* number of magazines */
        long        ml_min;        /* min since last update */
        long        ml_reaplimit;  /* max reapable magazines */
        uint64_t    ml_alloc;      /* allocations from this list */
    } kmem_maglist_t;
    
    /*
     * Per CPU cache data
     */
    typedef struct kmem_cpu_cache {
        kmutex_t          cc_lock;     /* protects this cpu's local cache */
        
        uint64_t          cc_alloc;    /* allocations from this cpu */
        uint64_t          cc_free;     /* frees to this cpu */
        kmem_magazine_t  *cc_loaded;   /* the currently loaded magazine */
        kmem_magazine_t  *cc_ploaded;  /* the previously loaded magazine */
        int               cc_flags;    /* CPU-local copy of cache_flags */
        short             cc_rounds;   /* number of objects in loaded mag */
        short             cc_prounds;  /* number of objects in previous mag */
        short             cc_magsize;  /* number of rounds in a full mag */
    } kmem_cpu_cache_t;
    
    /*
     * Cache
     */
    typedef struct kmem_cache {
        /*
         * Cache
         */
        char                 kc_name[32];
        uint64_t             kc_size;
        constructor_fn_t     kc_constructor;
        destructor_fn_t      kc_destructor;
        reclaim_fn_t         kc_reclaim;
        void                *kc_private;
        
        uint64_t             kc_alloc_count;
        
        // FIXME
        //cache_alloc_strategy_t kc_alloc_strategy;
        //cache_free_strategy_t  kc_free_strategy;
        
        /*
         * Slab layer
         */
        size_t               kc_cache_chunksize;             /* buf + alignment [+ debug] */
        
        /*
         * Depot
         */
        kmutex_t             kc_cache_depot_lock;            /* protects depot */
        uint64_t             kc_cache_depot_contention;      /* contention count */
        uint64_t             kc_cache_depot_contention_prev; /* previous snapshot */
        kmem_maglist_t       kc_cache_full;                  /* full magazines */
        kmem_maglist_t       kc_cache_empty;                 /* empty magazines */
        struct kmem_magtype *kc_magtype;                     /* magazine */
        
        /*
         * Per CPU structures
         */
        kmem_cpu_cache_t    *kc_cache_cpu;                   /* per-cpu data */
        
        /*
         * Managements structures
         */
        list_node_t          kc_cache_link_node;             /* internal */
    } kmem_cache_t;
    
#define vmem_t  void
    
    void *zfs_kmem_alloc(size_t size, int kmflags);
    void zfs_kmem_free(void *buf, size_t size);
    uint64_t kmem_size(void);
    uint64_t kmem_used(void);
    uint64_t kmem_avail(void);
    uint64_t kmem_num_pages_wanted();
    int spl_vm_pool_low(void);
    
    kmem_cache_t *kmem_cache_create(char *name, size_t bufsize, size_t align,
                                    int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
                                    void (*reclaim)(void *), void *_private, vmem_t *vmp, int cflags);
    void kmem_cache_destroy(kmem_cache_t *cache);
    void *kmem_cache_alloc(kmem_cache_t *cache, int flags);
    void kmem_cache_free(kmem_cache_t *cache, void *buf);
    void kmem_cache_reap_now(kmem_cache_t *cache);
    void kmem_reap(void);
    void kmem_flush();
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
    
    void spl_kmem_init(uint64_t);
    void spl_kmem_tasks_init();
    void spl_kmem_tasks_fini();
    void spl_kmem_fini(void);
    
#ifdef	__cplusplus
}
#endif

#endif	/* _SPL_KMEM_H */

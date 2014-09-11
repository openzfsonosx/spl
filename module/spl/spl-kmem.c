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
 * Copyright (C) 2008 MacZFS
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 * Copyright (C) 2014 Brendon Humphrey <brendon.humphrey@mac.com>
 *
 */

#include <spl-debug.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kstat.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <kern/sched_prim.h>
#include "spl-bmalloc.h"

//===============================================================
// Options
//===============================================================
//#define PRINT_CACHE_STATS 1

//===============================================================
// OS Interface
//===============================================================

// This variable is a count of the number of threads
// blocked waiting for memory pages to become free.
// We are using wake indications on this event as a
// indication of paging activity, and therefore as a
// proxy to the machine experiencing memory pressure.
extern unsigned int vm_page_free_wanted;

extern unsigned int vm_page_free_count;
extern unsigned int vm_page_speculative_count;

// Can be polled to determine if the VM is experiecing
// a shortage of free pages.
extern int vm_pool_low(void);

// Kernel API for monitoring memory pressure.
extern kern_return_t
mach_vm_pressure_monitor(boolean_t	wait_for_pressure,
						 unsigned int	nsecs_monitored,
						 unsigned int	*pages_reclaimed_p,
						 unsigned int	*pages_wanted_p);

// Which CPU are we executing on?
extern int cpu_number();

//===============================================================
// Variables
//===============================================================

// Measure the wakeup count of the memory monitor thread
unsigned long		wake_count = 0; // DEBUG

// Indicates that the machine is believed to be swapping
// due to thread waking. This is reset when spl_vm_pool_low()
// is called and reports the activity to ZFS.
int					machine_is_swapping = 0;

// Flag to cause tasks and threads to terminate as
// the kmem module is preparing to unload.
int					shutting_down = 0;

uint64_t			physmem = 0;

// Size in bytes of the memory allocated by bmalloc resuling from
// allocation calls to the SPL. The ratio of
// total_in_use :bmalloc_allocated_total is an indication of
// the space efficiency of bmalloc.
extern uint64_t		bmalloc_allocated_total;

// Size in bytes of all memory allocated by applications via bmalloc
extern uint64_t		bmalloc_app_allocated_total;

// Number of active threads
extern uint64_t     zfs_threads;

// Number of pages the OS last reported that it needed freed
unsigned int		num_pages_wanted = 0;

static kmutex_t		kmem_cache_lock;    /* inter-cache linkage only */
static list_t		kmem_caches;

// Task queue for processing kmem internal tasks.
static taskq_t		*kmem_taskq;

//static vmem_t		*kmem_metadata_arena;
//static vmem_t		*kmem_msb_arena;	/* arena for metadata caches */
//static vmem_t		*kmem_cache_arena;
//static vmem_t		*kmem_hash_arena;
//static vmem_t		*kmem_log_arena;
//static vmem_t		*kmem_oversize_arena;
//static vmem_t		*kmem_va_arena;
//static vmem_t		*kmem_default_arena;
//static vmem_t		*kmem_firewall_va_arena;
//static vmem_t		*kmem_firewall_arena;

//kmem_log_header_t	*kmem_transaction_log;
//kmem_log_header_t	*kmem_content_log;
//kmem_log_header_t	*kmem_failure_log;
//kmem_log_header_t	*kmem_slab_log;

/*
 * The default set of caches to back kmem_alloc().
 * These sizes should be reevaluated periodically.
 *
 * We want allocations that are multiples of the coherency granularity
 * (64 bytes) to be satisfied from a cache which is a multiple of 64
 * bytes, so that it will be 64-byte aligned.  For all multiples of 64,
 * the next kmem_cache_size greater than or equal to it must be a
 * multiple of 64.
 *
 * We split the table into two sections:  size <= 4k and size > 4k.  This
 * saves a lot of space and cache footprint in our cache tables.
 */
static const int kmem_alloc_sizes[] = {
	1 * 8,
	2 * 8,
	3 * 8,
	4 * 8,		5 * 8,		6 * 8,		7 * 8,
	4 * 16,		5 * 16,		6 * 16,		7 * 16,
	4 * 32,		5 * 32,		6 * 32,		7 * 32,
	4 * 64,		5 * 64,		6 * 64,		7 * 64,
	4 * 128,	5 * 128,	6 * 128,	7 * 128,
	P2ALIGN(8192 / 7, 64),
	P2ALIGN(8192 / 6, 64),
	P2ALIGN(8192 / 5, 64),
	P2ALIGN(8192 / 4, 64),
	P2ALIGN(8192 / 3, 64),
	P2ALIGN(8192 / 2, 64),
};

static const int kmem_big_alloc_sizes[] = {
	2 * 4096,	3 * 4096,
	2 * 8192,	3 * 8192,
	4 * 8192,	5 * 8192,	6 * 8192,	7 * 8192,
	8 * 8192,	9 * 8192,	10 * 8192,	11 * 8192,
	12 * 8192,	13 * 8192,	14 * 8192,	15 * 8192,
	16 * 8192
};

#define	KMEM_MAXBUF		4096
#define	KMEM_BIG_MAXBUF_32BIT	32768
#define	KMEM_BIG_MAXBUF		131072

#define	KMEM_BIG_MULTIPLE	4096	/* big_alloc_sizes must be a multiple */
#define	KMEM_BIG_SHIFT		12	/* lg(KMEM_BIG_MULTIPLE) */

static kmem_cache_t *kmem_alloc_table[KMEM_MAXBUF >> KMEM_ALIGN_SHIFT];
static kmem_cache_t *kmem_big_alloc_table[KMEM_BIG_MAXBUF >> KMEM_BIG_SHIFT];

#define	KMEM_ALLOC_TABLE_MAX	(KMEM_MAXBUF >> KMEM_ALIGN_SHIFT)
static size_t kmem_big_alloc_table_max = 0;	/* # of filled elements */

static kmem_magtype_t kmem_magtype[] = {
	{ 1,	8,	3200,	131072	},
	{ 3,	16,	256,	32768	},
	{ 7,	32,	64,	16384	},
	{ 15,	64,	0,	8192	},
	{ 31,	64,	0,	4096	},
	{ 47,	64,	0,	2048	},
	{ 63,	64,	0,	1024	},
	{ 95,	64,	0,	512	},
	{ 143,	64,	0,	0	},
};

static kmem_cache_t		*kmem_slab_cache;
static kmem_cache_t		*kmem_bufctl_cache;
static kmem_cache_t		*kmem_bufctl_audit_cache;

static kmutex_t			kmem_cache_lock;/* inter-cache linkage only */
static list_t			kmem_caches;

// Lock manager stuff
static lck_grp_t        *kmem_lock_group = NULL;
static lck_attr_t       *kmem_lock_attr = NULL;
static lck_grp_attr_t	*kmem_group_attr = NULL;

size_t	kmem_max_cached = KMEM_BIG_MAXBUF;	/* maximum kmem_alloc cache */

static int kmem_depot_contention = 3;	/* max failed tryenters per real interval */

static struct timespec	kmem_reap_all_task_timeout	= {15, 0};			// 15 seconds
static struct timespec	reap_finish_task_timeout	= {0, 500000000};	// 0.5 seconds
static struct timespec	kmem_update_interval		= {15, 0};			// 15 seconds
static struct timespec	bmalloc_task_timeout		= {2, 500000000};	// 2.5 Seconds

static kcondvar_t memory_monitor_cv;
static kmutex_t memory_monitor_cv_lock;

#ifdef PRINT_CACHE_STATS
static struct timespec print_all_cache_stats_task_timeout = {60, 0};
#endif

//===============================================================
// Kstats published for bmalloc
//===============================================================

typedef struct bmalloc_stats {
	kstat_named_t bmalloc_app_allocated;
	kstat_named_t bmalloc_system_allocated;
	kstat_named_t bmalloc_space_efficiency_percent;
	kstat_named_t bmalloc_active_threads;
} bmalloc_stats_t;

static bmalloc_stats_t bmalloc_stats = {
	{"apps_allocated", KSTAT_DATA_UINT64},
	{"bmalloc_allocated", KSTAT_DATA_UINT64},
	{"space_efficiency_percent", KSTAT_DATA_UINT64},
	{"active_threads", KSTAT_DATA_UINT64},
};

static kstat_t *bmalloc_ksp = 0;

//===============================================================
// Forward Declarations
//===============================================================

static void bmalloc_maintenance_task_proc(void *p);
static void kmem_reap_task(void *p);

void bmalloc_release_memory_task();
void memory_pressure_task();

static void kmem_reap_task_finish(void *p);
static void reap_finish_task_proc();

static void kmem_reap_all_task();
static void kmem_reap_all_task_proc();

#ifdef PRINT_CACHE_STATS
static void print_all_cache_stats_task();
static void print_all_cache_stats_task_proc();
#endif

static void kmem_update(void *);

//===============================================================
// Allocation and release calls
//===============================================================

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
    size_t index;
	kmem_cache_t *cp;
	void *buf;

	if ((index = ((size - 1) >> KMEM_ALIGN_SHIFT)) < KMEM_ALLOC_TABLE_MAX) {
		cp = kmem_alloc_table[index];
		/* fall through to kmem_cache_alloc() */

	} else if ((index = ((size - 1) >> KMEM_BIG_SHIFT)) <
               kmem_big_alloc_table_max) {
		cp = kmem_big_alloc_table[index];
		/* fall through to kmem_cache_alloc() */

	} else {
		if (size == 0)
			return (NULL);

		buf = bmalloc(size, kmflags);

		return (buf);
	}

	buf = kmem_cache_alloc(cp, kmflags);

    /*
     if ((cp->cache_flags & KMF_BUFTAG) && !KMEM_DUMP(cp) && buf != NULL) {
		kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
		((uint8_t *)buf)[size] = KMEM_REDZONE_BYTE;
		((uint32_t *)btp)[1] = KMEM_SIZE_ENCODE(size);

		if (cp->cache_flags & KMF_LITE) {
			KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count, caller());
		}
	}
    */

    if (!buf) {
        printf("[spl] kmem_alloc(%lu) failed: \n", size);
    }

	return (buf);
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
	void *buf = kmem_alloc(size, kmflags);

    if (buf) {
		bzero(buf, size);
	}

	return (buf);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    size_t index;
	kmem_cache_t *cp;

    ASSERT(buf && size);

	if ((index = (size - 1) >> KMEM_ALIGN_SHIFT) < KMEM_ALLOC_TABLE_MAX) {
		cp = kmem_alloc_table[index];
		/* fall through to kmem_cache_free() */

	} else if ((index = ((size - 1) >> KMEM_BIG_SHIFT)) <
               kmem_big_alloc_table_max) {
		cp = kmem_big_alloc_table[index];
		/* fall through to kmem_cache_free() */

	} else {
		//EQUIV(buf == NULL, size == 0);
		if (buf == NULL && size == 0)
			return;
		bfree(buf, size);
		return;
	}

    /*
	if ((cp->cache_flags & KMF_BUFTAG) && !KMEM_DUMP(cp)) {
		kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
		uint32_t *ip = (uint32_t *)btp;
		if (ip[1] != KMEM_SIZE_ENCODE(size)) {
			if (*(uint64_t *)buf == KMEM_FREE_PATTERN) {
				kmem_error(KMERR_DUPFREE, cp, buf);
				return;
			}
			if (KMEM_SIZE_VALID(ip[1])) {
				ip[0] = KMEM_SIZE_ENCODE(size);
				kmem_error(KMERR_BADSIZE, cp, buf);
			} else {
				kmem_error(KMERR_REDZONE, cp, buf);
			}
			return;
		}
		if (((uint8_t *)buf)[size] != KMEM_REDZONE_BYTE) {
			kmem_error(KMERR_REDZONE, cp, buf);
			return;
		}
		btp->bt_redzone = KMEM_REDZONE_PATTERN;
		if (cp->cache_flags & KMF_LITE) {
			KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count,
                                   caller());
		}
	}
     */
	kmem_cache_free(cp, buf);
}

void *
calloc(size_t n, size_t s)
{
	return (kmem_zalloc(n * s, KM_NOSLEEP));
}

//===============================================================
// Status
//===============================================================

uint64_t
kmem_num_pages_wanted()
{
	uint64_t tmp = num_pages_wanted;
	num_pages_wanted = 0;

	//printf("num pages wanted -> %llu\n", tmp);

	return tmp;
}

uint64_t
kmem_size(void)
{
	return (physmem * PAGE_SIZE);
}

uint64_t
kmem_used(void)
{
    return bmalloc_app_allocated_total;
}

uint64_t
kmem_avail(void)
{
    return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
}

int
kmem_debugging(void)
{
	return (0);
}

int spl_vm_pool_low(void)
{
	int r = machine_is_swapping;
	machine_is_swapping = 0;
    return r;
}

// ===========================================================
// CACHE - iteration
// ===========================================================

static void
kmem_cache_applyall(void (*func)(kmem_cache_t *), taskq_t *tq, int tqflag)
{
	kmem_cache_t *cp;

	//printf("kmem cache apply all\n");

	mutex_enter(&kmem_cache_lock);
	for (cp = list_head(&kmem_caches); cp != NULL;
         cp = list_next(&kmem_caches, cp))
		if (tq != NULL)
			(void) taskq_dispatch(tq, (task_func_t *)func, cp,
                                  tqflag);
		else
			func(cp);

	mutex_exit(&kmem_cache_lock);
}

// ===========================================================
// CACHE - magazine
// ===========================================================


static kmem_magazine_t*
kmem_magazine_alloc_init(kmem_cache_t* cp, int flags)
{
    kmem_magazine_t* mag = 0;
    kmem_magtype_t *mtp = cp->cache_magtype;

    // Illumos uses a kmem_cache of magazines, but I dont understand how
    // nested manazines work, so will just use a simple linked
    // list of cache magazines. This will result in some sort
    // of scalability penalty.

    lck_spin_lock(mtp->mt_lock);
    if(!list_empty(&mtp->mt_list)) {
        mag = list_head(&mtp->mt_list);
        list_remove_head(&mtp->mt_list);
    }
    lck_spin_unlock(mtp->mt_lock);

    if (!mag) {
        uint64_t alloc_size = sizeof(list_node_t) + (mtp->mt_magsize * sizeof(void*));
        mag = bzmalloc(alloc_size, flags);
    }

    return mag;
}

static void
kmem_magazine_release(kmem_cache_t *cp, kmem_magazine_t *mp)
{
    kmem_magtype_t *mtp = cp->cache_magtype;

    lck_spin_lock(mtp->mt_lock);
    list_link_init(&mp->mag_node);
    list_insert_head(&mtp->mt_list, mp);
    lck_spin_unlock(mtp->mt_lock);
}

static void
kmem_magazine_destroy(kmem_cache_t *cp, kmem_magazine_t *mp, uint64_t nrounds)
{
	//printf("kmem_magazine_destroy\n");

    int round;

    for (round = 0; round < nrounds; round++) {
        void *buf = mp->mag_round[round];

        if (cp->cache_destructor) {
            cp->cache_destructor(buf, cp->cache_private);
        }

        bfree(buf, cp->cache_bufsize);
    }

    // Place the magazine in the freelist for reuse
    kmem_magazine_release(cp, mp);
    //    lck_spin_lock(mtp->mt_lock);
    //    list_link_init(&mp->mag_node);
    //    list_insert_head(&mtp->mt_list, mp);
    //    lck_spin_unlock(mtp->mt_lock);
}

// ===========================================================
// CACHE - Magazine List
// ===========================================================

static void kmem_magazine_list_init(kmem_maglist_t* mag_list)
{
    bzero(mag_list, sizeof(kmem_maglist_t));
    list_create(&mag_list->ml_list, sizeof(kmem_magazine_t), offsetof(kmem_magazine_t, mag_node));
}

// ===========================================================
// CACHE - depot
// ===========================================================

static void
kmem_depot_init(kmem_cache_t* cp)
{
    mutex_init(&cp->cache_depot_lock, "kmem", MUTEX_DEFAULT, NULL);
    kmem_magazine_list_init(&cp->cache_full);
    kmem_magazine_list_init(&cp->cache_empty);
}

static kmem_magazine_t*
kmem_depot_alloc(kmem_cache_t *cp, kmem_maglist_t *mlp)
{
    kmem_magazine_t *mp = 0;

    /*
     * If we can't get the depot lock without contention,
     * update our contention count.  We use the depot
     * contention rate to determine whether we need to
     * increase the magazine size for better scalability.
     */
    if (likely(!mutex_tryenter(&cp->cache_depot_lock))) {
        mutex_enter(&cp->cache_depot_lock);
        cp->cache_depot_contention++;
    }

    if (likely(!list_is_empty(&mlp->ml_list))) {

        // FIXME - figure out of list_remove_head returns the removed head or the new head
        mp = list_head(&mlp->ml_list);
        list_remove_head(&mlp->ml_list);

        if (--mlp->ml_total < mlp->ml_min)
            mlp->ml_min = mlp->ml_total;
        mlp->ml_alloc++;
    }

    mutex_exit(&cp->cache_depot_lock);

    return (mp);
}

/*
 * Free a magazine to the depot.
 */
static void
kmem_depot_free(kmem_cache_t *cp, kmem_maglist_t *mlp, kmem_magazine_t *mp)
{
    mutex_enter(&cp->cache_depot_lock);
    list_link_init(&mp->mag_node);
    list_insert_head(&mlp->ml_list, mp);
    mlp->ml_total++;
    mutex_exit(&cp->cache_depot_lock);
}

static void
kmem_depot_ws_update(kmem_cache_t *cp)
{
    mutex_enter(&cp->cache_depot_lock);
    cp->cache_full.ml_reaplimit = cp->cache_full.ml_min;
    cp->cache_full.ml_min = cp->cache_full.ml_total;
    cp->cache_empty.ml_reaplimit = cp->cache_empty.ml_min;
    cp->cache_empty.ml_min = cp->cache_empty.ml_total;
    mutex_exit(&cp->cache_depot_lock);
}

static void
kmem_depot_ws_reap(kmem_cache_t *cp)
{
    long reap;
    kmem_magazine_t *mp;

    reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
    while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_full)) != NULL)
        kmem_magazine_destroy(cp, mp, cp->cache_magtype->mt_magsize);

    reap = MIN(cp->cache_empty.ml_reaplimit, cp->cache_empty.ml_min);
    while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_empty)) != NULL)
        kmem_magazine_destroy(cp, mp, 0);
}

static void
kmem_depot_fini(kmem_cache_t *cp)
{
    // FIXME - empty the linked lists, release all memory
    mutex_destroy(&cp->cache_depot_lock);
}

// ===========================================================
// CACHE - cpu cache
// ===========================================================

static void
kmem_cpu_cache_init(kmem_cpu_cache_t* cpu_cache)
{
    bzero(cpu_cache, sizeof(kmem_cpu_cache_t));
    mutex_init(&cpu_cache->cc_lock, "kmem", MUTEX_DEFAULT, NULL);
    cpu_cache->cc_rounds = -1;
    cpu_cache->cc_prounds = -1;
}

static void
kmem_cpu_cache_fini(kmem_cpu_cache_t* cpu_cache)
{
    mutex_destroy(&cpu_cache->cc_lock);
}

static void
kmem_cpu_cache_reload(kmem_cpu_cache_t *ccp, kmem_magazine_t *mp, int rounds)
{
    ccp->cc_ploaded = ccp->cc_loaded;
    ccp->cc_prounds = ccp->cc_rounds;
    ccp->cc_loaded = mp;
    ccp->cc_rounds = rounds;
}

static int
kmem_cpu_cache_magazine_alloc(kmem_cpu_cache_t *ccp, kmem_cache_t *cp)
{
    kmem_magazine_t *emp;
	kmem_magtype_t *mtp;

    emp = kmem_depot_alloc(cp, &cp->cache_empty);
    if (emp != NULL) {
        if (ccp->cc_ploaded != NULL)
            kmem_depot_free(cp, &cp->cache_full, ccp->cc_ploaded);
        kmem_cpu_cache_reload(ccp, emp, 0);
        return (1);
    }

    /*
     * There are no empty magazines in the depot,
     * so try to allocate a new one.
     */
    mtp = cp->cache_magtype;
    mutex_exit(&ccp->cc_lock);

    emp = kmem_magazine_alloc_init(cp, KM_NOSLEEP);  //  FIXME flags KM_NOSLEEP);

    mutex_enter(&ccp->cc_lock);


	if (emp != NULL) {
		/*
		 * We successfully allocated an empty magazine.
		 * However, we had to drop ccp->cc_lock to do it,
		 * so the cache's magazine size may have changed.
		 * If so, free the magazine and try again.
		 */
		if (ccp->cc_magsize != mtp->mt_magsize) {
			//mutex_exit(&ccp->cc_lock);
			// FIXME lets just leak this for now - where does it release to? kmem_magazine_release(cp, emp);
			//mutex_enter(&ccp->cc_lock);
			return (1);
		}

        /*
         * We got a magazine of the right size.  Add it to
         * the depot and try the whole dance again.
         */
        kmem_depot_free(cp, &cp->cache_empty, emp);
        return (1);
    }

    /*
     * We couldn't allocate an empty magazine,
     * so fall through to the slab layer.
     */
    return (0);
}


// ===========================================================
// CACHE - body
// ===========================================================

static
void kmem_cache_magazine_enable(kmem_cache_t* cp)
{
    int cpu_seqid;

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];

        mutex_enter(&ccp->cc_lock);
        ccp->cc_magsize = cp->cache_magtype->mt_magsize;
        mutex_exit(&ccp->cc_lock);
    }
}

static void
kmem_cache_magazine_purge(kmem_cache_t *cp)
{
    kmem_cpu_cache_t *ccp;
    kmem_magazine_t *mp, *pmp;
    int rounds, prounds, cpu_seqid;

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        ccp = &cp->cache_cpu[cpu_seqid];

        mutex_enter(&ccp->cc_lock);

        mp = ccp->cc_loaded;
        pmp = ccp->cc_ploaded;
        rounds = ccp->cc_rounds;
        prounds = ccp->cc_prounds;
        ccp->cc_loaded = NULL;
        ccp->cc_ploaded = NULL;
        ccp->cc_rounds = -1;
        ccp->cc_prounds = -1;
        ccp->cc_magsize = 0;

        mutex_exit(&ccp->cc_lock);

        if (mp)
            kmem_magazine_destroy(cp, mp, rounds);

        if (pmp)
            kmem_magazine_destroy(cp, pmp, prounds);
    }

    /*
     * Updating the working set statistics twice in a row has the
     * effect of setting the working set size to zero, so everything
     * is eligible for reaping.
     */
    kmem_depot_ws_update(cp);
    kmem_depot_ws_update(cp);

    kmem_depot_ws_reap(cp);
}

kmem_cache_t *
kmem_cache_create(char *name, size_t bufsize, size_t align,
                  int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
                  void (*reclaim)(void *), void *private, vmem_t *vmp, int cflags)
{
    kmem_cache_t *cache;
    kmem_magtype_t *mtp;
    size_t chunksize;

    cache = bmalloc(sizeof(*cache), KM_SLEEP);
    bzero(cache, sizeof(kmem_cache_t));

    strlcpy(cache->cache_name, name, sizeof(cache->cache_name));
    cache->cache_constructor = constructor;
    cache->cache_destructor = destructor;
    cache->cache_reclaim = reclaim;
    cache->cache_private = private;
    cache->cache_bufsize = bufsize;

    cache->cache_alloc_count = 0;

    kmem_depot_init(cache);

    // FIXME check this is 64 bit aligned
    cache->cache_cpu = bmalloc(max_ncpus * sizeof(kmem_cpu_cache_t), KM_SLEEP);
    for (int i=0; i<max_ncpus; i++) {
        kmem_cpu_cache_init(&cache->cache_cpu[i]);
    }

    /*
     * Massive differences to illumos here.
     * all the slab stuff is missing.
     */

    /*
     * Select magazine to use etc
     */
    chunksize = bufsize;
    cache->cache_chunksize = chunksize;

    for (mtp = kmem_magtype; chunksize <= mtp->mt_minbuf; mtp++)
        continue;

    cache->cache_magtype = mtp;

    /*
     * Add the cache to the global list.  This makes it visible
     * to kmem_update(), so the cache must be ready for business.
     */
    mutex_enter(&kmem_cache_lock);
    list_insert_tail(&kmem_caches, cache);
    mutex_exit(&kmem_cache_lock);

    kmem_cache_magazine_enable(cache);

    return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
    /*
     * Remove the cache from the global cache list so that no one else
     * can schedule tasks on its behalf, wait for any pending tasks to
     * complete, purge the cache, and then destroy it.
     */
    mutex_enter(&kmem_cache_lock);
    list_remove(&kmem_caches, cp);
    mutex_exit(&kmem_cache_lock);

    kmem_cache_magazine_purge(cp);

    /*
     * The cache is now dead.  There should be no further activity.  We
     * enforce this by setting land mines in the constructor, destructor,
     * reclaim, and move routines that induce a kernel text fault if
     * invoked.
     */
    cp->cache_constructor = (int (*)(void *, void *, int))1;
    cp->cache_destructor = (void (*)(void *, void *))2;
    cp->cache_reclaim = (void (*)(void *))3;

    // Terminate cache internals
    for (int i=0; i<max_ncpus; i++) {
        kmem_cpu_cache_fini(&cp->cache_cpu[i]);
    }
    kmem_depot_fini(cp);

    // Free the cache structures
    bfree(cp, sizeof(*cp));
}

void *
kmem_cache_alloc(kmem_cache_t *cp, int flags)
{
    kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_number()];
    kmem_magazine_t *fmp = 0;
    void *buf = 0;

    mutex_enter(&ccp->cc_lock);

    for(;;) {
        if (ccp->cc_rounds > 0) {
            kmem_magazine_t *mp = ccp->cc_loaded;
            void *obj = mp->mag_round[--ccp->cc_rounds];
            ccp->cc_alloc++;
            mutex_exit(&ccp->cc_lock);
            return (obj);
        }

        /*
         * The loaded magazine is empty.  If the previously loaded
         * magazine was full, exchange them and try again.
         */
        if (ccp->cc_prounds > 0) {
            kmem_cpu_cache_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
            continue;
        }

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

        /*
         * Try to get a full magazine from the depot.
         */
        fmp = kmem_depot_alloc(cp, &cp->cache_full);
        if (fmp != NULL) {
            if (ccp->cc_ploaded != NULL)
                kmem_depot_free(cp, &cp->cache_empty, ccp->cc_ploaded);
            kmem_cpu_cache_reload(ccp, fmp, ccp->cc_magsize);
            continue;
        }

        /*
         * There are no full magazines in the depot,
         * so fall through to the slab layer.
         */
        break;
    }

    mutex_exit(&ccp->cc_lock);

    /*
     * We couldn't allocate a constructed object from the magazine layer,
     * so get a raw buffer from the slab layer and apply its constructor.
     */
    buf = bmalloc(cp->cache_bufsize, flags);
    if (buf && cp->cache_constructor)
        cp->cache_constructor(buf, cp->cache_private, flags);

    return buf;
}

void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
    kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_number()];

    mutex_enter(&ccp->cc_lock);

    for (;;) {

        /*
         * If there's a slot available in the current CPU's
         * loaded magazine, just put the object there and return.
         */
        if ((uint32_t)ccp->cc_rounds < ccp->cc_magsize) {
            ccp->cc_loaded->mag_round[ccp->cc_rounds++] = buf;
            ccp->cc_free++;

            mutex_exit(&ccp->cc_lock);
            return;
        }

        //if (iters > 10)
        //    printf("[sp] [k_c_f %d %d] mag full\n", cpu_number(), iters);
        /*
         * The loaded magazine is full.  If the previously loaded
         * magazine was empty, exchange them and try again.
         */
        if (ccp->cc_prounds == 0) {
            kmem_cpu_cache_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
            continue;
        }

        /*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

        if (!kmem_cpu_cache_magazine_alloc(ccp, cp)) {
            /*
             * We couldn't free our constructed object to the
             * magazine layer, so apply its destructor and free it
             * to the slab layer.
             */
            break;
        }
    }

    mutex_exit(&ccp->cc_lock);

    if (cp->cache_destructor) {
        cp->cache_destructor(buf, cp->cache_private);
    }

    bfree(buf, cp->cache_bufsize);
}


/*
 * Call the registered reclaim function for a cache.  Depending on how
 * many and which objects are released it may simply repopulate the
 * local magazine which will then need to age-out.  Objects which cannot
 * fit in the magazine we will be released back to their slabs which will
 * also need to age out before being release.  This is all just best
 * effort and we do not want to thrash creating and destroying slabs.
 */
void
kmem_cache_reap(kmem_cache_t *cp)
{
    /*
     * Ask the cache's owner to free some memory if possible.
     * The idea is to handle things like the inode cache, which
     * typically sits on a bunch of memory that it doesn't truly
     * *need*.  Reclaim policy is entirely up to the owner; this
     * callback is just an advisory plea for help.
     */
    if (cp->cache_reclaim != NULL) {
        long delta;

        /*
         * Reclaimed memory should be reapable (not included in the
         * depot's working set).
         */
        delta = cp->cache_full.ml_total;
        cp->cache_reclaim(cp->cache_private);
        delta = cp->cache_full.ml_total - delta;
        if (delta > 0) {
            mutex_enter(&cp->cache_depot_lock);
            cp->cache_full.ml_reaplimit += delta;
            cp->cache_full.ml_min += delta;
            mutex_exit(&cp->cache_depot_lock);
        }
    }

    kmem_depot_ws_reap(cp);
}

/*
 * Call the registered reclaim function for a cache.  Depending on how
 * many and which objects are released it may simply repopulate the
 * local magazine which will then need to age-out.  Objects which cannot
 * fit in the magazine we will be released back to their slabs which will
 * also need to age out before being release.  This is all just best
 * effort and we do not want to thrash creating and destroying slabs.
 */
void
kmem_cache_reap_now(kmem_cache_t *cache)
{
	//printf("kmem_cache_reap now\n");

	(void)taskq_dispatch(kmem_taskq,
						 (task_func_t *)kmem_cache_reap,
						 cache,
						 TQ_NOSLEEP);
}

void
kmem_reap()
{
	(void)taskq_dispatch(kmem_taskq,
						 (task_func_t *)kmem_reap_task,
						 0,
						 TQ_NOSLEEP);
}

void kmem_flush()
{
	(void)taskq_dispatch(kmem_taskq, kmem_reap_task_finish, 0, TQ_PUSHPAGE);
}

//===============================================================
// Caches for serving kmem_?alloc requests
//===============================================================

static void
kmem_alloc_caches_create(const int *array, size_t count,
                         kmem_cache_t **alloc_table, size_t maxbuf, uint_t shift)
{
	char name[KMEM_CACHE_NAMELEN + 1];
	size_t table_unit = (1 << shift); /* range of one alloc_table entry */
	size_t size = table_unit;
	int i;

	for (i = 0; i < count; i++) {
		size_t cache_size = array[i];
		size_t align = KMEM_ALIGN;

		kmem_cache_t *cp;

		/* if the table has an entry for maxbuf, we're done */
		if (size > maxbuf)
			break;

		/* cache size must be a multiple of the table unit */
		ASSERT(P2PHASE(cache_bufsize, table_unit) == 0);

		/*
		 * If they allocate a multiple of the coherency granularity,
		 * they get a coherency-granularity-aligned address.
		 */
		if (IS_P2ALIGNED(cache_size, 64))
			align = 64;
		if (IS_P2ALIGNED(cache_size, PAGESIZE))
			align = PAGESIZE;
		(void) snprintf(name, sizeof (name),
                        "kmem_alloc_%lu", cache_size);

		cp = kmem_cache_create(name, cache_size, align,
                               NULL, NULL, NULL, NULL, NULL, KMC_KMEM_ALLOC);

		while (size <= cache_size) {
			alloc_table[(size - 1) >> shift] = cp;
			size += table_unit;
		}
	}

	ASSERT(size > maxbuf);		/* i.e. maxbuf <= max(cache_size) */
}

static void
kmem_cache_init(int pass, int use_large_pages)
{
	int i = 0;
	size_t maxbuf = KMEM_BIG_MAXBUF;
	kmem_magtype_t *mtp;

	/*
	 * Create the magazine caches
	 */

	for (i = 0; i < sizeof (kmem_magtype) / sizeof (*mtp); i++) {
		char name[KMEM_CACHE_NAMELEN + 1];

		mtp = &kmem_magtype[i];
		(void) snprintf(name, sizeof(name), "kmem_magazine_%d", mtp->mt_magsize);
		mtp->mt_cache = kmem_cache_create(name,
										  (mtp->mt_magsize + 1) * sizeof (void *),
										  mtp->mt_align, NULL, NULL, NULL, NULL,
										  NULL /*kmem_msb_arena*/, KMC_NOHASH);
	}

	/*
	 * Create slab caches
	 */

	kmem_slab_cache = kmem_cache_create("kmem_slab_cache",
										sizeof (kmem_slab_t), 0, NULL, NULL, NULL, NULL,
										NULL /*kmem_msb_arena*/, KMC_NOHASH);

	kmem_bufctl_cache = kmem_cache_create("kmem_bufctl_cache",
										  sizeof (kmem_bufctl_t), 0, NULL, NULL, NULL, NULL,
										  NULL /*kmem_msb_arena*/, KMC_NOHASH);

	kmem_bufctl_audit_cache = kmem_cache_create("kmem_bufctl_audit_cache",
												sizeof (kmem_bufctl_audit_t), 0, NULL, NULL, NULL, NULL,
												NULL /*kmem_msb_arena*/, KMC_NOHASH);

    /*
	 * Set up the default caches to back kmem_alloc()
	 */

	kmem_max_cached = KMEM_BIG_MAXBUF;

	kmem_alloc_caches_create(kmem_alloc_sizes, sizeof (kmem_alloc_sizes) / sizeof (int),
                             kmem_alloc_table, KMEM_MAXBUF, KMEM_ALIGN_SHIFT);

	kmem_alloc_caches_create(kmem_big_alloc_sizes, sizeof (kmem_big_alloc_sizes) / sizeof (int),
                             kmem_big_alloc_table, maxbuf, KMEM_BIG_SHIFT);

	kmem_big_alloc_table_max = maxbuf >> KMEM_BIG_SHIFT;
}

//===============================================================
// String handling
//===============================================================

void
strfree(char *str)
{
    bfree(str, strlen(str) + 1);
}

char *kvasprintf(const char *fmt, va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    p = bmalloc(len+1, KM_SLEEP);
    if (!p)
        return NULL;

    vsnprintf(p, len+1, fmt, ap);

    return p;
}

char *
kmem_vasprintf(const char *fmt, va_list ap)
{
    va_list aq;
    char *ptr;

    do {
        va_copy(aq, ap);
        ptr = kvasprintf(fmt, aq);
        va_end(aq);
    } while (ptr == NULL);

    return ptr;
}

char *
kmem_asprintf(const char *fmt, ...)
{
    va_list ap;
    char *ptr;

    do {
        va_start(ap, fmt);
        ptr = kvasprintf(fmt, ap);
        va_end(ap);
    } while (ptr == NULL);

    return ptr;
}

//===============================================================
// Memory pressure monitor thread
//===============================================================

void memory_monitor_thread_continue()
{
	static int first_time = 1;

	if (first_time) {
		//printf("memory pressure monitor thread started\n");
		first_time = 0;
		assert_wait((event_t) &vm_page_free_wanted, THREAD_UNINT);
		thread_block((thread_continue_t)memory_monitor_thread_continue);
	} else {
		kern_return_t kr;
		unsigned int nsecs_monitored = 1000000000 / 4;
		unsigned int pages_reclaimed = 0;

		while (!shutting_down) {
			wake_count++;

			kr = mach_vm_pressure_monitor(TRUE, nsecs_monitored,
										  &pages_reclaimed, &num_pages_wanted);

			if (kr == KERN_SUCCESS && num_pages_wanted) {
				memory_pressure_task(num_pages_wanted);
			}
		}
	}

	thread_exit();
}

static void start_memory_monitor()
{
	cv_init(&memory_monitor_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&memory_monitor_cv_lock, "kmem", MUTEX_DEFAULT, NULL);
	(void)thread_create(NULL, 0, memory_monitor_thread_continue, 0, 0, 0, 0, 0);
}

static void stop_memory_monitor()
{
    shutting_down = 1;
    thread_wakeup((event_t) &vm_page_free_wanted);
}

//===============================================================
// Tasks
//===============================================================

void bmalloc_maintenance_task()
{
	//printf("bmalloc gc\n");

    bmalloc_garbage_collect();
    if(!shutting_down) {
        bsd_timeout(bmalloc_maintenance_task_proc, 0, &bmalloc_task_timeout);
    }
}

static void bmalloc_maintenance_task_proc(void *p)
{
	taskq_dispatch(kmem_taskq, bmalloc_maintenance_task, 0, TQ_PUSHPAGE);
}

void memory_pressure_task(void *p)
{
	uint64_t num_pages = (uint64_t)(p);

	// Attempt to give the OS as many pages as it is
	// seeking from the memory cached by bmalloc.
	//
	// If bmalloc cant satisfy the request completely
	// then we have to resort to having ZFS start releasing memory.
	if (!bmalloc_release_pages(num_pages)) {
		// Set flag for spl_vm_pool_low callers
		machine_is_swapping = 1;

		// And request memory holders release memory.
		kmem_cache_applyall(kmem_cache_reap, 0, TQ_NOSLEEP);
	}
}

void bmalloc_release_memory_task()
{
	bmalloc_release_memory();
}

static void kmem_reap_task(void *p)
{
	// Request memory holders release memory.
	kmem_cache_applyall(kmem_cache_reap, 0, TQ_NOSLEEP);

	// Cache reaping is likely to be async, give the memory owners some
	// time to implement before cleaning out unwanted memory.
	bsd_timeout(reap_finish_task_proc, 0, &reap_finish_task_timeout);
}

static void kmem_reap_task_finish(void *p)
{
	// Drop all unwanted cached memory out of bmalloc
	bmalloc_garbage_collect();
	bmalloc_release_memory();
}

static void reap_finish_task_proc()
{
	if(!shutting_down) {
		taskq_dispatch(kmem_taskq, kmem_reap_task_finish, 0, TQ_PUSHPAGE);
    }
}

/*
 * Recompute a cache's magazine size.  The trade-off is that larger magazines
 * provide a higher transfer rate with the depot, while smaller magazines
 * reduce memory consumption.  Magazine resizing is an expensive operation;
 * it should not be done frequently.
 *
 * Changes to the magazine size are serialized by the kmem_taskq lock.
 *
 * Note: at present this only grows the magazine size.  It might be useful
 * to allow shrinkage too.
 */
static void
kmem_cache_magazine_resize(kmem_cache_t *cp)
{
	kmem_magtype_t *mtp = cp->cache_magtype;

	if (cp->cache_chunksize < mtp->mt_maxbuf) {
		kmem_cache_magazine_purge(cp);

		mutex_enter(&cp->cache_depot_lock);
		cp->cache_magtype = ++mtp;
        cp->cache_depot_contention_prev =
        cp->cache_depot_contention + INT_MAX;
		mutex_exit(&cp->cache_depot_lock);

        kmem_cache_magazine_enable(cp);
	}
}

/*
 * Perform periodic maintenance on a cache: hash rescaling, depot working-set
 * update, magazine resizing, and slab consolidation.
 */
static void
kmem_cache_update(kmem_cache_t *cp)
{
    //	int need_hash_rescale = 0;
	int need_magazine_resize = 0;

    //	ASSERT(MUTEX_HELD(&kmem_cache_lock));

	/*
	 * If the cache has become much larger or smaller than its hash table,
	 * fire off a request to rescale the hash table.
	 */
    //	mutex_enter(&cp->cache_lock);
    //
    //	if ((cp->cache_flags & KMF_HASH) &&
    //	    (cp->cache_buftotal > (cp->cache_hash_mask << 1) ||
    //	    (cp->cache_buftotal < (cp->cache_hash_mask >> 1) &&
    //	    cp->cache_hash_mask > KMEM_HASH_INITIAL)))
    //		need_hash_rescale = 1;
    //
    //	mutex_exit(&cp->cache_lock);

	/*
	 * Update the depot working set statistics.
	 */
	kmem_depot_ws_update(cp);

	/*
	 * If there's a lot of contention in the depot,
	 * increase the magazine size.
	 */
	mutex_enter(&cp->cache_depot_lock);

	if (cp->cache_chunksize < cp->cache_magtype->mt_maxbuf &&
	    (int)(cp->cache_depot_contention -
              cp->cache_depot_contention_prev) > kmem_depot_contention)
		need_magazine_resize = 1;

	cp->cache_depot_contention_prev = cp->cache_depot_contention;

	mutex_exit(&cp->cache_depot_lock);

    //	if (need_hash_rescale)
    //		(void) taskq_dispatch(kmem_taskq,
    //		    (task_func_t *)kmem_hash_rescale, cp, TQ_NOSLEEP);

	if (need_magazine_resize)
		(void) taskq_dispatch(kmem_taskq,
                              (task_func_t *)kmem_cache_magazine_resize, cp, TQ_NOSLEEP);

    //	if (cp->cache_defrag != NULL)
    //		(void) taskq_dispatch(kmem_taskq,
    //		    (task_func_t *)kmem_cache_scan, cp, TQ_NOSLEEP);
}

static void
kmem_update_timeout(void *dummy)
{
    bsd_timeout(kmem_update, dummy, &kmem_update_interval);
}

static void
kmem_update(void *dummy)
{
    kmem_cache_applyall(kmem_cache_update, NULL, TQ_NOSLEEP);

    /*
     * We use taskq_dispatch() to reschedule the timeout so that
     * kmem_update() becomes self-throttling: it won't schedule
     * new tasks until all previous tasks have completed.
     */
    if (!taskq_dispatch(kmem_taskq, kmem_update_timeout, dummy, TQ_NOSLEEP))
        kmem_update_timeout(NULL);
}

static void kmem_reap_all_task()
{
	kmem_cache_applyall(kmem_cache_reap, 0, TQ_NOSLEEP);
    bsd_timeout(kmem_reap_all_task_proc, 0, &kmem_reap_all_task_timeout);
}

static void kmem_reap_all_task_proc()
{
    taskq_dispatch(kmem_taskq, kmem_reap_all_task, 0, TQ_NOSLEEP);
}

//===============================================================
// Initialisation/Finalisation
//===============================================================

static int
bmalloc_kstat_update(kstat_t *ksp, int rw)
{
	bmalloc_stats_t *bs = ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		return (SET_ERROR(EACCES));
	} else {
		bs->bmalloc_app_allocated.value.ui64 = bmalloc_app_allocated_total;
		bs->bmalloc_system_allocated.value.ui64 = bmalloc_allocated_total;
		bs->bmalloc_space_efficiency_percent.value.ui64 = (bmalloc_app_allocated_total * 100)/bmalloc_allocated_total;
		bs->bmalloc_active_threads.value.ui64 = zfs_threads;
	}

	return (0);
}

void
spl_kmem_init(uint64_t total_memory)
{
    printf("SPL: Total memory %llu\n", total_memory);

	// Kstats
	bmalloc_ksp = kstat_create("spl", 0, "bmalloc", "misc", KSTAT_TYPE_NAMED,
						   sizeof (bmalloc_stats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);

	if (bmalloc_ksp != NULL) {
		bmalloc_ksp->ks_data = &bmalloc_stats;
		bmalloc_ksp->ks_update = bmalloc_kstat_update;
		kstat_install(bmalloc_ksp);
	}

    // Initialise spinlocks
    kmem_lock_attr = lck_attr_alloc_init();
    kmem_group_attr = lck_grp_attr_alloc_init();
    kmem_lock_group  = lck_grp_alloc_init("kmem-spinlocks", kmem_group_attr);

    // Initialise the cache list
    mutex_init(&kmem_cache_lock, "kmem", MUTEX_DEFAULT, NULL);
    list_create(&kmem_caches, sizeof(kmem_cache_t), offsetof(kmem_cache_t, cache_link));

    // Initialise the magazines
    kmem_magtype_t *mtp;

    for (int i = 0; i < sizeof (kmem_magtype) / sizeof (*mtp); i++) {
        mtp = &kmem_magtype[i];
        mtp->mt_lock = lck_spin_alloc_init(kmem_lock_group, kmem_lock_attr);
        list_create(&mtp->mt_list, sizeof(kmem_magazine_t), offsetof(kmem_magazine_t, mag_node));
    }

    // Initialise the backing store for kmem_alloc et al
    // We dont read no config files, just pretend....
    kmem_cache_init(2, FALSE);
}

void spl_kmem_tasks_init()
{
    kmem_taskq = taskq_create("kmem-taskq",
                              1,
                              minclsyspri,
                              300, INT_MAX, TASKQ_PREPOPULATE);

    bsd_timeout(bmalloc_maintenance_task_proc, 0, &bmalloc_task_timeout);
    bsd_timeout(kmem_reap_all_task_proc, 0, &kmem_reap_all_task_timeout);
	start_memory_monitor();
    kmem_update_timeout(NULL);

#ifdef PRINT_CACHE_STATS
	bsd_timeout(print_all_cache_stats_task_proc, 0, &print_all_cache_stats_task_timeout);
#endif
}

void spl_kmem_tasks_fini()
{
    shutting_down = 1;

    // FIXME - might have to put a flush-through task into the task q
    // in here somewhere to ensure that all tasks are dead during
    // shutdown.

    bsd_untimeout(kmem_update, 0);
    bsd_untimeout(bmalloc_maintenance_task_proc, 0);
    bsd_untimeout(kmem_reap_all_task_proc, 0);
    bsd_untimeout(reap_finish_task_proc, 0);

	stop_memory_monitor();

#ifdef PRINT_CACHE_STATS
	bsd_untimeout(print_all_cache_stats_task_proc, 0);
#endif

    taskq_destroy(kmem_taskq);
}

void
spl_kmem_fini(void)
{
	kstat_delete(bmalloc_ksp);
}

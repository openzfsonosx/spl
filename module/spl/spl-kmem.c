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
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kstat.h>
#include <sys/seg_kmem.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <kern/sched_prim.h>
//===============================================================
// Options
//===============================================================
//#define PRINT_CACHE_STATS 1

// Uncomment to turn on kmems' debug features.
//#define DEBUG 1

//===============================================================
// OS Interface
//===============================================================

// This variable is a count of the number of threads
// blocked waiting for memory pages to become free.
// We are using wake indications on this event as a
// indication of paging activity, and therefore as a
// proxy to the machine experiencing memory pressure.
extern unsigned int vm_page_free_wanted;
extern unsigned int vm_page_free_min;
extern unsigned int vm_page_free_count;
extern unsigned int vm_page_speculative_count;

// Start and end address of kernel memory
//http://fxr.watson.org/fxr/source/osfmk/vm/vm_resident.c?v=xnu-2050.18.24;im=excerpts#L135
extern vm_offset_t virtual_space_start;
extern vm_offset_t virtual_space_end;

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

// Invoke the kernel debugger
extern void Debugger(const char *message);

// Read from /dev/random
void read_random(void* buffer, u_int numbytes);

//===============================================================
// Non Illumos Variables
//===============================================================

// Flag to cause tasks and threads to terminate as
// the kmem module is preparing to unload.
static int			shutting_down = 0;

// Amount of RAM in machine
uint64_t			physmem = 0;

// Size in bytes of the memory allocated in seg_kmem
extern uint64_t		segkmem_total_mem_allocated;

// Number of active threads
extern uint64_t		zfs_threads;
extern uint64_t		zfs_active_mutex;
extern uint64_t		zfs_active_rwlock;

// Set the memory target wanted when we detect pressure, this
// will get cleared once we are under it.
uint64_t            pressure_bytes_target = 0;

#define MULT 1

static char kext_version[64] = SPL_META_VERSION "-" SPL_META_RELEASE SPL_DEBUG_STR;

struct sysctl_oid_list sysctl__spl_children;
SYSCTL_DECL(_spl);
SYSCTL_NODE( , OID_AUTO, spl, CTLFLAG_RD, 0, "");
SYSCTL_STRING(_spl, OID_AUTO, kext_version,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    kext_version, 0, "SPL KEXT Version");


//===============================================================
// Illumos Variables
//===============================================================

struct kmem_cache_kstat {
    kstat_named_t	kmc_buf_size;
    kstat_named_t	kmc_align;
    kstat_named_t	kmc_chunk_size;
    kstat_named_t	kmc_slab_size;
    kstat_named_t	kmc_alloc;
    kstat_named_t	kmc_alloc_fail;
    kstat_named_t	kmc_free;
    kstat_named_t	kmc_depot_alloc;
    kstat_named_t	kmc_depot_free;
    kstat_named_t	kmc_depot_contention;
    kstat_named_t	kmc_slab_alloc;
    kstat_named_t	kmc_slab_free;
    kstat_named_t	kmc_buf_constructed;
    kstat_named_t	kmc_buf_avail;
    kstat_named_t	kmc_buf_inuse;
    kstat_named_t	kmc_buf_total;
    kstat_named_t	kmc_buf_max;
    kstat_named_t	kmc_slab_create;
    kstat_named_t	kmc_slab_destroy;
    kstat_named_t	kmc_vmem_source;
    kstat_named_t	kmc_hash_size;
    kstat_named_t	kmc_hash_lookup_depth;
    kstat_named_t	kmc_hash_rescale;
    kstat_named_t	kmc_full_magazines;
    kstat_named_t	kmc_empty_magazines;
    kstat_named_t	kmc_magazine_size;
    kstat_named_t	kmc_reap; /* number of kmem_cache_reap() calls */
    kstat_named_t	kmc_defrag; /* attempts to defrag all partial slabs */
    kstat_named_t	kmc_scan; /* attempts to defrag one partial slab */
    kstat_named_t	kmc_move_callbacks; /* sum of yes, no, later, dn, dk */
    kstat_named_t	kmc_move_yes;
    kstat_named_t	kmc_move_no;
    kstat_named_t	kmc_move_later;
    kstat_named_t	kmc_move_dont_need;
    kstat_named_t	kmc_move_dont_know; /* obj unrecognized by client ... */
    kstat_named_t	kmc_move_hunt_found; /* ... but found in mag layer */
    kstat_named_t	kmc_move_slabs_freed; /* slabs freed by consolidator */
    kstat_named_t	kmc_move_reclaimable; /* buffers, if consolidator ran */
} kmem_cache_kstat = {
    { "buf_size",		KSTAT_DATA_UINT64 },
    { "align",		KSTAT_DATA_UINT64 },
    { "chunk_size",		KSTAT_DATA_UINT64 },
    { "slab_size",		KSTAT_DATA_UINT64 },
    { "alloc",		KSTAT_DATA_UINT64 },
    { "alloc_fail",		KSTAT_DATA_UINT64 },
    { "free",		KSTAT_DATA_UINT64 },
    { "depot_alloc",	KSTAT_DATA_UINT64 },
    { "depot_free",		KSTAT_DATA_UINT64 },
    { "depot_contention",	KSTAT_DATA_UINT64 },
    { "slab_alloc",		KSTAT_DATA_UINT64 },
    { "slab_free",		KSTAT_DATA_UINT64 },
    { "buf_constructed",	KSTAT_DATA_UINT64 },
    { "buf_avail",		KSTAT_DATA_UINT64 },
    { "buf_inuse",		KSTAT_DATA_UINT64 },
    { "buf_total",		KSTAT_DATA_UINT64 },
    { "buf_max",		KSTAT_DATA_UINT64 },
    { "slab_create",	KSTAT_DATA_UINT64 },
    { "slab_destroy",	KSTAT_DATA_UINT64 },
    { "vmem_source",	KSTAT_DATA_UINT64 },
    { "hash_size",		KSTAT_DATA_UINT64 },
    { "hash_lookup_depth",	KSTAT_DATA_UINT64 },
    { "hash_rescale",	KSTAT_DATA_UINT64 },
    { "full_magazines",	KSTAT_DATA_UINT64 },
    { "empty_magazines",	KSTAT_DATA_UINT64 },
    { "magazine_size",	KSTAT_DATA_UINT64 },
    { "reap",		KSTAT_DATA_UINT64 },
    { "defrag",		KSTAT_DATA_UINT64 },
    { "scan",		KSTAT_DATA_UINT64 },
    { "move_callbacks",	KSTAT_DATA_UINT64 },
    { "move_yes",		KSTAT_DATA_UINT64 },
    { "move_no",		KSTAT_DATA_UINT64 },
    { "move_later",		KSTAT_DATA_UINT64 },
    { "move_dont_need",	KSTAT_DATA_UINT64 },
    { "move_dont_know",	KSTAT_DATA_UINT64 },
    { "move_hunt_found",	KSTAT_DATA_UINT64 },
    { "move_slabs_freed",	KSTAT_DATA_UINT64 },
    { "move_reclaimable",	KSTAT_DATA_UINT64 },
};

static kmutex_t kmem_cache_kstat_lock;

/*
 * The default set of caches to back kmem_alloc().
 * These sizes should be reevaluated periodically.
 *
 * We want allocations that are multiples of the coherency granularity
 * (64 bytes) to be satisfied from a cache which is a multiple of 64
 * bytes, so that it will be 64-byte aligned.  For all multiples of 64,
 * the next 1 greater than or equal to it must be a
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
    { 1,	8,	3200,	65536	},
    { 3,	16,	256,	32768	},
    { 7,	32,	64,	16384	},
    { 15,	64,	0,	8192	},
    { 31,	64,	0,	4096	},
    { 47,	64,	0,	2048	},
    { 63,	64,	0,	1024	},
    { 95,	64,	0,	512	},
    { 143,	64,	0,	0	},
};

static uint32_t kmem_reaping;
static uint32_t kmem_reaping_idspace;

/*
 * kmem tunables
 */
//clock_t kmem_reap_interval;	/* cache reaping rate [15 * HZ ticks] */
static struct timespec	kmem_reap_interval	= {15, 0};
int kmem_depot_contention = 3;	/* max failed tryenters per real interval */
pgcnt_t kmem_reapahead = 0;	/* start reaping N pages before pageout */
int kmem_panic = 1;		/* whether to panic on error */
//int kmem_panic = 0;		/* whether to panic on error */
int kmem_logging = 0;		/* kmem_log_enter() override */
uint32_t kmem_mtbf = 0;		/* mean time between failures [default: off] */
size_t kmem_transaction_log_size; /* transaction log size [2% of memory] */
size_t kmem_content_log_size;	/* content log size [2% of memory] */
size_t kmem_failure_log_size;	/* failure log [4 pages per CPU] */
size_t kmem_slab_log_size;	/* slab create log [4 pages per CPU] */
size_t kmem_content_maxsave = 256; /* KMF_CONTENTS max bytes to log */
size_t kmem_lite_minsize = 0;	/* minimum buffer size for KMF_LITE */
size_t kmem_lite_maxalign = 1024; /* maximum buffer alignment for KMF_LITE */
int kmem_lite_pcs = 4;		/* number of PCs to store in KMF_LITE mode */
size_t kmem_maxverify;		/* maximum bytes to inspect in debug routines */
size_t kmem_minfirewall;	/* hardware-enforced redzone threshold */

//#ifdef _LP64
size_t	kmem_max_cached = KMEM_BIG_MAXBUF;	/* maximum kmem_alloc cache */
//#else
//size_t	kmem_max_cached = KMEM_BIG_MAXBUF_32BIT; /* maximum kmem_alloc cache */
//#endif

#ifdef DEBUG
int kmem_flags = KMF_AUDIT | KMF_DEADBEEF | KMF_REDZONE | KMF_CONTENTS;
#else
int kmem_flags = 0;
#endif
int kmem_ready;

static kmem_cache_t	*kmem_slab_cache;
static kmem_cache_t	*kmem_bufctl_cache;
static kmem_cache_t	*kmem_bufctl_audit_cache;

static kmutex_t		kmem_cache_lock;	/* inter-cache linkage only */
static list_t		kmem_caches;
extern vmem_t		*heap_arena;
static taskq_t		*kmem_taskq;
static kmutex_t		kmem_flags_lock;
static vmem_t		*kmem_metadata_arena;
static vmem_t		*kmem_msb_arena;	/* arena for metadata caches */
static vmem_t		*kmem_cache_arena;
static vmem_t		*kmem_hash_arena;
static vmem_t		*kmem_log_arena;
static vmem_t		*kmem_oversize_arena;
static vmem_t		*kmem_va_arena;
static vmem_t		*kmem_default_arena;
//static vmem_t		*kmem_firewall_va_arena;
static vmem_t		*kmem_firewall_arena;

/*
 * Define KMEM_STATS to turn on statistic gathering. By default, it is only
 * turned on when DEBUG is also defined.
 */
#ifdef	DEBUG
#define	KMEM_STATS
#endif	/* DEBUG */

#ifdef	KMEM_STATS
#define	KMEM_STAT_ADD(stat)			((stat)++)
#define	KMEM_STAT_COND_ADD(cond, stat)		((void) (!(cond) || (stat)++))
#else
#define	KMEM_STAT_ADD(stat)			/* nothing */
#define	KMEM_STAT_COND_ADD(cond, stat)		/* nothing */
#endif	/* KMEM_STATS */

/*
 * kmem slab consolidator thresholds (tunables)
 */
size_t kmem_frag_minslabs = 101;	/* minimum total slabs */
size_t kmem_frag_numer = 1;		/* free buffers (numerator) */
size_t kmem_frag_denom = KMEM_VOID_FRACTION; /* buffers (denominator) */
/*
 * Maximum number of slabs from which to move buffers during a single
 * maintenance interval while the system is not low on memory.
 */
size_t kmem_reclaim_max_slabs = 1;
/*
 * Number of slabs to scan backwards from the end of the partial slab list
 * when searching for buffers to relocate.
 */
size_t kmem_reclaim_scan_range = 12;

#ifdef	KMEM_STATS
static struct {
    uint64_t kms_callbacks;
    uint64_t kms_yes;
    uint64_t kms_no;
    uint64_t kms_later;
    uint64_t kms_dont_need;
    uint64_t kms_dont_know;
    uint64_t kms_hunt_found_mag;
    uint64_t kms_hunt_found_slab;
    uint64_t kms_hunt_alloc_fail;
    uint64_t kms_hunt_lucky;
    uint64_t kms_notify;
    uint64_t kms_notify_callbacks;
    uint64_t kms_disbelief;
    uint64_t kms_already_pending;
    uint64_t kms_callback_alloc_fail;
    uint64_t kms_callback_taskq_fail;
    uint64_t kms_endscan_slab_dead;
    uint64_t kms_endscan_slab_destroyed;
    uint64_t kms_endscan_nomem;
    uint64_t kms_endscan_refcnt_changed;
    uint64_t kms_endscan_nomove_changed;
    uint64_t kms_endscan_freelist;
    uint64_t kms_avl_update;
    uint64_t kms_avl_noupdate;
    uint64_t kms_no_longer_reclaimable;
    uint64_t kms_notify_no_longer_reclaimable;
    uint64_t kms_notify_slab_dead;
    uint64_t kms_notify_slab_destroyed;
    uint64_t kms_alloc_fail;
    uint64_t kms_constructor_fail;
    uint64_t kms_dead_slabs_freed;
    uint64_t kms_defrags;
    uint64_t kms_scans;
    uint64_t kms_scan_depot_ws_reaps;
    uint64_t kms_debug_reaps;
    uint64_t kms_debug_scans;
} kmem_move_stats;
#endif	/* KMEM_STATS */

/* consolidator knobs */
static boolean_t kmem_move_noreap;
static boolean_t kmem_move_blocked;
static boolean_t kmem_move_fulltilt;
static boolean_t kmem_move_any_partial;

#ifdef	DEBUG
/*
 * kmem consolidator debug tunables:
 * Ensure code coverage by occasionally running the consolidator even when the
 * caches are not fragmented (they may never be). These intervals are mean time
 * in cache maintenance intervals (kmem_cache_update).
 */
uint32_t kmem_mtb_move = 60;	/* defrag 1 slab (~15min) */
uint32_t kmem_mtb_reap = 1800;	/* defrag all slabs (~7.5hrs) */
#endif	/* DEBUG */

static kmem_cache_t	*kmem_defrag_cache;
static kmem_cache_t	*kmem_move_cache;
static taskq_t		*kmem_move_taskq;

static void kmem_cache_scan(kmem_cache_t *);
static void kmem_cache_defrag(kmem_cache_t *);
static void kmem_slab_prefill(kmem_cache_t *, kmem_slab_t *);


kmem_log_header_t	*kmem_transaction_log;
kmem_log_header_t	*kmem_content_log;
kmem_log_header_t	*kmem_failure_log;
kmem_log_header_t	*kmem_slab_log;

static int		kmem_lite_count; /* # of PCs in kmem_buftag_lite_t */

#define	KMEM_BUFTAG_LITE_ENTER(bt, count, caller)			\
if ((count) > 0) {						\
pc_t *_s = ((kmem_buftag_lite_t *)(bt))->bt_history;	\
pc_t *_e;						\
/* memmove() the old entries down one notch */		\
for (_e = &_s[(count) - 1]; _e > _s; _e--)		\
*_e = *(_e - 1);				\
*_s = (uintptr_t)(caller);				\
}

#define	KMERR_MODIFIED	0	/* buffer modified while on freelist */
#define	KMERR_REDZONE	1	/* redzone violation (write past end of buf) */
#define	KMERR_DUPFREE	2	/* freed a buffer twice */
#define	KMERR_BADADDR	3	/* freed a bad (unallocated) address */
#define	KMERR_BADBUFTAG	4	/* buftag corrupted */
#define	KMERR_BADBUFCTL	5	/* bufctl corrupted */
#define	KMERR_BADCACHE	6	/* freed a buffer to the wrong cache */
#define	KMERR_BADSIZE	7	/* alloc size != free size */
#define	KMERR_BADBASE	8	/* buffer base address wrong */

struct {
    hrtime_t	kmp_timestamp;	/* timestamp of panic */
    int		kmp_error;	/* type of kmem error */
    void		*kmp_buffer;	/* buffer that induced panic */
    void		*kmp_realbuf;	/* real start address for buffer */
    kmem_cache_t	*kmp_cache;	/* buffer's cache according to client */
    kmem_cache_t	*kmp_realcache;	/* actual cache containing buffer */
    kmem_slab_t	*kmp_slab;	/* slab accoring to kmem_findslab() */
    kmem_bufctl_t	*kmp_bufctl;	/* bufctl */
} kmem_panic_info;

typedef struct spl_stats {
    kstat_named_t spl_os_alloc;
    kstat_named_t spl_active_threads;
    kstat_named_t spl_active_mutex;
    kstat_named_t spl_active_rwlock;
    kstat_named_t spl_monitor_thread_wake_count;
    kstat_named_t spl_simulate_pressure;
} spl_stats_t;

static spl_stats_t spl_stats = {
    {"os_mem_alloc", KSTAT_DATA_UINT64},
    {"active_threads", KSTAT_DATA_UINT64},
    {"active_mutex", KSTAT_DATA_UINT64},
    {"active_rwlock", KSTAT_DATA_UINT64},
    {"monitor_thread_wake_count", KSTAT_DATA_UINT64},
    {"simulate_pressure", KSTAT_DATA_UINT64},
};

static kstat_t *spl_ksp = 0;

// Stub out caller()
caddr_t caller()
{
    return (caddr_t)(0);
}

void *
calloc(size_t n, size_t s)
{
    return (zfs_kmem_zalloc(n * s, KM_NOSLEEP));
}

#define	IS_DIGIT(c)	((c) >= '0' && (c) <= '9')

#define	IS_ALPHA(c)	\
(((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))

/*
 * Get bytes from the /dev/random generator. Returns 0
 * on success. Returns EAGAIN if there is insufficient entropy.
 */
int
random_get_bytes(uint8_t *ptr, size_t len)
{
	read_random(ptr, len);
	return 0;
}

/*
 * BGH - Missing from OSX?
 *
 * Convert a string into a valid C identifier by replacing invalid
 * characters with '_'.  Also makes sure the string is nul-terminated
 * and takes up at most n bytes.
 */
void
strident_canon(char *s, size_t n)
{
    char c;
    char *end = s + n - 1;

    if ((c = *s) == 0)
        return;

    if (!IS_ALPHA(c) && c != '_')
        *s = '_';

    while (s < end && ((c = *(++s)) != 0)) {
        if (!IS_ALPHA(c) && !IS_DIGIT(c) && c != '_')
            *s = '_';
    }
    *s = 0;
}

int
strident_valid(const char *id)
{
	int c = *id++;

	if (!IS_ALPHA(c) && c != '_')
		return (0);
	while ((c = *id++) != 0) {
		if (!IS_ALPHA(c) && !IS_DIGIT(c) && c != '_')
			return (0);
	}
	return (1);
}

static void
copy_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
    uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
    uint64_t *buf = buf_arg;

    while (buf < bufend)
        *buf++ = pattern;
}

static void *
verify_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
    uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
    uint64_t *buf;

    for (buf = buf_arg; buf < bufend; buf++)
        if (*buf != pattern)
            return (buf);
    return (NULL);
}

static void *
verify_and_copy_pattern(uint64_t old, uint64_t new, void *buf_arg, size_t size)
{
    uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
    uint64_t *buf;

    for (buf = buf_arg; buf < bufend; buf++) {
        if (*buf != old) {
            copy_pattern(old, buf_arg,
                         (char *)buf - (char *)buf_arg);
            return (buf);
        }
        *buf = new;
    }

    return (NULL);
}

static void
kmem_cache_applyall(void (*func)(kmem_cache_t *), taskq_t *tq, int tqflag)
{
    kmem_cache_t *cp;

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

static void
kmem_cache_applyall_id(void (*func)(kmem_cache_t *), taskq_t *tq, int tqflag)
{
    kmem_cache_t *cp;

    mutex_enter(&kmem_cache_lock);
    for (cp = list_head(&kmem_caches); cp != NULL;
         cp = list_next(&kmem_caches, cp)) {
        if (!(cp->cache_cflags & KMC_IDENTIFIER))
            continue;
        if (tq != NULL)
            (void) taskq_dispatch(tq, (task_func_t *)func, cp,
                                  tqflag);
        else
            func(cp);
    }
    mutex_exit(&kmem_cache_lock);
}

/*
 * Debugging support.  Given a buffer address, find its slab.
 */
static kmem_slab_t *
kmem_findslab(kmem_cache_t *cp, void *buf)
{
    kmem_slab_t *sp;

    mutex_enter(&cp->cache_lock);
    for (sp = list_head(&cp->cache_complete_slabs); sp != NULL;
         sp = list_next(&cp->cache_complete_slabs, sp)) {
        if (KMEM_SLAB_MEMBER(sp, buf)) {
            mutex_exit(&cp->cache_lock);
            return (sp);
        }
    }
    for (sp = avl_first(&cp->cache_partial_slabs); sp != NULL;
         sp = AVL_NEXT(&cp->cache_partial_slabs, sp)) {
        if (KMEM_SLAB_MEMBER(sp, buf)) {
            mutex_exit(&cp->cache_lock);
            return (sp);
        }
    }
    mutex_exit(&cp->cache_lock);

    return (NULL);
}

static void
kmem_error(int error, kmem_cache_t *cparg, void *bufarg)
{
    kmem_buftag_t *btp = NULL;
    kmem_bufctl_t *bcp = NULL;
    kmem_cache_t *cp = cparg;
    kmem_slab_t *sp;
    uint64_t *off;
    void *buf = bufarg;

    kmem_logging = 0;	/* stop logging when a bad thing happens */

    kmem_panic_info.kmp_timestamp = gethrtime();

    sp = kmem_findslab(cp, buf);
    if (sp == NULL) {
        for (cp = list_tail(&kmem_caches); cp != NULL;
             cp = list_prev(&kmem_caches, cp)) {
            if ((sp = kmem_findslab(cp, buf)) != NULL)
                break;
        }
    }

    if (sp == NULL) {
        cp = NULL;
        error = KMERR_BADADDR;
    } else {
        if (cp != cparg)
            error = KMERR_BADCACHE;
        else
            buf = (char *)bufarg - ((uintptr_t)bufarg -
                                    (uintptr_t)sp->slab_base) % cp->cache_chunksize;
        if (buf != bufarg)
            error = KMERR_BADBASE;
        if (cp->cache_flags & KMF_BUFTAG)
            btp = KMEM_BUFTAG(cp, buf);
        if (cp->cache_flags & KMF_HASH) {
            mutex_enter(&cp->cache_lock);
            for (bcp = *KMEM_HASH(cp, buf); bcp; bcp = bcp->bc_next)
                if (bcp->bc_addr == buf)
                    break;
            mutex_exit(&cp->cache_lock);
            if (bcp == NULL && btp != NULL)
                bcp = btp->bt_bufctl;
            if (kmem_findslab(cp->cache_bufctl_cache, bcp) ==
                NULL || P2PHASE((uintptr_t)bcp, KMEM_ALIGN) ||
                bcp->bc_addr != buf) {
                error = KMERR_BADBUFCTL;
                bcp = NULL;
            }
        }
    }

    kmem_panic_info.kmp_error = error;
    kmem_panic_info.kmp_buffer = bufarg;
    kmem_panic_info.kmp_realbuf = buf;
    kmem_panic_info.kmp_cache = cparg;
    kmem_panic_info.kmp_realcache = cp;
    kmem_panic_info.kmp_slab = sp;
    kmem_panic_info.kmp_bufctl = bcp;

    printf("kernel memory allocator: ");

    switch (error) {

        case KMERR_MODIFIED:
            printf("buffer modified after being freed\n");
            off = verify_pattern(KMEM_FREE_PATTERN, buf, cp->cache_verify);
            if (off == NULL)	/* shouldn't happen */
                off = buf;
            printf("modification occurred at offset 0x%lx "
                   "(0x%llx replaced by 0x%llx)\n",
                   (uintptr_t)off - (uintptr_t)buf,
                   (longlong_t)KMEM_FREE_PATTERN, (longlong_t)*off);
            break;

        case KMERR_REDZONE:
            printf("redzone violation: write past end of buffer\n");
            break;

        case KMERR_BADADDR:
            printf("invalid free: buffer not in cache\n");
            break;

        case KMERR_DUPFREE:
            printf("duplicate free: buffer freed twice\n");
            break;

        case KMERR_BADBUFTAG:
            printf("boundary tag corrupted\n");
            printf("bcp ^ bxstat = %lx, should be %lx\n",
                   (intptr_t)btp->bt_bufctl ^ btp->bt_bxstat,
                   KMEM_BUFTAG_FREE);
            break;

        case KMERR_BADBUFCTL:
            printf("bufctl corrupted\n");
            break;

        case KMERR_BADCACHE:
            printf("buffer freed to wrong cache\n");
            printf("buffer was allocated from %s,\n", cp->cache_name);
            printf("caller attempting free to %s.\n", cparg->cache_name);
            break;

        case KMERR_BADSIZE:
            printf("bad free: free size (%u) != alloc size (%u)\n",
                   KMEM_SIZE_DECODE(((uint32_t *)btp)[0]),
                   KMEM_SIZE_DECODE(((uint32_t *)btp)[1]));
            break;

        case KMERR_BADBASE:
            printf("bad free: free address (%p) != alloc address (%p)\n",
                   bufarg, buf);
            break;
    }

    printf("buffer=%p  bufctl=%p  cache: %s\n",
           bufarg, (void *)bcp, cparg->cache_name);

#ifndef APPLE
//   if (bcp != NULL && (cp->cache_flags & KMF_AUDIT) &&
//       error != KMERR_BADBUFCTL) {
//       int d;
//       timestruc_t ts;
//       kmem_bufctl_audit_t *bcap = (kmem_bufctl_audit_t *)bcp;
//
//     hrt2ts(kmem_panic_info.kmp_timestamp - bcap->bc_timestamp, &ts);
//        printf("previous transaction on buffer %p:\n", buf);
//        printf("thread=%p  time=T-%ld.%09ld  slab=%p  cache: %s\n",
//               (void *)bcap->bc_thread, ts.tv_sec, ts.tv_nsec,
//               (void *)sp, cp->cache_name);
//        for (d = 0; d < MIN(bcap->bc_depth, KMEM_STACK_DEPTH); d++) {
//            ulong_t off;
//            char *sym = kobj_getsymname(bcap->bc_stack[d], &off);
//            printf("%s+%lx\n", sym ? sym : "?", off);
//        }
//    }
#endif

    if (kmem_panic > 0) {
        delay(hz);
        panic("kernel heap corruption detected");
    }

//	if (kmem_panic == 0) {
//        debug_enter(NULL);
//		Debugger("Kernel heap corruption detected");
//	}


    kmem_logging = 1;	/* resume logging */
}

static kmem_log_header_t *
kmem_log_init(size_t logsize)
{
    kmem_log_header_t *lhp;
    int nchunks = 4 * max_ncpus;
    size_t lhsize = (size_t)&((kmem_log_header_t *)0)->lh_cpu[max_ncpus];
    int i;

    /*
     * Make sure that lhp->lh_cpu[] is nicely aligned
     * to prevent false sharing of cache lines.
     */
    lhsize = P2ROUNDUP(lhsize, KMEM_ALIGN);
    lhp = vmem_xalloc(kmem_log_arena, lhsize, 64, P2NPHASE(lhsize, 64), 0,
                      NULL, NULL, VM_SLEEP);
    bzero(lhp, lhsize);

    mutex_init(&lhp->lh_lock, NULL, MUTEX_DEFAULT, NULL);
    lhp->lh_nchunks = nchunks;
    lhp->lh_chunksize = P2ROUNDUP(logsize / nchunks + 1, KMEM_QUANTUM);
    lhp->lh_base = vmem_alloc(kmem_log_arena,
                              lhp->lh_chunksize * nchunks, VM_SLEEP);
    lhp->lh_free = vmem_alloc(kmem_log_arena,
                              nchunks * sizeof (int), VM_SLEEP);
    bzero(lhp->lh_base, lhp->lh_chunksize * nchunks);

    for (i = 0; i < max_ncpus; i++) {
        kmem_cpu_log_header_t *clhp = &lhp->lh_cpu[i];
        mutex_init(&clhp->clh_lock, NULL, MUTEX_DEFAULT, NULL);
        clhp->clh_chunk = i;
    }

    for (i = max_ncpus; i < nchunks; i++)
        lhp->lh_free[i] = i;

    lhp->lh_head = max_ncpus;
    lhp->lh_tail = 0;

    return (lhp);
}


static void
kmem_log_fini(kmem_log_header_t *lhp)
{
    int nchunks = 4 * max_ncpus;
    size_t lhsize = (size_t)&((kmem_log_header_t *)0)->lh_cpu[max_ncpus];
    int i;



    for (i = 0; i < max_ncpus; i++) {
        kmem_cpu_log_header_t *clhp = &lhp->lh_cpu[i];
        mutex_destroy(&clhp->clh_lock);
    }

    vmem_free(kmem_log_arena,
			  lhp->lh_free,
			  nchunks * sizeof (int));

	vmem_free(kmem_log_arena,
			  lhp->lh_base,
			  lhp->lh_chunksize * nchunks);

    mutex_destroy(&lhp->lh_lock);

    lhsize = P2ROUNDUP(lhsize, KMEM_ALIGN);
    vmem_xfree(kmem_log_arena,
			   lhp,
			   lhsize);
}


static void *
kmem_log_enter(kmem_log_header_t *lhp, void *data, size_t size)
{
    void *logspace;

    kmem_cpu_log_header_t *clhp = &lhp->lh_cpu[cpu_number()];

//    if (lhp == NULL || kmem_logging == 0 || panicstr)
	if (lhp == NULL || kmem_logging == 0)
        return (NULL);

    mutex_enter(&clhp->clh_lock);
    clhp->clh_hits++;
    if (size > clhp->clh_avail) {
        mutex_enter(&lhp->lh_lock);
        lhp->lh_hits++;
        lhp->lh_free[lhp->lh_tail] = clhp->clh_chunk;
        lhp->lh_tail = (lhp->lh_tail + 1) % lhp->lh_nchunks;
        clhp->clh_chunk = lhp->lh_free[lhp->lh_head];
        lhp->lh_head = (lhp->lh_head + 1) % lhp->lh_nchunks;
        clhp->clh_current = lhp->lh_base +
        clhp->clh_chunk * lhp->lh_chunksize;
        clhp->clh_avail = lhp->lh_chunksize;
        if (size > lhp->lh_chunksize)
            size = lhp->lh_chunksize;
        mutex_exit(&lhp->lh_lock);
    }
    logspace = clhp->clh_current;
    clhp->clh_current += size;
    clhp->clh_avail -= size;
    bcopy(data, logspace, size);
    mutex_exit(&clhp->clh_lock);
    return (logspace);
}

// _bcp->bc_depth = getpcstack(_bcp->bc_stack, KMEM_STACK_DEPTH);
// checked
//_bcp->bc_thread = cpu_number();
#define	KMEM_AUDIT(lp, cp, bcp)										\
{																	\
    kmem_bufctl_audit_t *_bcp = (kmem_bufctl_audit_t *)(bcp);		\
    _bcp->bc_timestamp = gethrtime();								\
    _bcp->bc_thread = 0;                                            \
    _bcp->bc_depth = 0;												\
    _bcp->bc_lastlog = kmem_log_enter((lp), _bcp, sizeof (*_bcp));	\
}

static void
kmem_log_event(kmem_log_header_t *lp, kmem_cache_t *cp,
               kmem_slab_t *sp, void *addr)
{
    kmem_bufctl_audit_t bca;

    bzero(&bca, sizeof (kmem_bufctl_audit_t));
    bca.bc_addr = addr;
    bca.bc_slab = sp;
    KMEM_AUDIT(lp, cp, &bca);
}

/*
 * Create a new slab for cache cp.
 */
static kmem_slab_t *
kmem_slab_create(kmem_cache_t *cp, int kmflag)
{
    size_t slabsize = cp->cache_slabsize;
    size_t chunksize = cp->cache_chunksize;
    int cache_flags = cp->cache_flags;
    size_t color, chunks;
    char *buf, *slab;
    kmem_slab_t *sp;
    kmem_bufctl_t *bcp;
    vmem_t *vmp = cp->cache_arena;

    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));

    color = cp->cache_color + cp->cache_align;
    if (color > cp->cache_maxcolor)
        color = cp->cache_mincolor;
    cp->cache_color = color;

    slab = vmem_alloc(vmp, slabsize, kmflag & KM_VMFLAGS);

    if (slab == NULL)
        goto vmem_alloc_failure;

    ASSERT(P2PHASE((uintptr_t)slab, vmp->vm_quantum) == 0);

    /*
     * Reverify what was already checked in kmem_cache_set_move(), since the
     * consolidator depends (for correctness) on slabs being initialized
     * with the 0xbaddcafe memory pattern (setting a low order bit usable by
     * clients to distinguish uninitialized memory from known objects).
     */
    ASSERT((cp->cache_move == NULL) || !(cp->cache_cflags & KMC_NOTOUCH));
    if (!(cp->cache_cflags & KMC_NOTOUCH))
        copy_pattern(KMEM_UNINITIALIZED_PATTERN, slab, slabsize);

    if (cache_flags & KMF_HASH) {
        if ((sp = kmem_cache_alloc(kmem_slab_cache, kmflag)) == NULL)
            goto slab_alloc_failure;
        chunks = (slabsize - color) / chunksize;
    } else {
        sp = KMEM_SLAB(cp, slab);
        chunks = (slabsize - sizeof (kmem_slab_t) - color) / chunksize;
    }

    sp->slab_cache	= cp;
    sp->slab_head	= NULL;
    sp->slab_refcnt	= 0;
    sp->slab_base	= buf = slab + color;
    sp->slab_chunks	= chunks;
    sp->slab_stuck_offset = (uint32_t)-1;
    sp->slab_later_count = 0;
    sp->slab_flags = 0;

    ASSERT(chunks > 0);
    while (chunks-- != 0) {
        if (cache_flags & KMF_HASH) {
            bcp = kmem_cache_alloc(cp->cache_bufctl_cache, kmflag);
            if (bcp == NULL)
                goto bufctl_alloc_failure;
            if (cache_flags & KMF_AUDIT) {
                kmem_bufctl_audit_t *bcap =
                (kmem_bufctl_audit_t *)bcp;
                bzero(bcap, sizeof (kmem_bufctl_audit_t));
                bcap->bc_cache = cp;
            }
            bcp->bc_addr = buf;
            bcp->bc_slab = sp;
        } else {
            bcp = KMEM_BUFCTL(cp, buf);
        }
        if (cache_flags & KMF_BUFTAG) {
            kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
            btp->bt_redzone = KMEM_REDZONE_PATTERN;
            btp->bt_bufctl = bcp;
            btp->bt_bxstat = (intptr_t)bcp ^ KMEM_BUFTAG_FREE;
            if (cache_flags & KMF_DEADBEEF) {
                copy_pattern(KMEM_FREE_PATTERN, buf,
                             cp->cache_verify);
            }
        }
        bcp->bc_next = sp->slab_head;
        sp->slab_head = bcp;
        buf += chunksize;
    }

    kmem_log_event(kmem_slab_log, cp, sp, slab);

    return (sp);

bufctl_alloc_failure:

    while ((bcp = sp->slab_head) != NULL) {
        sp->slab_head = bcp->bc_next;
        kmem_cache_free(cp->cache_bufctl_cache, bcp);
    }
    kmem_cache_free(kmem_slab_cache, sp);

slab_alloc_failure:

    vmem_free(vmp, slab, slabsize);

vmem_alloc_failure:

    kmem_log_event(kmem_failure_log, cp, NULL, NULL);
    atomic_inc_64(&cp->cache_alloc_fail);

    return (NULL);
}

/*
 * Destroy a slab.
 */
static void
kmem_slab_destroy(kmem_cache_t *cp, kmem_slab_t *sp)
{
    vmem_t *vmp = cp->cache_arena;
    void *slab = (void *)P2ALIGN((uintptr_t)sp->slab_base, vmp->vm_quantum);

    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));
    ASSERT(sp->slab_refcnt == 0);

    if (cp->cache_flags & KMF_HASH) {
        kmem_bufctl_t *bcp;
        while ((bcp = sp->slab_head) != NULL) {
            sp->slab_head = bcp->bc_next;
            kmem_cache_free(cp->cache_bufctl_cache, bcp);
        }
        kmem_cache_free(kmem_slab_cache, sp);
    }
	kpreempt(KPREEMPT_SYNC);
    vmem_free(vmp, slab, cp->cache_slabsize);
}

static void *
kmem_slab_alloc_impl(kmem_cache_t *cp, kmem_slab_t *sp, boolean_t prefill)
{
    kmem_bufctl_t *bcp, **hash_bucket;
    void *buf;
    boolean_t new_slab = (sp->slab_refcnt == 0);

    ASSERT(MUTEX_HELD(&cp->cache_lock));
    /*
     * kmem_slab_alloc() drops cache_lock when it creates a new slab, so we
     * can't ASSERT(avl_is_empty(&cp->cache_partial_slabs)) here when the
     * slab is newly created.
     */
    ASSERT(new_slab || (KMEM_SLAB_IS_PARTIAL(sp) &&
                        (sp == avl_first(&cp->cache_partial_slabs))));
    ASSERT(sp->slab_cache == cp);

    cp->cache_slab_alloc++;
    cp->cache_bufslab--;
    sp->slab_refcnt++;

    bcp = sp->slab_head;
    sp->slab_head = bcp->bc_next;

    if (cp->cache_flags & KMF_HASH) {
        /*
         * Add buffer to allocated-address hash table.
         */
        buf = bcp->bc_addr;
        hash_bucket = KMEM_HASH(cp, buf);
        bcp->bc_next = *hash_bucket;
        *hash_bucket = bcp;
        if ((cp->cache_flags & (KMF_AUDIT | KMF_BUFTAG)) == KMF_AUDIT) {
            KMEM_AUDIT(kmem_transaction_log, cp, bcp);
        }
    } else {
        buf = KMEM_BUF(cp, bcp);
    }

    ASSERT(KMEM_SLAB_MEMBER(sp, buf));

    if (sp->slab_head == NULL) {
        ASSERT(KMEM_SLAB_IS_ALL_USED(sp));
        if (new_slab) {
            ASSERT(sp->slab_chunks == 1);
        } else {
            ASSERT(sp->slab_chunks > 1); /* the slab was partial */
            avl_remove(&cp->cache_partial_slabs, sp);
            sp->slab_later_count = 0; /* clear history */
            sp->slab_flags &= ~KMEM_SLAB_NOMOVE;
            sp->slab_stuck_offset = (uint32_t)-1;
        }
        list_insert_head(&cp->cache_complete_slabs, sp);
        cp->cache_complete_slab_count++;
        return (buf);
    }

    ASSERT(KMEM_SLAB_IS_PARTIAL(sp));
    /*
     * Peek to see if the magazine layer is enabled before
     * we prefill.  We're not holding the cpu cache lock,
     * so the peek could be wrong, but there's no harm in it.
     */
    if (new_slab && prefill && (cp->cache_flags & KMF_PREFILL) &&
        (KMEM_CPU_CACHE(cp)->cc_magsize != 0))  {
        kmem_slab_prefill(cp, sp);
        return (buf);
    }

    if (new_slab) {
        avl_add(&cp->cache_partial_slabs, sp);
        return (buf);
    }

    /*
     * The slab is now more allocated than it was, so the
     * order remains unchanged.
     */
    ASSERT(!avl_update(&cp->cache_partial_slabs, sp));
    return (buf);
}

/*
 * Allocate a raw (unconstructed) buffer from cp's slab layer.
 */
static void *
kmem_slab_alloc(kmem_cache_t *cp, int kmflag)
{
    kmem_slab_t *sp;
    void *buf;
    boolean_t test_destructor;

    mutex_enter(&cp->cache_lock);
    test_destructor = (cp->cache_slab_alloc == 0);
    sp = avl_first(&cp->cache_partial_slabs);
    if (sp == NULL) {
        ASSERT(cp->cache_bufslab == 0);

        /*
         * The freelist is empty.  Create a new slab.
         */
        mutex_exit(&cp->cache_lock);
        if ((sp = kmem_slab_create(cp, kmflag)) == NULL) {
            return (NULL);
        }
        mutex_enter(&cp->cache_lock);
        cp->cache_slab_create++;
        if ((cp->cache_buftotal += sp->slab_chunks) > cp->cache_bufmax)
            cp->cache_bufmax = cp->cache_buftotal;
        cp->cache_bufslab += sp->slab_chunks;
    }

    buf = kmem_slab_alloc_impl(cp, sp, B_TRUE);
    ASSERT((cp->cache_slab_create - cp->cache_slab_destroy) ==
           (cp->cache_complete_slab_count +
            avl_numnodes(&cp->cache_partial_slabs) +
            (cp->cache_defrag == NULL ? 0 : cp->cache_defrag->kmd_deadcount)));
    mutex_exit(&cp->cache_lock);

    if (test_destructor && cp->cache_destructor != NULL) {
        /*
         * On the first kmem_slab_alloc(), assert that it is valid to
         * call the destructor on a newly constructed object without any
         * client involvement.
         */
/*
        if ((cp->cache_constructor == NULL) ||
            cp->cache_constructor(buf, cp->cache_private,
                                  kmflag) == 0) {
			//cp->cache_destructor(buf, cp->cache_private);
            }
*/
        copy_pattern(KMEM_UNINITIALIZED_PATTERN, buf,
                     cp->cache_bufsize);
        if (cp->cache_flags & KMF_DEADBEEF) {
            copy_pattern(KMEM_FREE_PATTERN, buf, cp->cache_verify);
        }
    }

    return (buf);
}

static void kmem_slab_move_yes(kmem_cache_t *, kmem_slab_t *, void *);

/*
 * Free a raw (unconstructed) buffer to cp's slab layer.
 */
static void
kmem_slab_free(kmem_cache_t *cp, void *buf)
{
    kmem_slab_t *sp;
    kmem_bufctl_t *bcp, **prev_bcpp;

    ASSERT(buf != NULL);

    mutex_enter(&cp->cache_lock);
    cp->cache_slab_free++;

    if (cp->cache_flags & KMF_HASH) {
        /*
         * Look up buffer in allocated-address hash table.
         */
        prev_bcpp = KMEM_HASH(cp, buf);
        while ((bcp = *prev_bcpp) != NULL) {
            if (bcp->bc_addr == buf) {
                *prev_bcpp = bcp->bc_next;
                sp = bcp->bc_slab;
                break;
            }
            cp->cache_lookup_depth++;
            prev_bcpp = &bcp->bc_next;
        }
    } else {
        bcp = KMEM_BUFCTL(cp, buf);
        sp = KMEM_SLAB(cp, buf);
    }

    if (bcp == NULL || sp->slab_cache != cp || !KMEM_SLAB_MEMBER(sp, buf)) {
        mutex_exit(&cp->cache_lock);
        kmem_error(KMERR_BADADDR, cp, buf);
        return;
    }

    if (KMEM_SLAB_OFFSET(sp, buf) == sp->slab_stuck_offset) {
        /*
         * If this is the buffer that prevented the consolidator from
         * clearing the slab, we can reset the slab flags now that the
         * buffer is freed. (It makes sense to do this in
         * kmem_cache_free(), where the client gives up ownership of the
         * buffer, but on the hot path the test is too expensive.)
         */
        kmem_slab_move_yes(cp, sp, buf);
    }

    if ((cp->cache_flags & (KMF_AUDIT | KMF_BUFTAG)) == KMF_AUDIT) {
        if (cp->cache_flags & KMF_CONTENTS)
            ((kmem_bufctl_audit_t *)bcp)->bc_contents =
            kmem_log_enter(kmem_content_log, buf,
                           cp->cache_contents);
        KMEM_AUDIT(kmem_transaction_log, cp, bcp);
    }

    bcp->bc_next = sp->slab_head;
    sp->slab_head = bcp;

    cp->cache_bufslab++;
    ASSERT(sp->slab_refcnt >= 1);

    if (--sp->slab_refcnt == 0) {
        /*
         * There are no outstanding allocations from this slab,
         * so we can reclaim the memory.
         */
        if (sp->slab_chunks == 1) {
            list_remove(&cp->cache_complete_slabs, sp);
            cp->cache_complete_slab_count--;
        } else {
            avl_remove(&cp->cache_partial_slabs, sp);
        }

        cp->cache_buftotal -= sp->slab_chunks;
        cp->cache_bufslab -= sp->slab_chunks;
        /*
         * Defer releasing the slab to the virtual memory subsystem
         * while there is a pending move callback, since we guarantee
         * that buffers passed to the move callback have only been
         * touched by kmem or by the client itself. Since the memory
         * patterns baddcafe (uninitialized) and deadbeef (freed) both
         * set at least one of the two lowest order bits, the client can
         * test those bits in the move callback to determine whether or
         * not it knows about the buffer (assuming that the client also
         * sets one of those low order bits whenever it frees a buffer).
         */
        if (cp->cache_defrag == NULL ||
            (avl_is_empty(&cp->cache_defrag->kmd_moves_pending) &&
             !(sp->slab_flags & KMEM_SLAB_MOVE_PENDING))) {
                cp->cache_slab_destroy++;
                mutex_exit(&cp->cache_lock);
                kmem_slab_destroy(cp, sp);
            } else {
                list_t *deadlist = &cp->cache_defrag->kmd_deadlist;
                /*
                 * Slabs are inserted at both ends of the deadlist to
                 * distinguish between slabs freed while move callbacks
                 * are pending (list head) and a slab freed while the
                 * lock is dropped in kmem_move_buffers() (list tail) so
                 * that in both cases slab_destroy() is called from the
                 * right context.
                 */
                if (sp->slab_flags & KMEM_SLAB_MOVE_PENDING) {
                    list_insert_tail(deadlist, sp);
                } else {
                    list_insert_head(deadlist, sp);
                }
                cp->cache_defrag->kmd_deadcount++;
                mutex_exit(&cp->cache_lock);
            }
        return;
    }

    if (bcp->bc_next == NULL) {
        /* Transition the slab from completely allocated to partial. */
        ASSERT(sp->slab_refcnt == (sp->slab_chunks - 1));
        ASSERT(sp->slab_chunks > 1);
        list_remove(&cp->cache_complete_slabs, sp);
        cp->cache_complete_slab_count--;
        avl_add(&cp->cache_partial_slabs, sp);
    } else {
#ifdef	DEBUG
        if (avl_update_gt(&cp->cache_partial_slabs, sp)) {
            KMEM_STAT_ADD(kmem_move_stats.kms_avl_update);
        } else {
            KMEM_STAT_ADD(kmem_move_stats.kms_avl_noupdate);
        }
#else
        (void) avl_update_gt(&cp->cache_partial_slabs, sp);
#endif
    }

    ASSERT((cp->cache_slab_create - cp->cache_slab_destroy) ==
           (cp->cache_complete_slab_count +
            avl_numnodes(&cp->cache_partial_slabs) +
            (cp->cache_defrag == NULL ? 0 : cp->cache_defrag->kmd_deadcount)));
    mutex_exit(&cp->cache_lock);
}

/*
 * Return -1 if kmem_error, 1 if constructor fails, 0 if successful.
 */
static int
kmem_cache_alloc_debug(kmem_cache_t *cp, void *buf, int kmflag, int construct,
                       caddr_t caller)
{
    kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
    kmem_bufctl_audit_t *bcp = (kmem_bufctl_audit_t *)btp->bt_bufctl;
    uint32_t mtbf;

    if (btp->bt_bxstat != ((intptr_t)bcp ^ KMEM_BUFTAG_FREE)) {
        kmem_error(KMERR_BADBUFTAG, cp, buf);
        return (-1);
    }

    btp->bt_bxstat = (intptr_t)bcp ^ KMEM_BUFTAG_ALLOC;

    if ((cp->cache_flags & KMF_HASH) && bcp->bc_addr != buf) {
        kmem_error(KMERR_BADBUFCTL, cp, buf);
        return (-1);
    }

    if (cp->cache_flags & KMF_DEADBEEF) {
        if (!construct && (cp->cache_flags & KMF_LITE)) {
            if (*(uint64_t *)buf != KMEM_FREE_PATTERN) {
                kmem_error(KMERR_MODIFIED, cp, buf);
                return (-1);
            }
            if (cp->cache_constructor != NULL)
                *(uint64_t *)buf = btp->bt_redzone;
            else
                *(uint64_t *)buf = KMEM_UNINITIALIZED_PATTERN;
        } else {
            construct = 1;
            if (verify_and_copy_pattern(KMEM_FREE_PATTERN,
                                        KMEM_UNINITIALIZED_PATTERN, buf,
                                        cp->cache_verify)) {
                kmem_error(KMERR_MODIFIED, cp, buf);
                return (-1);
            }
        }
    }
    btp->bt_redzone = KMEM_REDZONE_PATTERN;

    if ((mtbf = kmem_mtbf | cp->cache_mtbf) != 0 &&
        gethrtime() % mtbf == 0 &&
        (kmflag & (KM_NOSLEEP | KM_PANIC)) == KM_NOSLEEP) {
        kmem_log_event(kmem_failure_log, cp, NULL, NULL);
        if (!construct && cp->cache_destructor != NULL)
            cp->cache_destructor(buf, cp->cache_private);
    } else {
        mtbf = 0;
    }

    if (mtbf || (construct && cp->cache_constructor != NULL &&
                 cp->cache_constructor(buf, cp->cache_private, kmflag) != 0)) {
        atomic_inc_64(&cp->cache_alloc_fail);
        btp->bt_bxstat = (intptr_t)bcp ^ KMEM_BUFTAG_FREE;
        if (cp->cache_flags & KMF_DEADBEEF)
            copy_pattern(KMEM_FREE_PATTERN, buf, cp->cache_verify);
        kmem_slab_free(cp, buf);
        return (1);
    }

    if (cp->cache_flags & KMF_AUDIT) {
        KMEM_AUDIT(kmem_transaction_log, cp, bcp);
    }

    if ((cp->cache_flags & KMF_LITE) &&
        !(cp->cache_cflags & KMC_KMEM_ALLOC)) {
        KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count, caller);
    }

    return (0);
}

static int
kmem_cache_free_debug(kmem_cache_t *cp, void *buf, caddr_t caller)
{
    kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
    kmem_bufctl_audit_t *bcp = (kmem_bufctl_audit_t *)btp->bt_bufctl;
    kmem_slab_t *sp;

    if (btp->bt_bxstat != ((intptr_t)bcp ^ KMEM_BUFTAG_ALLOC)) {
        if (btp->bt_bxstat == ((intptr_t)bcp ^ KMEM_BUFTAG_FREE)) {
            kmem_error(KMERR_DUPFREE, cp, buf);
            return (-1);
        }
        sp = kmem_findslab(cp, buf);
        if (sp == NULL || sp->slab_cache != cp)
            kmem_error(KMERR_BADADDR, cp, buf);
        else
            kmem_error(KMERR_REDZONE, cp, buf);
        return (-1);
    }

    btp->bt_bxstat = (intptr_t)bcp ^ KMEM_BUFTAG_FREE;

    if ((cp->cache_flags & KMF_HASH) && bcp->bc_addr != buf) {
        kmem_error(KMERR_BADBUFCTL, cp, buf);
        return (-1);
    }

    if (btp->bt_redzone != KMEM_REDZONE_PATTERN) {
        kmem_error(KMERR_REDZONE, cp, buf);
        return (-1);
    }

    if (cp->cache_flags & KMF_AUDIT) {
        if (cp->cache_flags & KMF_CONTENTS)
            bcp->bc_contents = kmem_log_enter(kmem_content_log,
                                              buf, cp->cache_contents);
        KMEM_AUDIT(kmem_transaction_log, cp, bcp);
    }

    if ((cp->cache_flags & KMF_LITE) &&
        !(cp->cache_cflags & KMC_KMEM_ALLOC)) {
        KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count, caller);
    }

    if (cp->cache_flags & KMF_DEADBEEF) {
        if (cp->cache_flags & KMF_LITE)
            btp->bt_redzone = *(uint64_t *)buf;
        else if (cp->cache_destructor != NULL)
            cp->cache_destructor(buf, cp->cache_private);

        copy_pattern(KMEM_FREE_PATTERN, buf, cp->cache_verify);
    }

    return (0);
}

/*
 * Free each object in magazine mp to cp's slab layer, and free mp itself.
 */
static void
kmem_magazine_destroy(kmem_cache_t *cp, kmem_magazine_t *mp, int nrounds)
{
    int round;

    ASSERT(!list_link_active(&cp->cache_link) ||
           taskq_member(kmem_taskq, curthread));

    for (round = 0; round < nrounds; round++) {
        void *buf = mp->mag_round[round];

        if (cp->cache_flags & KMF_DEADBEEF) {
            if (verify_pattern(KMEM_FREE_PATTERN, buf,
                               cp->cache_verify) != NULL) {
                kmem_error(KMERR_MODIFIED, cp, buf);
                continue;
            }
            if ((cp->cache_flags & KMF_LITE) &&
                cp->cache_destructor != NULL) {
                kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
                *(uint64_t *)buf = btp->bt_redzone;
                cp->cache_destructor(buf, cp->cache_private);
                *(uint64_t *)buf = KMEM_FREE_PATTERN;
            }
        } else if (cp->cache_destructor != NULL) {
            cp->cache_destructor(buf, cp->cache_private);
        }

        kmem_slab_free(cp, buf);

		kpreempt(KPREEMPT_SYNC);

    }
    ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
    kmem_cache_free(cp->cache_magtype->mt_cache, mp);

}

/*
 * Allocate a magazine from the depot.
 */
static kmem_magazine_t *
kmem_depot_alloc(kmem_cache_t *cp, kmem_maglist_t *mlp)
{
    kmem_magazine_t *mp;

    /*
     * If we can't get the depot lock without contention,
     * update our contention count.  We use the depot
     * contention rate to determine whether we need to
     * increase the magazine size for better scalability.
     */
    if (!mutex_tryenter(&cp->cache_depot_lock)) {
        mutex_enter(&cp->cache_depot_lock);
        cp->cache_depot_contention++;
    }

    if ((mp = mlp->ml_list) != NULL) {
        ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
        mlp->ml_list = mp->mag_next;
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
    ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
    mp->mag_next = mlp->ml_list;
    mlp->ml_list = mp;
    mlp->ml_total++;
    mutex_exit(&cp->cache_depot_lock);
}

/*
 * Update the working set statistics for cp's depot.
 */
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

/*
 * Reap all magazines that have fallen out of the depot's working set.
 */
static void
kmem_depot_ws_reap(kmem_cache_t *cp)
{
    long reap;
    kmem_magazine_t *mp;

    ASSERT(!list_link_active(&cp->cache_link) ||
           taskq_member(kmem_taskq, curthread));

    reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
    while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_full)) != NULL)
        kmem_magazine_destroy(cp, mp, cp->cache_magtype->mt_magsize);

    reap = MIN(cp->cache_empty.ml_reaplimit, cp->cache_empty.ml_min);
    while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_empty)) != NULL)
        kmem_magazine_destroy(cp, mp, 0);
}

static void
kmem_cpu_reload(kmem_cpu_cache_t *ccp, kmem_magazine_t *mp, int rounds)
{
    ASSERT((ccp->cc_loaded == NULL && ccp->cc_rounds == -1) ||
           (ccp->cc_loaded && ccp->cc_rounds + rounds == ccp->cc_magsize));
    ASSERT(ccp->cc_magsize > 0);

    ccp->cc_ploaded = ccp->cc_loaded;
    ccp->cc_prounds = ccp->cc_rounds;
    ccp->cc_loaded = mp;
    ccp->cc_rounds = rounds;
}

/*
 * Intercept kmem alloc/free calls during crash dump in order to avoid
 * changing kmem state while memory is being saved to the dump device.
 * Otherwise, ::kmem_verify will report "corrupt buffers".  Note that
 * there are no locks because only one CPU calls kmem during a crash
 * dump. To enable this feature, first create the associated vmem
 * arena with VMC_DUMPSAFE.
 */
static void *kmem_dump_start;	/* start of pre-reserved heap */
static void *kmem_dump_end;	/* end of heap area */
static void *kmem_dump_curr;	/* current free heap pointer */
static size_t kmem_dump_size;	/* size of heap area */

/* append to each buf created in the pre-reserved heap */
typedef struct kmem_dumpctl {
    void	*kdc_next;	/* cache dump free list linkage */
} kmem_dumpctl_t;

#define	KMEM_DUMPCTL(cp, buf)	\
((kmem_dumpctl_t *)P2ROUNDUP((uintptr_t)(buf) + (cp)->cache_bufsize, \
sizeof (void *)))

/* Keep some simple stats. */
#define	KMEM_DUMP_LOGS	(100)

typedef struct kmem_dump_log {
    kmem_cache_t	*kdl_cache;
    uint_t		kdl_allocs;		/* # of dump allocations */
    uint_t		kdl_frees;		/* # of dump frees */
    uint_t		kdl_alloc_fails;	/* # of allocation failures */
    uint_t		kdl_free_nondump;	/* # of non-dump frees */
    uint_t		kdl_unsafe;		/* cache was used, but unsafe */
} kmem_dump_log_t;

static kmem_dump_log_t *kmem_dump_log;
static int kmem_dump_log_idx;

#define	KDI_LOG(cp, stat) {						\
kmem_dump_log_t *kdl;						\
if ((kdl = (kmem_dump_log_t *)((cp)->cache_dumplog)) != NULL) {	\
kdl->stat++;						\
} else if (kmem_dump_log_idx < KMEM_DUMP_LOGS) {		\
kdl = &kmem_dump_log[kmem_dump_log_idx++];		\
kdl->stat++;						\
kdl->kdl_cache = (cp);					\
(cp)->cache_dumplog = kdl;				\
}								\
}

/* set non zero for full report */
uint_t kmem_dump_verbose = 0;

/* stats for overize heap */
uint_t kmem_dump_oversize_allocs = 0;
uint_t kmem_dump_oversize_max = 0;

static void
kmem_dumppr(char **pp, char *e, const char *format, ...)
{
    char *p = *pp;

    if (p < e) {
        int n;
        va_list ap;

        va_start(ap, format);
        n = vsnprintf(p, e - p, format, ap);
        va_end(ap);
        *pp = p + n;
    }
}

/*
 * Called when dumpadm(1M) configures dump parameters.
 */
void
kmem_dump_init(size_t size)
{
    if (kmem_dump_start != NULL)
        zfs_kmem_free(kmem_dump_start, kmem_dump_size);

    if (kmem_dump_log == NULL)
        kmem_dump_log = (kmem_dump_log_t *)zfs_kmem_zalloc(KMEM_DUMP_LOGS *
                                                       sizeof (kmem_dump_log_t), KM_SLEEP);

    kmem_dump_start = zfs_kmem_alloc(size, KM_SLEEP);

    if (kmem_dump_start != NULL) {
        kmem_dump_size = size;
        kmem_dump_curr = kmem_dump_start;
        kmem_dump_end = (void *)((char *)kmem_dump_start + size);
        copy_pattern(KMEM_UNINITIALIZED_PATTERN, kmem_dump_start, size);
    } else {
        kmem_dump_size = 0;
        kmem_dump_curr = NULL;
        kmem_dump_end = NULL;
    }
}

/*
 * Set flag for each kmem_cache_t if is safe to use alternate dump
 * memory. Called just before panic crash dump starts. Set the flag
 * for the calling CPU.
 */
void
kmem_dump_begin(void)
{
    //ASSERT(panicstr != NULL);
    if (kmem_dump_start != NULL) {
        kmem_cache_t *cp;

        for (cp = list_head(&kmem_caches); cp != NULL;
             cp = list_next(&kmem_caches, cp)) {
            kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);

            if (cp->cache_arena->vm_cflags & VMC_DUMPSAFE) {
                cp->cache_flags |= KMF_DUMPDIVERT;
                ccp->cc_flags |= KMF_DUMPDIVERT;
                ccp->cc_dump_rounds = ccp->cc_rounds;
                ccp->cc_dump_prounds = ccp->cc_prounds;
                ccp->cc_rounds = ccp->cc_prounds = -1;
            } else {
                cp->cache_flags |= KMF_DUMPUNSAFE;
                ccp->cc_flags |= KMF_DUMPUNSAFE;
            }
        }
    }
}

/*
 * finished dump intercept
 * print any warnings on the console
 * return verbose information to dumpsys() in the given buffer
 */
size_t
kmem_dump_finish(char *buf, size_t size)
{
    int kdi_idx;
    int kdi_end = kmem_dump_log_idx;
    int percent = 0;
    int header = 0;
    int warn = 0;
    size_t used;
    kmem_cache_t *cp;
    kmem_dump_log_t *kdl;
    char *e = buf + size;
    char *p = buf;

    if (kmem_dump_size == 0 || kmem_dump_verbose == 0)
        return (0);

    used = (char *)kmem_dump_curr - (char *)kmem_dump_start;
    percent = (used * 100) / kmem_dump_size;

    kmem_dumppr(&p, e, "%% heap used,%d\n", percent);
    kmem_dumppr(&p, e, "used bytes,%ld\n", used);
    kmem_dumppr(&p, e, "heap size,%ld\n", kmem_dump_size);
    kmem_dumppr(&p, e, "Oversize allocs,%d\n",
                kmem_dump_oversize_allocs);
    kmem_dumppr(&p, e, "Oversize max size,%ld\n",
                kmem_dump_oversize_max);

    for (kdi_idx = 0; kdi_idx < kdi_end; kdi_idx++) {
        kdl = &kmem_dump_log[kdi_idx];
        cp = kdl->kdl_cache;
        if (cp == NULL)
            break;
        if (kdl->kdl_alloc_fails)
            ++warn;
        if (header == 0) {
            kmem_dumppr(&p, e,
                        "Cache Name,Allocs,Frees,Alloc Fails,"
                        "Nondump Frees,Unsafe Allocs/Frees\n");
            header = 1;
        }
        kmem_dumppr(&p, e, "%s,%d,%d,%d,%d,%d\n",
                    cp->cache_name, kdl->kdl_allocs, kdl->kdl_frees,
                    kdl->kdl_alloc_fails, kdl->kdl_free_nondump,
                    kdl->kdl_unsafe);
    }

    /* return buffer size used */
    if (p < e)
        bzero(p, e - p);
    return (p - buf);
}

/*
 * Allocate a constructed object from alternate dump memory.
 */
void *
kmem_cache_alloc_dump(kmem_cache_t *cp, int kmflag)
{
    void *buf;
    void *curr;
    char *bufend;

    /* return a constructed object */
    if ((buf = cp->cache_dumpfreelist) != NULL) {
        cp->cache_dumpfreelist = KMEM_DUMPCTL(cp, buf)->kdc_next;
        KDI_LOG(cp, kdl_allocs);
        return (buf);
    }

    /* create a new constructed object */
    curr = kmem_dump_curr;
    buf = (void *)P2ROUNDUP((uintptr_t)curr, cp->cache_align);
    bufend = (char *)KMEM_DUMPCTL(cp, buf) + sizeof (kmem_dumpctl_t);

    /* hat layer objects cannot cross a page boundary */
    if (cp->cache_align < PAGESIZE) {
        char *page = (char *)P2ROUNDUP((uintptr_t)buf, PAGESIZE);
        if (bufend > page) {
            bufend += page - (char *)buf;
            buf = (void *)page;
        }
    }

    /* fall back to normal alloc if reserved area is used up */
    if (bufend > (char *)kmem_dump_end) {
        kmem_dump_curr = kmem_dump_end;
        KDI_LOG(cp, kdl_alloc_fails);
        return (NULL);
    }

    /*
     * Must advance curr pointer before calling a constructor that
     * may also allocate memory.
     */
    kmem_dump_curr = bufend;

    /* run constructor */
    if (cp->cache_constructor != NULL &&
        cp->cache_constructor(buf, cp->cache_private, kmflag)
        != 0) {
#ifdef DEBUG
        printf("name='%s' cache=0x%p: kmem cache constructor failed\n",
               cp->cache_name, (void *)cp);
#endif
        /* reset curr pointer iff no allocs were done */
        if (kmem_dump_curr == bufend)
            kmem_dump_curr = curr;

        /* fall back to normal alloc if the constructor fails */
        KDI_LOG(cp, kdl_alloc_fails);
        return (NULL);
    }

    KDI_LOG(cp, kdl_allocs);
    return (buf);
}

/*
 * Free a constructed object in alternate dump memory.
 */
int
kmem_cache_free_dump(kmem_cache_t *cp, void *buf)
{
    /* save constructed buffers for next time */
    if ((char *)buf >= (char *)kmem_dump_start &&
        (char *)buf < (char *)kmem_dump_end) {
        KMEM_DUMPCTL(cp, buf)->kdc_next = cp->cache_dumpfreelist;
        cp->cache_dumpfreelist = buf;
        KDI_LOG(cp, kdl_frees);
        return (0);
    }

    /* count all non-dump buf frees */
    KDI_LOG(cp, kdl_free_nondump);

    /* just drop buffers that were allocated before dump started */
    if (kmem_dump_curr < kmem_dump_end)
        return (0);

    /* fall back to normal free if reserved area is used up */
    return (1);
}

/*
 * Allocate a constructed object from cache cp.
 */
void *
kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
    kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);
    kmem_magazine_t *fmp;
    void *buf;
    mutex_enter(&ccp->cc_lock);
    for (;;) {
        /*
         * If there's an object available in the current CPU's
         * loaded magazine, just take it and return.
         */
        if (ccp->cc_rounds > 0) {
            buf = ccp->cc_loaded->mag_round[--ccp->cc_rounds];
            ccp->cc_alloc++;
            mutex_exit(&ccp->cc_lock);
            if (ccp->cc_flags & (KMF_BUFTAG | KMF_DUMPUNSAFE)) {
                if (ccp->cc_flags & KMF_DUMPUNSAFE) {
                    ASSERT(!(ccp->cc_flags &
                             KMF_DUMPDIVERT));
                    KDI_LOG(cp, kdl_unsafe);
                }
                if ((ccp->cc_flags & KMF_BUFTAG) &&
                    kmem_cache_alloc_debug(cp, buf, kmflag, 0,
                                           caller()) != 0) {
                        if (kmflag & KM_NOSLEEP)
                            return (NULL);
                        mutex_enter(&ccp->cc_lock);
                        continue;
                    }
            }
            return (buf);
        }

        /*
         * The loaded magazine is empty.  If the previously loaded
         * magazine was full, exchange them and try again.
         */
        if (ccp->cc_prounds > 0) {
            kmem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
            continue;
        }

        /*
         * Return an alternate buffer at dump time to preserve
         * the heap.
         */
        if (ccp->cc_flags & (KMF_DUMPDIVERT | KMF_DUMPUNSAFE)) {
            if (ccp->cc_flags & KMF_DUMPUNSAFE) {
                ASSERT(!(ccp->cc_flags & KMF_DUMPDIVERT));
                /* log it so that we can warn about it */
                KDI_LOG(cp, kdl_unsafe);
            } else {
                if ((buf = kmem_cache_alloc_dump(cp, kmflag)) !=
                    NULL) {
                    mutex_exit(&ccp->cc_lock);
                    return (buf);
                }
                break;		/* fall back to slab layer */
            }
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
                kmem_depot_free(cp, &cp->cache_empty,
                                ccp->cc_ploaded);
            kmem_cpu_reload(ccp, fmp, ccp->cc_magsize);
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
    buf = kmem_slab_alloc(cp, kmflag);

    if (buf == NULL)
        return (NULL);

    if (cp->cache_flags & KMF_BUFTAG) {
        /*
         * Make kmem_cache_alloc_debug() apply the constructor for us.
         */
        int rc = kmem_cache_alloc_debug(cp, buf, kmflag, 1, caller());
        if (rc != 0) {
            if (kmflag & KM_NOSLEEP)
                return (NULL);
            /*
             * kmem_cache_alloc_debug() detected corruption
             * but didn't panic (kmem_panic <= 0). We should not be
             * here because the constructor failed (indicated by a
             * return code of 1). Try again.
             */
            ASSERT(rc == -1);
            return (kmem_cache_alloc(cp, kmflag));
        }
        return (buf);
    }

    if (cp->cache_constructor != NULL &&
        cp->cache_constructor(buf, cp->cache_private, kmflag) != 0) {
        atomic_inc_64(&cp->cache_alloc_fail);
        kmem_slab_free(cp, buf);
        return (NULL);
    }

    return (buf);
}

/*
 * The freed argument tells whether or not kmem_cache_free_debug() has already
 * been called so that we can avoid the duplicate free error. For example, a
 * buffer on a magazine has already been freed by the client but is still
 * constructed.
 */
static void
kmem_slab_free_constructed(kmem_cache_t *cp, void *buf, boolean_t freed)
{
    if (!freed && (cp->cache_flags & KMF_BUFTAG))
        if (kmem_cache_free_debug(cp, buf, caller()) == -1)
            return;

    /*
     * Note that if KMF_DEADBEEF is in effect and KMF_LITE is not,
     * kmem_cache_free_debug() will have already applied the destructor.
     */
    if ((cp->cache_flags & (KMF_DEADBEEF | KMF_LITE)) != KMF_DEADBEEF &&
        cp->cache_destructor != NULL) {
        if (cp->cache_flags & KMF_DEADBEEF) {	/* KMF_LITE implied */
            kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
            *(uint64_t *)buf = btp->bt_redzone;
            cp->cache_destructor(buf, cp->cache_private);
            *(uint64_t *)buf = KMEM_FREE_PATTERN;
        } else {
            cp->cache_destructor(buf, cp->cache_private);
        }
    }

    kmem_slab_free(cp, buf);
}

/*
 * Used when there's no room to free a buffer to the per-CPU cache.
 * Drops and re-acquires &ccp->cc_lock, and returns non-zero if the
 * caller should try freeing to the per-CPU cache again.
 * Note that we don't directly install the magazine in the cpu cache,
 * since its state may have changed wildly while the lock was dropped.
 */
static int
kmem_cpucache_magazine_alloc(kmem_cpu_cache_t *ccp, kmem_cache_t *cp)
{
    kmem_magazine_t *emp;
    kmem_magtype_t *mtp;

    ASSERT(MUTEX_HELD(&ccp->cc_lock));
    ASSERT(((uint_t)ccp->cc_rounds == ccp->cc_magsize ||
            ((uint_t)ccp->cc_rounds == -1)) &&
           ((uint_t)ccp->cc_prounds == ccp->cc_magsize ||
            ((uint_t)ccp->cc_prounds == -1)));

    emp = kmem_depot_alloc(cp, &cp->cache_empty);
    if (emp != NULL) {
        if (ccp->cc_ploaded != NULL)
            kmem_depot_free(cp, &cp->cache_full,
                            ccp->cc_ploaded);
        kmem_cpu_reload(ccp, emp, 0);
        return (1);
    }
    /*
     * There are no empty magazines in the depot,
     * so try to allocate a new one.  We must drop all locks
     * across kmem_cache_alloc() because lower layers may
     * attempt to allocate from this cache.
     */
    mtp = cp->cache_magtype;
    mutex_exit(&ccp->cc_lock);
    emp = kmem_cache_alloc(mtp->mt_cache, KM_NOSLEEP);
    mutex_enter(&ccp->cc_lock);

    if (emp != NULL) {
        /*
         * We successfully allocated an empty magazine.
         * However, we had to drop ccp->cc_lock to do it,
         * so the cache's magazine size may have changed.
         * If so, free the magazine and try again.
         */
        if (ccp->cc_magsize != mtp->mt_magsize) {
            mutex_exit(&ccp->cc_lock);
            kmem_cache_free(mtp->mt_cache, emp);
            mutex_enter(&ccp->cc_lock);
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

/*
 * Free a constructed object to cache cp.
 */
void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
    kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);

    /*
     * The client must not free either of the buffers passed to the move
     * callback function.
     */
    ASSERT(cp->cache_defrag == NULL ||
           cp->cache_defrag->kmd_thread != spl_current_thread() ||
           (buf != cp->cache_defrag->kmd_from_buf &&
            buf != cp->cache_defrag->kmd_to_buf));

    if (ccp->cc_flags & (KMF_BUFTAG | KMF_DUMPDIVERT | KMF_DUMPUNSAFE)) {
        if (ccp->cc_flags & KMF_DUMPUNSAFE) {
            ASSERT(!(ccp->cc_flags & KMF_DUMPDIVERT));
            /* log it so that we can warn about it */
            KDI_LOG(cp, kdl_unsafe);
        } else if (KMEM_DUMPCC(ccp) && !kmem_cache_free_dump(cp, buf)) {
            return;
        }
        if (ccp->cc_flags & KMF_BUFTAG) {
            if (kmem_cache_free_debug(cp, buf, caller()) == -1)
                return;
        }
    }

    mutex_enter(&ccp->cc_lock);
    /*
     * Any changes to this logic should be reflected in kmem_slab_prefill()
     */
    for (;;) {
        /*
         * If there's a slot available in the current CPU's
         * loaded magazine, just put the object there and return.
         */
        if ((uint_t)ccp->cc_rounds < ccp->cc_magsize) {
            ccp->cc_loaded->mag_round[ccp->cc_rounds++] = buf;
            ccp->cc_free++;
            mutex_exit(&ccp->cc_lock);
            return;
        }

        /*
         * The loaded magazine is full.  If the previously loaded
         * magazine was empty, exchange them and try again.
         */
        if (ccp->cc_prounds == 0) {
            kmem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
            continue;
        }

        /*
         * If the magazine layer is disabled, break out now.
         */
        if (ccp->cc_magsize == 0)
            break;

        if (!kmem_cpucache_magazine_alloc(ccp, cp)) {
            /*
             * We couldn't free our constructed object to the
             * magazine layer, so apply its destructor and free it
             * to the slab layer.
             */
            break;
        }
    }
    mutex_exit(&ccp->cc_lock);
	kpreempt(KPREEMPT_SYNC);
    kmem_slab_free_constructed(cp, buf, B_TRUE);
}

static void
kmem_slab_prefill(kmem_cache_t *cp, kmem_slab_t *sp)
{
    kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);
    //int cache_flags = cp->cache_flags;

    kmem_bufctl_t *next, *head;
    size_t nbufs;

    /*
     * Completely allocate the newly created slab and put the pre-allocated
     * buffers in magazines. Any of the buffers that cannot be put in
     * magazines must be returned to the slab.
     */
    ASSERT(MUTEX_HELD(&cp->cache_lock));
    //ASSERT((cache_flags & (KMF_PREFILL|KMF_BUFTAG)) == KMF_PREFILL);
    ASSERT(cp->cache_constructor == NULL);
    ASSERT(sp->slab_cache == cp);
    ASSERT(sp->slab_refcnt == 1);
    ASSERT(sp->slab_head != NULL && sp->slab_chunks > sp->slab_refcnt);
    ASSERT(avl_find(&cp->cache_partial_slabs, sp, NULL) == NULL);

    head = sp->slab_head;
    nbufs = (sp->slab_chunks - sp->slab_refcnt);
    sp->slab_head = NULL;
    sp->slab_refcnt += nbufs;
    cp->cache_bufslab -= nbufs;
    cp->cache_slab_alloc += nbufs;
    list_insert_head(&cp->cache_complete_slabs, sp);
    cp->cache_complete_slab_count++;
    mutex_exit(&cp->cache_lock);
    mutex_enter(&ccp->cc_lock);

    while (head != NULL) {
        void *buf = KMEM_BUF(cp, head);
        /*
         * If there's a slot available in the current CPU's
         * loaded magazine, just put the object there and
         * continue.
         */
        if ((uint_t)ccp->cc_rounds < ccp->cc_magsize) {
            ccp->cc_loaded->mag_round[ccp->cc_rounds++] =
            buf;
            ccp->cc_free++;
            nbufs--;
            head = head->bc_next;
            continue;
        }

        /*
         * The loaded magazine is full.  If the previously
         * loaded magazine was empty, exchange them and try
         * again.
         */
        if (ccp->cc_prounds == 0) {
            kmem_cpu_reload(ccp, ccp->cc_ploaded,
                            ccp->cc_prounds);
            continue;
        }

        /*
         * If the magazine layer is disabled, break out now.
         */

        if (ccp->cc_magsize == 0) {
            break;
        }

        if (!kmem_cpucache_magazine_alloc(ccp, cp))
            break;
    }
    mutex_exit(&ccp->cc_lock);
    if (nbufs != 0) {
        ASSERT(head != NULL);

        /*
         * If there was a failure, return remaining objects to
         * the slab
         */
        while (head != NULL) {
            ASSERT(nbufs != 0);
            next = head->bc_next;
            head->bc_next = NULL;
            kmem_slab_free(cp, KMEM_BUF(cp, head));
            head = next;
            nbufs--;
        }
    }
    ASSERT(head == NULL);
    ASSERT(nbufs == 0);
    mutex_enter(&cp->cache_lock);
}

void *
zfs_kmem_zalloc(size_t size, int kmflag)
{
    size_t index;
    void *buf;

    if ((index = ((size - 1) >> KMEM_ALIGN_SHIFT)) < KMEM_ALLOC_TABLE_MAX) {
        kmem_cache_t *cp = kmem_alloc_table[index];
        buf = kmem_cache_alloc(cp, kmflag);
        if (buf != NULL) {
            if ((cp->cache_flags & KMF_BUFTAG) && !KMEM_DUMP(cp)) {
                kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
                ((uint8_t *)buf)[size] = KMEM_REDZONE_BYTE;
                ((uint32_t *)btp)[1] = KMEM_SIZE_ENCODE(size);

                if (cp->cache_flags & KMF_LITE) {
                    KMEM_BUFTAG_LITE_ENTER(btp,
                                           kmem_lite_count, caller());
                }
            }
            bzero(buf, size);
        }
    } else {
        buf = zfs_kmem_alloc(size, kmflag);
        if (buf != NULL)
            bzero(buf, size);
    }
    return (buf);
}

void *
zfs_kmem_alloc(size_t size, int kmflag)
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

        buf = vmem_alloc(kmem_oversize_arena, size,
                         kmflag & KM_VMFLAGS);
        if (buf == NULL)
            kmem_log_event(kmem_failure_log, NULL, NULL,
                           (void *)size);
        else if (KMEM_DUMP(kmem_slab_cache)) {
            /* stats for dump intercept */
            kmem_dump_oversize_allocs++;
            if (size > kmem_dump_oversize_max)
                kmem_dump_oversize_max = size;
        }
        return (buf);
    }

    buf = kmem_cache_alloc(cp, kmflag);
    if ((cp->cache_flags & KMF_BUFTAG) && !KMEM_DUMP(cp) && buf != NULL) {
        kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
        ((uint8_t *)buf)[size] = KMEM_REDZONE_BYTE;
        ((uint32_t *)btp)[1] = KMEM_SIZE_ENCODE(size);

        if (cp->cache_flags & KMF_LITE) {
            KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count, caller());
        }
    }
    return (buf);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    size_t index;
    kmem_cache_t *cp;

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
        vmem_free(kmem_oversize_arena, buf, size);
        return;
    }

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
    kmem_cache_free(cp, buf);
}

#ifndef APPLE
//void *
//kmem_firewall_va_alloc(vmem_t *vmp, size_t size, int vmflag)
//{
//    size_t realsize = size + vmp->vm_quantum;
//    void *addr;
//
//    /*
//     * Annoying edge case: if 'size' is just shy of ULONG_MAX, adding
//     * vm_quantum will cause integer wraparound.  Check for this, and
//     * blow off the firewall page in this case.  Note that such a
//     * giant allocation (the entire kernel address space) can never
//     * be satisfied, so it will either fail immediately (VM_NOSLEEP)
//     * or sleep forever (VM_SLEEP).  Thus, there is no need for a
//     * corresponding check in kmem_firewall_va_free().
//     */
//    if (realsize < size)
//        realsize = size;
//
//    /*
//     * While boot still owns resource management, make sure that this
//     * redzone virtual address allocation is properly accounted for in
//     * OBPs "virtual-memory" "available" lists because we're
//     * effectively claiming them for a red zone.  If we don't do this,
//     * the available lists become too fragmented and too large for the
//     * current boot/kernel memory list interface.
//     */
//    addr = vmem_alloc(vmp, realsize, vmflag | VM_NEXTFIT);
//
//    if (addr != NULL && kvseg.s_base == NULL && realsize != size)
//        (void) boot_virt_alloc((char *)addr + size, vmp->vm_quantum);
//
//    return (addr);
//}
//
//void
//kmem_firewall_va_free(vmem_t *vmp, void *addr, size_t size)
//{
//    ASSERT((kvseg.s_base == NULL ?
//            va_to_pfn((char *)addr + size) :
//            hat_getpfnum(kas.a_hat, (caddr_t)addr + size)) == PFN_INVALID);
//
//    vmem_free(vmp, addr, size + vmp->vm_quantum);
//}
#endif

/*
 * Try to allocate at least `size' bytes of memory without sleeping or
 * panicking. Return actual allocated size in `asize'. If allocation failed,
 * try final allocation with sleep or panic allowed.
 */
void *
kmem_alloc_tryhard(size_t size, size_t *asize, int kmflag)
{
    void *p;

    *asize = P2ROUNDUP(size, KMEM_ALIGN);
    do {
        p = kmem_alloc(*asize, (kmflag | KM_NOSLEEP) & ~KM_PANIC);
        if (p != NULL)
            return (p);
        *asize += KMEM_ALIGN;
    } while (*asize <= PAGESIZE);

    *asize = P2ROUNDUP(size, KMEM_ALIGN);
    return (zfs_kmem_alloc(*asize, kmflag));
}

/*
 * Reclaim all unused memory from a cache.
 */
static void
kmem_cache_reap(kmem_cache_t *cp)
{
    ASSERT(taskq_member(kmem_taskq, curthread));

	//return;

    cp->cache_reap++;

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

    if (cp->cache_defrag != NULL && !kmem_move_noreap) {
        kmem_cache_defrag(cp);
    }
}

static void
kmem_reap_timeout(void *flag_arg)
{
    uint32_t *flag = (uint32_t *)flag_arg;

    ASSERT(flag == &kmem_reaping || flag == &kmem_reaping_idspace);
    *flag = 0;
}

static void
kmem_reap_done(void *flag)
{
#ifndef APPLE
//    if (!callout_init_done) {
//        /* can't schedule a timeout at this point */
//        kmem_reap_timeout(flag);
//    } else {
//        (void) timeout(kmem_reap_timeout, flag, kmem_reap_interval);
//    }
#endif
    (void) bsd_timeout(kmem_reap_timeout, flag, &kmem_reap_interval);
}

static void
kmem_reap_start(void *flag)
{
    ASSERT(flag == &kmem_reaping || flag == &kmem_reaping_idspace);

    if (flag == &kmem_reaping) {
        kmem_cache_applyall(kmem_cache_reap, kmem_taskq, TQ_NOSLEEP);
        /*
         * if we have segkp under heap, reap segkp cache.
         */
#ifndef APPLE
//        if (segkp_fromheap)
//            segkp_cache_free();
#endif
    }
    else
        kmem_cache_applyall_id(kmem_cache_reap, kmem_taskq, TQ_NOSLEEP);

    /*
     * We use taskq_dispatch() to schedule a timeout to clear
     * the flag so that kmem_reap() becomes self-throttling:
     * we won't reap again until the current reap completes *and*
     * at least kmem_reap_interval ticks have elapsed.
     */
    if (!taskq_dispatch(kmem_taskq, kmem_reap_done, flag, TQ_NOSLEEP))
        kmem_reap_done(flag);
}

static void
kmem_reap_common(void *flag_arg)
{
    uint32_t *flag = (uint32_t *)flag_arg;


    if (MUTEX_HELD(&kmem_cache_lock) || kmem_taskq == NULL ||
        atomic_cas_32(flag, 0, 1) != 0)
        return;

    /*
     * It may not be kosher to do memory allocation when a reap is called
     * is called (for example, if vmem_populate() is in the call chain).
     * So we start the reap going with a TQ_NOALLOC dispatch.  If the
     * dispatch fails, we reset the flag, and the next reap will try again.
     */
    if (!taskq_dispatch(kmem_taskq, kmem_reap_start, flag, TQ_NOALLOC))
        *flag = 0;
}

/*
 * Reclaim all unused memory from all caches.  Called from the VM system
 * when memory gets tight.
 */
void
kmem_reap(void)
{
    kmem_reap_common(&kmem_reaping);
}

/*
 * Reclaim all unused memory from identifier arenas, called when a vmem
 * arena not back by memory is exhausted.  Since reaping memory-backed caches
 * cannot help with identifier exhaustion, we avoid both a large amount of
 * work and unwanted side-effects from reclaim callbacks.
 */
void
kmem_reap_idspace(void)
{
    kmem_reap_common(&kmem_reaping_idspace);
}

/*
 * Purge all magazines from a cache and set its magazine limit to zero.
 * All calls are serialized by the kmem_taskq lock, except for the final
 * call from kmem_cache_destroy().
 */
static void
kmem_cache_magazine_purge(kmem_cache_t *cp)
{
    kmem_cpu_cache_t *ccp;
    kmem_magazine_t *mp, *pmp;
    int rounds, prounds, cpu_seqid;

    ASSERT(!list_link_active(&cp->cache_link) ||
           taskq_member(kmem_taskq, curthread));
    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));

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

/*
 * Enable per-cpu magazines on a cache.
 */
static void
kmem_cache_magazine_enable(kmem_cache_t *cp)
{
    int cpu_seqid;

    if (cp->cache_flags & KMF_NOMAGAZINE)
        return;

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
        mutex_enter(&ccp->cc_lock);
        ccp->cc_magsize = cp->cache_magtype->mt_magsize;
        mutex_exit(&ccp->cc_lock);
    }

}

static void
kmem_cache_magazine_disable(kmem_cache_t *cp)
{
    int cpu_seqid;

    if (cp->cache_flags & KMF_NOMAGAZINE)
        return;

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
        mutex_enter(&ccp->cc_lock);
        ccp->cc_magsize = 0;
        mutex_exit(&ccp->cc_lock);
    }

}

/*
 * Reap (almost) everything right now.  See kmem_cache_magazine_purge()
 * for explanation of the back-to-back kmem_depot_ws_update() calls.
 */
void
kmem_cache_reap_now(kmem_cache_t *cp)
{
    ASSERT(list_link_active(&cp->cache_link));

    kmem_depot_ws_update(cp);
    kmem_depot_ws_update(cp);

    (void) taskq_dispatch(kmem_taskq,
                          (task_func_t *)kmem_depot_ws_reap, cp, TQ_SLEEP);
    taskq_wait(kmem_taskq);
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

    ASSERT(taskq_member(kmem_taskq, curthread));

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
 * Rescale a cache's hash table, so that the table size is roughly the
 * cache size.  We want the average lookup time to be extremely small.
 */
static void
kmem_hash_rescale(kmem_cache_t *cp)
{
    kmem_bufctl_t **old_table, **new_table, *bcp;
    size_t old_size, new_size, h;

    ASSERT(taskq_member(kmem_taskq, curthread));

    new_size = MAX(KMEM_HASH_INITIAL,
                   1 << (highbit(3 * cp->cache_buftotal + 4) - 2));
    old_size = cp->cache_hash_mask + 1;

    if ((old_size >> 1) <= new_size && new_size <= (old_size << 1))
        return;

    new_table = vmem_alloc(kmem_hash_arena, new_size * sizeof (void *),
                           VM_NOSLEEP);
    if (new_table == NULL)
        return;
    bzero(new_table, new_size * sizeof (void *));

    mutex_enter(&cp->cache_lock);

    old_size = cp->cache_hash_mask + 1;
    old_table = cp->cache_hash_table;

    cp->cache_hash_mask = new_size - 1;
    cp->cache_hash_table = new_table;
    cp->cache_rescale++;

    for (h = 0; h < old_size; h++) {
        bcp = old_table[h];
        while (bcp != NULL) {
            void *addr = bcp->bc_addr;
            kmem_bufctl_t *next_bcp = bcp->bc_next;
            kmem_bufctl_t **hash_bucket = KMEM_HASH(cp, addr);
            bcp->bc_next = *hash_bucket;
            *hash_bucket = bcp;
            bcp = next_bcp;
        }
    }

    mutex_exit(&cp->cache_lock);

    vmem_free(kmem_hash_arena, old_table, old_size * sizeof (void *));
}

/*
 * Perform periodic maintenance on a cache: hash rescaling, depot working-set
 * update, magazine resizing, and slab consolidation.
 */
static void
kmem_cache_update(kmem_cache_t *cp)
{
    int need_hash_rescale = 0;
    int need_magazine_resize = 0;

    ASSERT(MUTEX_HELD(&kmem_cache_lock));

    /*
     * If the cache has become much larger or smaller than its hash table,
     * fire off a request to rescale the hash table.
     */
    mutex_enter(&cp->cache_lock);

    if ((cp->cache_flags & KMF_HASH) &&
        (cp->cache_buftotal > (cp->cache_hash_mask << 1) ||
         (cp->cache_buftotal < (cp->cache_hash_mask >> 1) &&
          cp->cache_hash_mask > KMEM_HASH_INITIAL)))
        need_hash_rescale = 1;

    mutex_exit(&cp->cache_lock);

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

    if (need_hash_rescale)
        (void) taskq_dispatch(kmem_taskq,
                              (task_func_t *)kmem_hash_rescale, cp, TQ_NOSLEEP);

    if (need_magazine_resize)
        (void) taskq_dispatch(kmem_taskq,
                              (task_func_t *)kmem_cache_magazine_resize, cp, TQ_NOSLEEP);

    if (cp->cache_defrag != NULL)
        (void) taskq_dispatch(kmem_taskq,
                              (task_func_t *)kmem_cache_scan, cp, TQ_NOSLEEP);

}

static void kmem_update(void *);

static void
kmem_update_timeout(void *dummy)
{
    (void) bsd_timeout(kmem_update, dummy, &kmem_reap_interval);
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

static int
kmem_cache_kstat_update(kstat_t *ksp, int rw)
{
    struct kmem_cache_kstat *kmcp = &kmem_cache_kstat;
    kmem_cache_t *cp = ksp->ks_private;
    uint64_t cpu_buf_avail;
    uint64_t buf_avail = 0;
    int cpu_seqid;
    long reap;

    ASSERT(MUTEX_HELD(&kmem_cache_kstat_lock));

    if (rw == KSTAT_WRITE)
        return (EACCES);

    mutex_enter(&cp->cache_lock);

    kmcp->kmc_alloc_fail.value.ui64		= cp->cache_alloc_fail;
    kmcp->kmc_alloc.value.ui64		= cp->cache_slab_alloc;
    kmcp->kmc_free.value.ui64		= cp->cache_slab_free;
    kmcp->kmc_slab_alloc.value.ui64		= cp->cache_slab_alloc;
    kmcp->kmc_slab_free.value.ui64		= cp->cache_slab_free;

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];

        mutex_enter(&ccp->cc_lock);

        cpu_buf_avail = 0;
        if (ccp->cc_rounds > 0)
            cpu_buf_avail += ccp->cc_rounds;
        if (ccp->cc_prounds > 0)
            cpu_buf_avail += ccp->cc_prounds;

        kmcp->kmc_alloc.value.ui64	+= ccp->cc_alloc;
        kmcp->kmc_free.value.ui64	+= ccp->cc_free;
        buf_avail			+= cpu_buf_avail;

        mutex_exit(&ccp->cc_lock);
    }

    mutex_enter(&cp->cache_depot_lock);

    kmcp->kmc_depot_alloc.value.ui64	= cp->cache_full.ml_alloc;
    kmcp->kmc_depot_free.value.ui64		= cp->cache_empty.ml_alloc;
    kmcp->kmc_depot_contention.value.ui64	= cp->cache_depot_contention;
    kmcp->kmc_full_magazines.value.ui64	= cp->cache_full.ml_total;
    kmcp->kmc_empty_magazines.value.ui64	= cp->cache_empty.ml_total;
    kmcp->kmc_magazine_size.value.ui64	=
    (cp->cache_flags & KMF_NOMAGAZINE) ?
    0 : cp->cache_magtype->mt_magsize;

    kmcp->kmc_alloc.value.ui64		+= cp->cache_full.ml_alloc;
    kmcp->kmc_free.value.ui64		+= cp->cache_empty.ml_alloc;
    buf_avail += cp->cache_full.ml_total * cp->cache_magtype->mt_magsize;

    reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
    reap = MIN(reap, cp->cache_full.ml_total);

    mutex_exit(&cp->cache_depot_lock);

    kmcp->kmc_buf_size.value.ui64	= cp->cache_bufsize;
    kmcp->kmc_align.value.ui64	= cp->cache_align;
    kmcp->kmc_chunk_size.value.ui64	= cp->cache_chunksize;
    kmcp->kmc_slab_size.value.ui64	= cp->cache_slabsize;
    kmcp->kmc_buf_constructed.value.ui64 = buf_avail;
    buf_avail += cp->cache_bufslab;
    kmcp->kmc_buf_avail.value.ui64	= buf_avail;
    kmcp->kmc_buf_inuse.value.ui64	= cp->cache_buftotal - buf_avail;
    kmcp->kmc_buf_total.value.ui64	= cp->cache_buftotal;
    kmcp->kmc_buf_max.value.ui64	= cp->cache_bufmax;
    kmcp->kmc_slab_create.value.ui64	= cp->cache_slab_create;
    kmcp->kmc_slab_destroy.value.ui64	= cp->cache_slab_destroy;
    kmcp->kmc_hash_size.value.ui64	= (cp->cache_flags & KMF_HASH) ?
    cp->cache_hash_mask + 1 : 0;
    kmcp->kmc_hash_lookup_depth.value.ui64	= cp->cache_lookup_depth;
    kmcp->kmc_hash_rescale.value.ui64	= cp->cache_rescale;
    kmcp->kmc_vmem_source.value.ui64	= cp->cache_arena->vm_id;
    kmcp->kmc_reap.value.ui64	= cp->cache_reap;

    if (cp->cache_defrag == NULL) {
        kmcp->kmc_move_callbacks.value.ui64	= 0;
        kmcp->kmc_move_yes.value.ui64		= 0;
        kmcp->kmc_move_no.value.ui64		= 0;
        kmcp->kmc_move_later.value.ui64		= 0;
        kmcp->kmc_move_dont_need.value.ui64	= 0;
        kmcp->kmc_move_dont_know.value.ui64	= 0;
        kmcp->kmc_move_hunt_found.value.ui64	= 0;
        kmcp->kmc_move_slabs_freed.value.ui64	= 0;
        kmcp->kmc_defrag.value.ui64		= 0;
        kmcp->kmc_scan.value.ui64		= 0;
        kmcp->kmc_move_reclaimable.value.ui64	= 0;
    } else {
        int64_t reclaimable;

        kmem_defrag_t *kd = cp->cache_defrag;
        kmcp->kmc_move_callbacks.value.ui64	= kd->kmd_callbacks;
        kmcp->kmc_move_yes.value.ui64		= kd->kmd_yes;
        kmcp->kmc_move_no.value.ui64		= kd->kmd_no;
        kmcp->kmc_move_later.value.ui64		= kd->kmd_later;
        kmcp->kmc_move_dont_need.value.ui64	= kd->kmd_dont_need;
        kmcp->kmc_move_dont_know.value.ui64	= kd->kmd_dont_know;
        kmcp->kmc_move_hunt_found.value.ui64	= kd->kmd_hunt_found;
        kmcp->kmc_move_slabs_freed.value.ui64	= kd->kmd_slabs_freed;
        kmcp->kmc_defrag.value.ui64		= kd->kmd_defrags;
        kmcp->kmc_scan.value.ui64		= kd->kmd_scans;

        reclaimable = cp->cache_bufslab - (cp->cache_maxchunks - 1);
        reclaimable = MAX(reclaimable, 0);
        reclaimable += ((uint64_t)reap * cp->cache_magtype->mt_magsize);
        kmcp->kmc_move_reclaimable.value.ui64	= reclaimable;
    }

    mutex_exit(&cp->cache_lock);
    return (0);
}

/*
 * Return a named statistic about a particular cache.
 * This shouldn't be called very often, so it's currently designed for
 * simplicity (leverages existing kstat support) rather than efficiency.
 */
uint64_t
kmem_cache_stat(kmem_cache_t *cp, char *name)
{
    int i;
    kstat_t *ksp = cp->cache_kstat;
    kstat_named_t *knp = (kstat_named_t *)&kmem_cache_kstat;
    uint64_t value = 0;

    if (ksp != NULL) {
        mutex_enter(&kmem_cache_kstat_lock);
        (void) kmem_cache_kstat_update(ksp, KSTAT_READ);
        for (i = 0; i < ksp->ks_ndata; i++) {
            if (strcmp(knp[i].name, name) == 0) {
                value = knp[i].value.ui64;
                break;
            }
        }
        mutex_exit(&kmem_cache_kstat_lock);
    }
    return (value);
}

/*
 * Return an estimate of currently available kernel heap memory.
 * On 32-bit systems, physical memory may exceed virtual memory,
 * we just truncate the result at 1GB.
 */
size_t
kmem_avail(void)
{
#ifndef APPLE
//    spgcnt_t rmem = availrmem - tune.t_minarmem;
//    spgcnt_t fmem = freemem - minfree;
//
//    return ((size_t)ptob(MIN(MAX(MIN(rmem, fmem), 0),
//                             1 << (30 - PAGESHIFT))));
#endif
    return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
}

/*
 * Return the maximum amount of memory that is (in theory) allocatable
 * from the heap. This may be used as an estimate only since there
 * is no guarentee this space will still be available when an allocation
 * request is made, nor that the space may be allocated in one big request
 * due to kernel heap fragmentation.
 */
size_t
kmem_maxavail(void)
{
#ifndef APPLE
//    spgcnt_t pmem = availrmem - tune.t_minarmem;
//    spgcnt_t vmem = btop(vmem_size(heap_arena, VMEM_FREE));
//
//    return ((size_t)ptob(MAX(MIN(pmem, vmem), 0)));
#endif
    return (physmem * PAGE_SIZE);
}

/*
 * Indicate whether memory-intensive kmem debugging is enabled.
 */
int
kmem_debugging(void)
{
    return (kmem_flags & (KMF_AUDIT | KMF_REDZONE));
}

/* binning function, sorts finely at the two extremes */
#define	KMEM_PARTIAL_SLAB_WEIGHT(sp, binshift)				\
((((sp)->slab_refcnt <= (binshift)) ||				\
(((sp)->slab_chunks - (sp)->slab_refcnt) <= (binshift)))	\
? -(sp)->slab_refcnt					\
: -((binshift) + ((sp)->slab_refcnt >> (binshift))))

/*
 * Minimizing the number of partial slabs on the freelist minimizes
 * fragmentation (the ratio of unused buffers held by the slab layer). There are
 * two ways to get a slab off of the freelist: 1) free all the buffers on the
 * slab, and 2) allocate all the buffers on the slab. It follows that we want
 * the most-used slabs at the front of the list where they have the best chance
 * of being completely allocated, and the least-used slabs at a safe distance
 * from the front to improve the odds that the few remaining buffers will all be
 * freed before another allocation can tie up the slab. For that reason a slab
 * with a higher slab_refcnt sorts less than than a slab with a lower
 * slab_refcnt.
 *
 * However, if a slab has at least one buffer that is deemed unfreeable, we
 * would rather have that slab at the front of the list regardless of
 * slab_refcnt, since even one unfreeable buffer makes the entire slab
 * unfreeable. If the client returns KMEM_CBRC_NO in response to a cache_move()
 * callback, the slab is marked unfreeable for as long as it remains on the
 * freelist.
 */
static int
//kmem_partial_slab_cmp(const void *p0, const void *p1) lundman!!!!
kmem_partial_slab_cmp(const void *pp0, const void *pp1)
{
    const kmem_cache_t *cp;
    const kmem_slab_t *s0 = pp0;
    const kmem_slab_t *s1 = pp1;
    int w0, w1;
    size_t binshift;

    ASSERT(KMEM_SLAB_IS_PARTIAL(s0));
    ASSERT(KMEM_SLAB_IS_PARTIAL(s1));
    ASSERT(s0->slab_cache == s1->slab_cache);
    cp = s1->slab_cache;
    ASSERT(MUTEX_HELD(&cp->cache_lock));
    binshift = cp->cache_partial_binshift;

    /* weight of first slab */
    w0 = KMEM_PARTIAL_SLAB_WEIGHT(s0, binshift);
    if (s0->slab_flags & KMEM_SLAB_NOMOVE) {
        w0 -= cp->cache_maxchunks;
    }

    /* weight of second slab */
    w1 = KMEM_PARTIAL_SLAB_WEIGHT(s1, binshift);
    if (s1->slab_flags & KMEM_SLAB_NOMOVE) {
        w1 -= cp->cache_maxchunks;
    }

    if (w0 < w1)
        return (-1);
    if (w0 > w1)
        return (1);

    /* compare pointer values */
    if ((uintptr_t)s0 < (uintptr_t)s1)
        return (-1);
    if ((uintptr_t)s0 > (uintptr_t)s1)
        return (1);

    return (0);
}

/*
 * It must be valid to call the destructor (if any) on a newly created object.
 * That is, the constructor (if any) must leave the object in a valid state for
 * the destructor.
 */
kmem_cache_t *
kmem_cache_create(
                  char *name,		/* descriptive name for this cache */
                  size_t bufsize,		/* size of the objects it manages */
                  size_t align,		/* required object alignment */
                  int (*constructor)(void *, void *, int), /* object constructor */
                  void (*destructor)(void *, void *),	/* object destructor */
                  void (*reclaim)(void *), /* memory reclaim callback */
                  void *private,		/* pass-thru arg for constr/destr/reclaim */
                  vmem_t *vmp,		/* vmem source for slab allocation */
                  int cflags)		/* cache creation flags */
{
    int cpu_seqid;
    size_t chunksize;
    kmem_cache_t *cp;
    kmem_magtype_t *mtp;
    size_t csize = KMEM_CACHE_SIZE(max_ncpus);

#ifdef	DEBUG
    /*
     * Cache names should conform to the rules for valid C identifiers
     */
    if (!strident_valid(name)) {
        cmn_err(CE_CONT,
                "kmem_cache_create: '%s' is an invalid cache name\n"
                "cache names must conform to the rules for "
                "C identifiers\n", name);
    }
#endif	/* DEBUG */

    if (vmp == NULL)
        vmp = kmem_default_arena;

    /*
     * If this kmem cache has an identifier vmem arena as its source, mark
     * it such to allow kmem_reap_idspace().
     */
    ASSERT(!(cflags & KMC_IDENTIFIER));   /* consumer should not set this */
    if (vmp->vm_cflags & VMC_IDENTIFIER)
        cflags |= KMC_IDENTIFIER;

    /*
     * Get a kmem_cache structure.  We arrange that cp->cache_cpu[]
     * is aligned on a KMEM_CPU_CACHE_SIZE boundary to prevent
     * false sharing of per-CPU data.
     */
    cp = vmem_xalloc(kmem_cache_arena, csize, KMEM_CPU_CACHE_SIZE,
                     P2NPHASE(csize, KMEM_CPU_CACHE_SIZE), 0, NULL, NULL, VM_SLEEP);
    bzero(cp, csize);
    list_link_init(&cp->cache_link);

    if (align == 0)
        align = KMEM_ALIGN;

    /*
     * If we're not at least KMEM_ALIGN aligned, we can't use free
     * memory to hold bufctl information (because we can't safely
     * perform word loads and stores on it).
     */
    if (align < KMEM_ALIGN)
        cflags |= KMC_NOTOUCH;

    if ((align & (align - 1)) != 0 || align > vmp->vm_quantum)
        panic("kmem_cache_create: bad alignment %lu", align);

    mutex_enter(&kmem_flags_lock);
    if (kmem_flags & KMF_RANDOMIZE)
        kmem_flags = (((kmem_flags | ~KMF_RANDOM) + 1) & KMF_RANDOM) |
        KMF_RANDOMIZE;
    cp->cache_flags = (kmem_flags | cflags) & KMF_DEBUG;
    mutex_exit(&kmem_flags_lock);

    /*
     * Make sure all the various flags are reasonable.
     */
    ASSERT(!(cflags & KMC_NOHASH) || !(cflags & KMC_NOTOUCH));

    if (cp->cache_flags & KMF_LITE) {
        if (bufsize >= kmem_lite_minsize &&
            align <= kmem_lite_maxalign &&
            P2PHASE(bufsize, kmem_lite_maxalign) != 0) {
            cp->cache_flags |= KMF_BUFTAG;
            cp->cache_flags &= ~(KMF_AUDIT | KMF_FIREWALL);
        } else {
            cp->cache_flags &= ~KMF_DEBUG;
        }
    }

    if (cp->cache_flags & KMF_DEADBEEF)
        cp->cache_flags |= KMF_REDZONE;

    if ((cflags & KMC_QCACHE) && (cp->cache_flags & KMF_AUDIT))
        cp->cache_flags |= KMF_NOMAGAZINE;

    if (cflags & KMC_NODEBUG)
        cp->cache_flags &= ~KMF_DEBUG;

    if (cflags & KMC_NOTOUCH)
        cp->cache_flags &= ~KMF_TOUCH;

    if (cflags & KMC_PREFILL)
        cp->cache_flags |= KMF_PREFILL;

    if (cflags & KMC_NOHASH)
        cp->cache_flags &= ~(KMF_AUDIT | KMF_FIREWALL);

    if (cflags & KMC_NOMAGAZINE)
        cp->cache_flags |= KMF_NOMAGAZINE;

    if ((cp->cache_flags & KMF_AUDIT) && !(cflags & KMC_NOTOUCH))
        cp->cache_flags |= KMF_REDZONE;

    if (!(cp->cache_flags & KMF_AUDIT))
        cp->cache_flags &= ~KMF_CONTENTS;

    if ((cp->cache_flags & KMF_BUFTAG) && bufsize >= kmem_minfirewall &&
        !(cp->cache_flags & KMF_LITE) && !(cflags & KMC_NOHASH))
        cp->cache_flags |= KMF_FIREWALL;

    if (vmp != kmem_default_arena || kmem_firewall_arena == NULL)
        cp->cache_flags &= ~KMF_FIREWALL;

    if (cp->cache_flags & KMF_FIREWALL) {
        cp->cache_flags &= ~KMF_BUFTAG;
        cp->cache_flags |= KMF_NOMAGAZINE;
        ASSERT(vmp == kmem_default_arena);
        vmp = kmem_firewall_arena;
    }

    /*
     * Set cache properties.
     */
    (void) strncpy(cp->cache_name, name, KMEM_CACHE_NAMELEN);
    strident_canon(cp->cache_name, KMEM_CACHE_NAMELEN + 1);
    cp->cache_bufsize = bufsize;
    cp->cache_align = align;
    cp->cache_constructor = constructor;
    cp->cache_destructor = destructor;
    cp->cache_reclaim = reclaim;
    cp->cache_private = private;
    cp->cache_arena = vmp;
    cp->cache_cflags = cflags;

    /*
     * Determine the chunk size.
     */
    chunksize = bufsize;

    if (align >= KMEM_ALIGN) {
        chunksize = P2ROUNDUP(chunksize, KMEM_ALIGN);
        cp->cache_bufctl = chunksize - KMEM_ALIGN;
    }

    if (cp->cache_flags & KMF_BUFTAG) {
        cp->cache_bufctl = chunksize;
        cp->cache_buftag = chunksize;
        if (cp->cache_flags & KMF_LITE)
            chunksize += KMEM_BUFTAG_LITE_SIZE(kmem_lite_count);
        else
            chunksize += sizeof (kmem_buftag_t);
    }

    if (cp->cache_flags & KMF_DEADBEEF) {
        cp->cache_verify = MIN(cp->cache_buftag, kmem_maxverify);
        if (cp->cache_flags & KMF_LITE)
            cp->cache_verify = sizeof (uint64_t);
    }

    cp->cache_contents = MIN(cp->cache_bufctl, kmem_content_maxsave);

    cp->cache_chunksize = chunksize = P2ROUNDUP(chunksize, align);

    /*
     * Now that we know the chunk size, determine the optimal slab size.
     */
    if (vmp == kmem_firewall_arena) {
        cp->cache_slabsize = P2ROUNDUP(chunksize, vmp->vm_quantum);
        cp->cache_mincolor = cp->cache_slabsize - chunksize;
        cp->cache_maxcolor = cp->cache_mincolor;
        cp->cache_flags |= KMF_HASH;
        ASSERT(!(cp->cache_flags & KMF_BUFTAG));
    } else if ((cflags & KMC_NOHASH) || (!(cflags & KMC_NOTOUCH) &&
                                         !(cp->cache_flags & KMF_AUDIT) &&
                                         chunksize < vmp->vm_quantum / KMEM_VOID_FRACTION)) {
        cp->cache_slabsize = vmp->vm_quantum;
        cp->cache_mincolor = 0;
        cp->cache_maxcolor =
        (cp->cache_slabsize - sizeof (kmem_slab_t)) % chunksize;
        ASSERT(chunksize + sizeof (kmem_slab_t) <= cp->cache_slabsize);
        ASSERT(!(cp->cache_flags & KMF_AUDIT));
    } else {
        size_t chunks, bestfit, waste, slabsize;
        size_t minwaste = LONG_MAX;

        for (chunks = 1; chunks <= KMEM_VOID_FRACTION; chunks++) {
            slabsize = P2ROUNDUP(chunksize * chunks,
                                 vmp->vm_quantum);
            chunks = slabsize / chunksize;
            waste = (slabsize % chunksize) / chunks;
            if (waste < minwaste) {
                minwaste = waste;
                bestfit = slabsize;
            }
        }
        if (cflags & KMC_QCACHE)
            bestfit = VMEM_QCACHE_SLABSIZE(vmp->vm_qcache_max);
        cp->cache_slabsize = bestfit;
        cp->cache_mincolor = 0;
        cp->cache_maxcolor = bestfit % chunksize;
        cp->cache_flags |= KMF_HASH;
    }

    cp->cache_maxchunks = (cp->cache_slabsize / cp->cache_chunksize);
    cp->cache_partial_binshift = highbit(cp->cache_maxchunks / 16) + 1;

    /*
     * Disallowing prefill when either the DEBUG or HASH flag is set or when
     * there is a constructor avoids some tricky issues with debug setup
     * that may be revisited later. We cannot allow prefill in a
     * metadata cache because of potential recursion.
     */
    if (vmp == kmem_msb_arena ||
        cp->cache_flags & (KMF_HASH | KMF_BUFTAG) ||
        cp->cache_constructor != NULL)
        cp->cache_flags &= ~KMF_PREFILL;

    if (cp->cache_flags & KMF_HASH) {
        ASSERT(!(cflags & KMC_NOHASH));
        cp->cache_bufctl_cache = (cp->cache_flags & KMF_AUDIT) ?
        kmem_bufctl_audit_cache : kmem_bufctl_cache;
    }

    if (cp->cache_maxcolor >= vmp->vm_quantum)
        cp->cache_maxcolor = vmp->vm_quantum - 1;

    cp->cache_color = cp->cache_mincolor;

    /*
     * Initialize the rest of the slab layer.
     */
    mutex_init(&cp->cache_lock, NULL, MUTEX_DEFAULT, NULL);

    avl_create(&cp->cache_partial_slabs, kmem_partial_slab_cmp,
               sizeof (kmem_slab_t), offsetof(kmem_slab_t, slab_link));
    /* LINTED: E_TRUE_LOGICAL_EXPR */
    ASSERT(sizeof (list_node_t) <= sizeof (avl_node_t));
    /* reuse partial slab AVL linkage for complete slab list linkage */
    list_create(&cp->cache_complete_slabs,
                sizeof (kmem_slab_t), offsetof(kmem_slab_t, slab_link));

    if (cp->cache_flags & KMF_HASH) {
        cp->cache_hash_table = vmem_alloc(kmem_hash_arena,
                                          KMEM_HASH_INITIAL * sizeof (void *), VM_SLEEP);
        bzero(cp->cache_hash_table,
              KMEM_HASH_INITIAL * sizeof (void *));
        cp->cache_hash_mask = KMEM_HASH_INITIAL - 1;
        cp->cache_hash_shift = highbit((ulong_t)chunksize) - 1;
    }

    /*
     * Initialize the depot.
     */
    mutex_init(&cp->cache_depot_lock, NULL, MUTEX_DEFAULT, NULL);

    for (mtp = kmem_magtype; chunksize <= mtp->mt_minbuf; mtp++)
        continue;

    cp->cache_magtype = mtp;

    /*
     * Initialize the CPU layer.
     */
    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
        mutex_init(&ccp->cc_lock, NULL, MUTEX_DEFAULT, NULL); // XNU
        ccp->cc_flags = cp->cache_flags;
        ccp->cc_rounds = -1;
        ccp->cc_prounds = -1;
    }

    /*
     * Create the cache's kstats.
     */
    if ((cp->cache_kstat = kstat_create("unix", 0, cp->cache_name,
                                        "kmem_cache", KSTAT_TYPE_NAMED,
                                        sizeof (kmem_cache_kstat) / sizeof (kstat_named_t),
                                        KSTAT_FLAG_VIRTUAL)) != NULL) {
        cp->cache_kstat->ks_data = &kmem_cache_kstat;
        cp->cache_kstat->ks_update = kmem_cache_kstat_update;
        cp->cache_kstat->ks_private = cp;
        cp->cache_kstat->ks_lock = &kmem_cache_kstat_lock;
        kstat_install(cp->cache_kstat);
    }

    /*
     * Add the cache to the global list.  This makes it visible
     * to kmem_update(), so the cache must be ready for business.
     */
    mutex_enter(&kmem_cache_lock);
    list_insert_tail(&kmem_caches, cp);
    mutex_exit(&kmem_cache_lock);

    if (kmem_ready)
        kmem_cache_magazine_enable(cp);

    return (cp);
}

static int
kmem_move_cmp(const void *buf, const void *p)
{
    const kmem_move_t *kmm = p;
    uintptr_t v1 = (uintptr_t)buf;
    uintptr_t v2 = (uintptr_t)kmm->kmm_from_buf;
    return (v1 < v2 ? -1 : (v1 > v2 ? 1 : 0));
}

static void
kmem_reset_reclaim_threshold(kmem_defrag_t *kmd)
{
    kmd->kmd_reclaim_numer = 1;
}

/*
 * Initially, when choosing candidate slabs for buffers to move, we want to be
 * very selective and take only slabs that are less than
 * (1 / KMEM_VOID_FRACTION) allocated. If we have difficulty finding candidate
 * slabs, then we raise the allocation ceiling incrementally. The reclaim
 * threshold is reset to (1 / KMEM_VOID_FRACTION) as soon as the cache is no
 * longer fragmented.
 */
static void
kmem_adjust_reclaim_threshold(kmem_defrag_t *kmd, int direction)
{
    if (direction > 0) {
        /* make it easier to find a candidate slab */
        if (kmd->kmd_reclaim_numer < (KMEM_VOID_FRACTION - 1)) {
            kmd->kmd_reclaim_numer++;
        }
    } else {
        /* be more selective */
        if (kmd->kmd_reclaim_numer > 1) {
            kmd->kmd_reclaim_numer--;
        }
    }
}

void
kmem_cache_set_move(kmem_cache_t *cp,
                    kmem_cbrc_t (*move)(void *, void *, size_t, void *))
{
    kmem_defrag_t *defrag;

    ASSERT(move != NULL);
    /*
     * The consolidator does not support NOTOUCH caches because kmem cannot
     * initialize their slabs with the 0xbaddcafe memory pattern, which sets
     * a low order bit usable by clients to distinguish uninitialized memory
     * from known objects (see kmem_slab_create).
     */
    ASSERT(!(cp->cache_cflags & KMC_NOTOUCH));
    ASSERT(!(cp->cache_cflags & KMC_IDENTIFIER));

    /*
     * We should not be holding anyone's cache lock when calling
     * kmem_cache_alloc(), so allocate in all cases before acquiring the
     * lock.
     */
    defrag = kmem_cache_alloc(kmem_defrag_cache, KM_SLEEP);

    mutex_enter(&cp->cache_lock);

    if (KMEM_IS_MOVABLE(cp)) {
        if (cp->cache_move == NULL) {
            ASSERT(cp->cache_slab_alloc == 0);

            cp->cache_defrag = defrag;
            defrag = NULL; /* nothing to free */
            bzero(cp->cache_defrag, sizeof (kmem_defrag_t));
            avl_create(&cp->cache_defrag->kmd_moves_pending,
                       kmem_move_cmp, sizeof (kmem_move_t),
                       offsetof(kmem_move_t, kmm_entry));
            /* LINTED: E_TRUE_LOGICAL_EXPR */
            ASSERT(sizeof (list_node_t) <= sizeof (avl_node_t));
            /* reuse the slab's AVL linkage for deadlist linkage */
            list_create(&cp->cache_defrag->kmd_deadlist,
                        sizeof (kmem_slab_t),
                        offsetof(kmem_slab_t, slab_link));
            kmem_reset_reclaim_threshold(cp->cache_defrag);
        }
        cp->cache_move = move;
    }

    mutex_exit(&cp->cache_lock);

    if (defrag != NULL) {
        kmem_cache_free(kmem_defrag_cache, defrag); /* unused */
    }
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
    int cpu_seqid;

    /*
     * Remove the cache from the global cache list so that no one else
     * can schedule tasks on its behalf, wait for any pending tasks to
     * complete, purge the cache, and then destroy it.
     */
    mutex_enter(&kmem_cache_lock);
    list_remove(&kmem_caches, cp);
    mutex_exit(&kmem_cache_lock);

    if (kmem_taskq != NULL)
        taskq_wait(kmem_taskq);
    if (kmem_move_taskq != NULL)
        taskq_wait(kmem_move_taskq);

    kmem_cache_magazine_purge(cp);

    mutex_enter(&cp->cache_lock);

    if (cp->cache_buftotal != 0)
        cmn_err(CE_WARN, "kmem_cache_destroy: '%s' (%p) not empty",
                cp->cache_name, (void *)cp);
    if (cp->cache_defrag != NULL) {
        avl_destroy(&cp->cache_defrag->kmd_moves_pending);
        list_destroy(&cp->cache_defrag->kmd_deadlist);
        kmem_cache_free(kmem_defrag_cache, cp->cache_defrag);
        cp->cache_defrag = NULL;
    }
    /*
     * The cache is now dead.  There should be no further activity.  We
     * enforce this by setting land mines in the constructor, destructor,
     * reclaim, and move routines that induce a kernel text fault if
     * invoked.
     */
    cp->cache_constructor = (int (*)(void *, void *, int))1;
    cp->cache_destructor = (void (*)(void *, void *))2;
    cp->cache_reclaim = (void (*)(void *))3;
    cp->cache_move = (kmem_cbrc_t (*)(void *, void *, size_t, void *))4;
    mutex_exit(&cp->cache_lock);

    kstat_delete(cp->cache_kstat);

    if (cp->cache_hash_table != NULL)
        vmem_free(kmem_hash_arena, cp->cache_hash_table,
                  (cp->cache_hash_mask + 1) * sizeof (void *));

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++)
        mutex_destroy(&cp->cache_cpu[cpu_seqid].cc_lock);     // XNU

    mutex_destroy(&cp->cache_depot_lock);
    mutex_destroy(&cp->cache_lock);

    vmem_free(kmem_cache_arena, cp, KMEM_CACHE_SIZE(max_ncpus));
}

/*ARGSUSED*/
#ifndef APPLE
//static int
//kmem_cpu_setup(cpu_setup_t what, int id, void *arg)
//{
//    ASSERT(MUTEX_HELD(&cpu_lock));
//    if (what == CPU_UNCONFIG) {
//        kmem_cache_applyall(kmem_cache_magazine_purge,
//                            kmem_taskq, TQ_SLEEP);
//        kmem_cache_applyall(kmem_cache_magazine_enable,
//                            kmem_taskq, TQ_SLEEP);
//    }
//    return (0);
//}
#endif

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
        ASSERT(P2PHASE(cache_size, table_unit) == 0);

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
    int i;
    size_t maxbuf;
    kmem_magtype_t *mtp;

    for (i = 0; i < sizeof (kmem_magtype) / sizeof (*mtp); i++) {
        char name[KMEM_CACHE_NAMELEN + 1];

        mtp = &kmem_magtype[i];
        (void) snprintf(name, KMEM_CACHE_NAMELEN, "kmem_magazine_%d", mtp->mt_magsize);
        mtp->mt_cache = kmem_cache_create(name,
                                          (mtp->mt_magsize + 1) * sizeof (void *),
                                          mtp->mt_align, NULL, NULL, NULL, NULL,
                                          kmem_msb_arena, KMC_NOHASH);
    }

    kmem_slab_cache = kmem_cache_create("kmem_slab_cache",
                                        sizeof (kmem_slab_t), 0, NULL, NULL, NULL, NULL,
                                        kmem_msb_arena, KMC_NOHASH);

    kmem_bufctl_cache = kmem_cache_create("kmem_bufctl_cache",
                                          sizeof (kmem_bufctl_t), 0, NULL, NULL, NULL, NULL,
                                          kmem_msb_arena, KMC_NOHASH);

    kmem_bufctl_audit_cache = kmem_cache_create("kmem_bufctl_audit_cache",
                                                sizeof (kmem_bufctl_audit_t), 0, NULL, NULL, NULL, NULL,
                                                kmem_msb_arena, KMC_NOHASH);

    if (pass == 2) {
        kmem_va_arena = vmem_create("kmem_va",
                                    NULL, 0, KMEM_QUANTUM,
                                    vmem_alloc, vmem_free, heap_arena,
                                    8 * KMEM_QUANTUM, VM_SLEEP);

//        if (use_large_pages) {
//            kmem_default_arena = vmem_xcreate("kmem_default",
//                                              NULL, 0, PAGESIZE,
//                                              segkmem_alloc_lp, segkmem_free_lp, kmem_va_arena,
//                                              0, VMC_DUMPSAFE | VM_SLEEP);
//        } else {
            kmem_default_arena = vmem_create("kmem_default",
                                             NULL, 0, KMEM_QUANTUM,
                                             segkmem_alloc, segkmem_free, kmem_va_arena,
                                             0, VMC_DUMPSAFE | VM_SLEEP);
//        }

        /* Figure out what our maximum cache size is */
        maxbuf = kmem_max_cached;
        if (maxbuf <= KMEM_MAXBUF) {
            maxbuf = 0;
            kmem_max_cached = KMEM_MAXBUF;
        } else {
            size_t size = 0;
            size_t max =
            sizeof (kmem_big_alloc_sizes) / sizeof (int);
            /*
             * Round maxbuf up to an existing cache size.  If maxbuf
             * is larger than the largest cache, we truncate it to
             * the largest cache's size.
             */
            for (i = 0; i < max; i++) {
                size = kmem_big_alloc_sizes[i];
                if (maxbuf <= size)
                    break;
            }
            kmem_max_cached = maxbuf = size;
        }

        /*
         * The big alloc table may not be completely overwritten, so
         * we clear out any stale cache pointers from the first pass.
         */
        bzero(kmem_big_alloc_table, sizeof (kmem_big_alloc_table));
    } else {
        /*
         * During the first pass, the kmem_alloc_* caches
         * are treated as metadata.
         */
        kmem_default_arena = kmem_msb_arena;
        maxbuf = KMEM_BIG_MAXBUF_32BIT;
    }

    /*
     * Set up the default caches to back kmem_alloc()
     */
    kmem_alloc_caches_create(
                             kmem_alloc_sizes, sizeof (kmem_alloc_sizes) / sizeof (int),
                             kmem_alloc_table, KMEM_MAXBUF, KMEM_ALIGN_SHIFT);

    kmem_alloc_caches_create(
                             kmem_big_alloc_sizes, sizeof (kmem_big_alloc_sizes) / sizeof (int),
                             kmem_big_alloc_table, maxbuf, KMEM_BIG_SHIFT);

    kmem_big_alloc_table_max = maxbuf >> KMEM_BIG_SHIFT;
}



struct free_slab {
	vmem_t *vmp;
	size_t slabsize;
	void *slab;
	list_node_t next;
};

static list_t freelist;


void kmem_cache_build_slablist(kmem_cache_t *cp)
{
	int cpu_seqid;

    vmem_t *vmp = cp->cache_arena;
    kmem_slab_t *sp;
	struct free_slab *fs;

    for (sp = list_head(&cp->cache_complete_slabs); sp != NULL;
         sp = list_next(&cp->cache_complete_slabs, sp)) {

		MALLOC(fs, struct free_slab *, sizeof(struct free_slab), M_TEMP, M_WAITOK);
		fs->vmp = vmp;
		fs->slabsize = cp->cache_slabsize;
		fs->slab = (void *)P2ALIGN((uintptr_t)sp->slab_base, vmp->vm_quantum);
		list_link_init(&fs->next);
		list_insert_tail(&freelist, fs);

    }

    for (sp = avl_first(&cp->cache_partial_slabs); sp != NULL;
         sp = AVL_NEXT(&cp->cache_partial_slabs, sp)) {

		MALLOC(fs, struct free_slab *, sizeof(struct free_slab), M_TEMP, M_WAITOK);
		fs->vmp = vmp;
		fs->slabsize = cp->cache_slabsize;
		fs->slab = (void *)P2ALIGN((uintptr_t)sp->slab_base, vmp->vm_quantum);
		list_link_init(&fs->next);
		list_insert_tail(&freelist, fs);

    }


    kstat_delete(cp->cache_kstat);

    if (cp->cache_hash_table != NULL)
        vmem_free(kmem_hash_arena, cp->cache_hash_table,
                  (cp->cache_hash_mask + 1) * sizeof (void *));

    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++)
        mutex_destroy(&cp->cache_cpu[cpu_seqid].cc_lock);     // XNU

    mutex_destroy(&cp->cache_depot_lock);
    mutex_destroy(&cp->cache_lock);

    vmem_free(kmem_cache_arena, cp, KMEM_CACHE_SIZE(max_ncpus));

}


static void
kmem_cache_fini(int pass, int use_large_pages)
{
	kmem_cache_t *cp;
	int i;
	struct free_slab *fs;

	list_create(&freelist, sizeof (struct free_slab),
				offsetof(struct free_slab, next));

    mutex_enter(&kmem_cache_lock);
	// lund


	while((cp = list_head(&kmem_caches))) {
			list_remove(&kmem_caches, cp);
			mutex_exit(&kmem_cache_lock);
			kmem_cache_build_slablist(cp);
			mutex_enter(&kmem_cache_lock);
	}

	mutex_exit(&kmem_cache_lock);


	//printf("Releasing slabs\n");
	i = 0;
	while((fs = list_head(&freelist))) {
		i++;
		list_remove(&freelist, fs);
		vmem_free(fs->vmp, fs->slab, fs->slabsize);
		FREE(fs, M_TEMP);

	}
	printf("SPL: Released %u slabs\n", i);
	list_destroy(&freelist);

	if (pass == 2) {
		vmem_destroy(kmem_default_arena);
		vmem_destroy(kmem_va_arena);
	}
}

static void memory_monitor_thread()
{
	kern_return_t kr;
	unsigned int nsecs_monitored = 1000000000 / 4;
	unsigned int pages_reclaimed = 0;
	unsigned int os_num_pages_wanted = 0;
	uint64_t last_reap = zfs_lbolt();

	while (!shutting_down) {

		delay(hz);
		kr = mach_vm_pressure_monitor(TRUE, nsecs_monitored,
									  &pages_reclaimed, &os_num_pages_wanted);

		spl_stats.spl_monitor_thread_wake_count.value.ui64++;

		if ((!shutting_down) && kr == KERN_SUCCESS) {

            // My original intent was to execute the reap synchronously
            // to limit the rate at which this thread spins. Turns out
            // that kmem_reap() has a semaphoring mechanism that prevents
            // concurrent reap activity.
            //
            // So we will let that mechanism work as I suspect its part of
            // kmems locking strategy.
			uint64_t newtarget;
			newtarget = kmem_used() -
				(os_num_pages_wanted * PAGESIZE * MULT);

			if (!pressure_bytes_target || (newtarget < pressure_bytes_target)) {
				pressure_bytes_target = newtarget;
				//printf("pressure: new target %llu\n", newtarget);
			}

			// Figure out if we should reap as well
			if (zfs_lbolt() - last_reap >= (hz * 60)) {
				last_reap = zfs_lbolt();
#if 0
				extern unsigned int memorystatus_level;
				printf("memorystatus_level %u\n", memorystatus_level);


				if (memorystatus_level < 30) {
					printf("SPL: memorystatus_level low, reaping\n");
					kmem_reap();
					kpreempt(KPREEMPT_SYNC);
					kmem_reap_idspace();
					printf("SPL: reaping complete.\n");

				}
#endif
			}


		} else {
			delay(hz/10);
		}
	}

	shutting_down = 2;
	thread_exit();
}

static int
spl_kstat_update(kstat_t *ksp, int rw)
{
	spl_stats_t *ks = ksp->ks_data;

	if (rw == KSTAT_WRITE) {

		if (ks->spl_simulate_pressure.value.ui64) {
			pressure_bytes_target = kmem_used() -
				(ks->spl_simulate_pressure.value.ui64 * 1024 * 1024);
			kmem_reap();
			kmem_reap_idspace();
		}
	} else {
		ks->spl_os_alloc.value.ui64 = segkmem_total_mem_allocated;
		ks->spl_active_threads.value.ui64 = zfs_threads;
		ks->spl_active_mutex.value.ui64 = zfs_active_mutex;
		ks->spl_active_rwlock.value.ui64 = zfs_active_rwlock;
		ks->spl_simulate_pressure.value.ui64 = 0;
	}

	return (0);
}

void
spl_kmem_init(uint64_t total_memory)
{
    //kmem_cache_t *cp;
    int old_kmem_flags = kmem_flags;
    int use_large_pages = 0;
    size_t maxverify, minfirewall;

    printf("SPL: Total memory %llu\n", total_memory);

	sysctl_register_oid(&sysctl__spl);
	sysctl_register_oid(&sysctl__spl_kext_version);

	// Initialise the kstat lock
	mutex_init(&kmem_cache_lock, "kmem_cache_lock", MUTEX_DEFAULT, NULL); // XNU
	mutex_init(&kmem_flags_lock, "kmem_flags_lock", MUTEX_DEFAULT, NULL); // XNU
	mutex_init(&kmem_cache_kstat_lock, "kmem_kstat_lock", MUTEX_DEFAULT, NULL); // XNU

    spl_kstat_init();


    /*
     * Small-memory systems (< 24 MB) can't handle kmem_flags overhead.
     */
    if (physmem < btop(24 << 20) && !(old_kmem_flags & KMF_STICKY))
        kmem_flags = 0;

    /*
     * Don't do firewalled allocations if the heap is less than 1TB
     * (i.e. on a 32-bit kernel)
     * The resulting VM_NEXTFIT allocations would create too much
     * fragmentation in a small heap.
     */
    maxverify = minfirewall = PAGESIZE / 2;


    /* LINTED */
    ASSERT(sizeof (kmem_cpu_cache_t) == KMEM_CPU_CACHE_SIZE);

    list_create(&kmem_caches, sizeof (kmem_cache_t),
                offsetof(kmem_cache_t, cache_link));

	// Initialise seg_kmem, only the first two parameters are valid for us.
	kernelheap_init((void*)((virtual_space_start + KMEM_QUANTUM)&~(KMEM_QUANTUM-1)),
					(void*)((virtual_space_end - KMEM_QUANTUM)&~(KMEM_QUANTUM-1)),
					0, 0, 0);

    kmem_metadata_arena = vmem_create("kmem_metadata", NULL, 0, KMEM_QUANTUM,
                                      vmem_alloc, vmem_free, heap_arena, 8 * KMEM_QUANTUM,
                                      VM_SLEEP | VMC_NO_QCACHE);

    kmem_msb_arena = vmem_create("kmem_msb", NULL, 0,
                                 KMEM_QUANTUM, segkmem_alloc, segkmem_free, kmem_metadata_arena, 0,
                                 VMC_DUMPSAFE | VM_SLEEP);

    kmem_cache_arena = vmem_create("kmem_cache", NULL, 0, KMEM_ALIGN,
                                   segkmem_alloc, segkmem_free, kmem_metadata_arena, 0, VM_SLEEP);

    kmem_hash_arena = vmem_create("kmem_hash", NULL, 0, KMEM_ALIGN,
                                  segkmem_alloc, segkmem_free, kmem_metadata_arena, 0, VM_SLEEP);

    kmem_log_arena = vmem_create("kmem_log", NULL, 0, KMEM_ALIGN,
                                 segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

	segkmem_zio_init((void*)((virtual_space_start + KMEM_QUANTUM)&~(KMEM_QUANTUM-1)),
					 (void*)((virtual_space_end - KMEM_QUANTUM)&~(KMEM_QUANTUM-1)));

#ifndef APPLE
//    kmem_firewall_va_arena = vmem_create("kmem_firewall_va",
//                                         NULL, 0, PAGESIZE,
//                                         kmem_firewall_va_alloc, kmem_firewall_va_free, heap_arena,
//                                         0, VM_SLEEP);
//
//    kmem_firewall_arena = vmem_create("kmem_firewall", NULL, 0, PAGESIZE,
//                                      segkmem_alloc, segkmem_free, kmem_firewall_va_arena, 0,
//                                      VMC_DUMPSAFE | VM_SLEEP);
#endif

    /* temporary oversize arena for mod_read_system_file */
    kmem_oversize_arena = vmem_create("kmem_oversize", NULL, 0, KMEM_QUANTUM,
                                      segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

    // statically declared above kmem_reap_interval = 15 * hz;

    /*
     * Read /etc/system.  This is a chicken-and-egg problem because
     * kmem_flags may be set in /etc/system, but mod_read_system_file()
     * needs to use the allocator.  The simplest solution is to create
     * all the standard kmem caches, read /etc/system, destroy all the
     * caches we just created, and then create them all again in light
     * of the (possibly) new kmem_flags and other kmem tunables.
     */

#ifndef APPLE
//    kmem_cache_init(1, 0);
//
//    mod_read_system_file(boothowto & RB_ASKNAME);
//
//    while ((cp = list_tail(&kmem_caches)) != NULL)
//        kmem_cache_destroy(cp);
//
//    vmem_destroy(kmem_oversize_arena);
#endif
    if (old_kmem_flags & KMF_STICKY)
        kmem_flags = old_kmem_flags;

    if (!(kmem_flags & KMF_AUDIT))
        vmem_seg_size = offsetof(vmem_seg_t, vs_thread);

    if (kmem_maxverify == 0)
        kmem_maxverify = maxverify;

    if (kmem_minfirewall == 0)
        kmem_minfirewall = minfirewall;

    /*
     * give segkmem a chance to figure out if we are using large pages
     * for the kernel heap
     */
//    use_large_pages = segkmem_lpsetup();
	use_large_pages = 0;

    /*
     * To protect against corruption, we keep the actual number of callers
     * KMF_LITE records seperate from the tunable.  We arbitrarily clamp
     * to 16, since the overhead for small buffers quickly gets out of
     * hand.
     *
     * The real limit would depend on the needs of the largest KMC_NOHASH
     * cache.
     */
    kmem_lite_count = MIN(MAX(0, kmem_lite_pcs), 16);
    kmem_lite_pcs = kmem_lite_count;

    /*
     * Normally, we firewall oversized allocations when possible, but
     * if we are using large pages for kernel memory, and we don't have
     * any non-LITE debugging flags set, we want to allocate oversized
     * buffers from large pages, and so skip the firewalling.
     */
//    if (use_large_pages &&
//        ((kmem_flags & KMF_LITE) || !(kmem_flags & KMF_DEBUG))) {
//        kmem_oversize_arena = vmem_xcreate("kmem_oversize", NULL, 0,
//                                           PAGESIZE, segkmem_alloc_lp, segkmem_free_lp, heap_arena,
//                                            0, VMC_DUMPSAFE | VM_SLEEP);
//    } else {
#if 0
        kmem_oversize_arena = vmem_create("kmem_oversize",
                                          NULL, 0, KMEM_QUANTUM,
                                          segkmem_alloc, segkmem_free,
//										  kmem_minfirewall < ULONG_MAX?
//                                          kmem_firewall_va_arena : heap_arena,
										  heap_arena,
										  0, VMC_DUMPSAFE |
                                          VM_SLEEP);
#endif
//    }

    kmem_cache_init(2, use_large_pages);

    if (kmem_flags & (KMF_AUDIT | KMF_RANDOMIZE)) {
        if (kmem_transaction_log_size == 0)
            kmem_transaction_log_size = kmem_maxavail() / 50;
        kmem_transaction_log = kmem_log_init(kmem_transaction_log_size);
    }

    if (kmem_flags & (KMF_CONTENTS | KMF_RANDOMIZE)) {
        if (kmem_content_log_size == 0)
            kmem_content_log_size = kmem_maxavail() / 50;
        kmem_content_log = kmem_log_init(kmem_content_log_size);
    }

    kmem_failure_log = kmem_log_init(kmem_failure_log_size);

    kmem_slab_log = kmem_log_init(kmem_slab_log_size);

#ifndef APPLE
//	/*
//     * Initialize STREAMS message caches so allocb() is available.
//     * This allows us to initialize the logging framework (cmn_err(9F),
//     * strlog(9F), etc) so we can start recording messages.
//     */
//    streams_msg_init();
//
//    /*
//     * Initialize the ZSD framework in Zones so modules loaded henceforth
//     * can register their callbacks.
//     */
//    zone_zsd_init();
//    log_init();
#endif
	spl_tsd_init();
	spl_rwlock_init();
	spl_taskq_init();

    /*
     * Warn about invalid or dangerous values of kmem_flags.
     * Always warn about unsupported values.
     */
    if (((kmem_flags & ~(KMF_AUDIT | KMF_DEADBEEF | KMF_REDZONE |
                         KMF_CONTENTS | KMF_LITE)) != 0) ||
        ((kmem_flags & KMF_LITE) && kmem_flags != KMF_LITE))
        cmn_err(CE_WARN, "kmem_flags set to unsupported value 0x%x. "
                "See the Solaris Tunable Parameters Reference Manual.",
                kmem_flags);

#ifdef DEBUG
    if ((kmem_flags & KMF_DEBUG) == 0)
        cmn_err(CE_NOTE, "kmem debugging disabled.");
#else
    /*
     * For non-debug kernels, the only "normal" flags are 0, KMF_LITE,
     * KMF_REDZONE, and KMF_CONTENTS (the last because it is only enabled
     * if KMF_AUDIT is set). We should warn the user about the performance
     * penalty of KMF_AUDIT or KMF_DEADBEEF if they are set and KMF_LITE
     * isn't set (since that disables AUDIT).
     */
    if (!(kmem_flags & KMF_LITE) &&
        (kmem_flags & (KMF_AUDIT | KMF_DEADBEEF)) != 0)
        cmn_err(CE_WARN, "High-overhead kmem debugging features "
                "enabled (kmem_flags = 0x%x).  Performance degradation "
                "and large memory overhead possible. See the Solaris "
                "Tunable Parameters Reference Manual.", kmem_flags);
#endif /* not DEBUG */

    kmem_cache_applyall(kmem_cache_magazine_enable, NULL, TQ_SLEEP);

    kmem_ready = 1;

	// Install spl kstats
	spl_ksp = kstat_create("spl", 0, "spl_misc", "misc", KSTAT_TYPE_NAMED,
							   sizeof (spl_stats) / sizeof (kstat_named_t),
						   KSTAT_FLAG_VIRTUAL|KSTAT_FLAG_WRITABLE);

	if (spl_ksp != NULL) {
		spl_ksp->ks_data = &spl_stats;
		spl_ksp->ks_update = spl_kstat_update;
		kstat_install(spl_ksp);
	}

    /*
     * Initialize the platform-specific aligned/DMA memory allocator.
     */
//    ka_init();

    /*
     * Initialize 32-bit ID cache.
     */
//    id32_init();

    /*
     * Initialize the networking stack so modules loaded can
     * register their callbacks.
     */
//    netstack_init();
}

void
spl_kmem_fini(void)
{
	sysctl_unregister_oid(&sysctl__spl_kext_version);
	sysctl_unregister_oid(&sysctl__spl);

    kmem_cache_applyall(kmem_cache_magazine_disable, NULL, TQ_SLEEP);

	kstat_delete(spl_ksp);

	kmem_log_fini(kmem_slab_log);
    kmem_log_fini(kmem_failure_log);

    if (kmem_flags & (KMF_CONTENTS | KMF_RANDOMIZE)) {
        if (kmem_content_log_size == 0)
            kmem_content_log_size = kmem_maxavail() / 50;
        kmem_log_fini(kmem_content_log);
    }

    if (kmem_flags & (KMF_AUDIT | KMF_RANDOMIZE)) {
        if (kmem_transaction_log_size == 0)
            kmem_transaction_log_size = kmem_maxavail() / 50;
		kmem_log_fini(kmem_transaction_log);
    }

	kmem_cache_fini(2, /*use_large_pages*/ 0);

	vmem_destroy(kmem_oversize_arena);

	segkmem_zio_fini();

	vmem_destroy(kmem_log_arena);
	vmem_destroy(kmem_hash_arena);
	vmem_destroy(kmem_cache_arena);
	vmem_destroy(kmem_msb_arena);
	vmem_destroy(kmem_metadata_arena);

	kernelheap_fini();

	list_destroy(&kmem_caches);
#if 0
	mutex_destroy(&kmem_cache_kstat_lock);
	mutex_destroy(&kmem_flags_lock);
	mutex_destroy(&kmem_cache_lock);
#endif

}

static void
kmem_move_init(void)
{
    kmem_defrag_cache = kmem_cache_create("kmem_defrag_cache",
                                          sizeof (kmem_defrag_t), 0, NULL, NULL, NULL, NULL,
                                          kmem_msb_arena, KMC_NOHASH);
    kmem_move_cache = kmem_cache_create("kmem_move_cache",
                                        sizeof (kmem_move_t), 0, NULL, NULL, NULL, NULL,
                                        kmem_msb_arena, KMC_NOHASH);

    /*
     * kmem guarantees that move callbacks are sequential and that even
     * across multiple caches no two moves ever execute simultaneously.
     * Move callbacks are processed on a separate taskq so that client code
     * does not interfere with internal maintenance tasks.
     */
    kmem_move_taskq = taskq_create("kmem_move_taskq", 1,
                                            minclsyspri, 100, INT_MAX, TASKQ_PREPOPULATE);
}

void kmem_move_fini(void)
{

	taskq_wait(kmem_move_taskq);
	taskq_destroy(kmem_move_taskq);
	kmem_move_taskq = 0;

	kmem_cache_destroy(kmem_move_cache);
	kmem_cache_destroy(kmem_defrag_cache);

}

void
spl_kmem_thread_init(void)
{
    kmem_move_init();
    kmem_taskq = taskq_create("kmem_taskq", 1, minclsyspri,
                                       300, INT_MAX, TASKQ_PREPOPULATE);
	(void)thread_create(NULL, 0, memory_monitor_thread, 0, 0, 0, 0, 0);
}

void
spl_kmem_thread_fini(void)
{
	shutting_down = 1;

	// FIXME - might have to put a flush-through task into the task q
	// in here somewhere to ensure that all tasks are dead during
	// shutdown.

	printf("SPL: stop memory monitor\n");
	thread_wakeup((event_t) &vm_page_free_wanted);

	printf("SPL: bsd_untimeout\n");
	bsd_untimeout(kmem_update,  0);
	bsd_untimeout(kmem_reap_timeout, &kmem_reaping);

	printf("SPL: wait for taskqs to empty\n");
	taskq_wait(kmem_taskq);

	printf("SPL: destroy taskq\n");
	taskq_destroy(kmem_taskq);
	kmem_taskq = 0;

	// Find a better way to wait for memory_monitor_thread to quit.
	while(shutting_down != 2) delay(hz>>4);

	// FIXME - maybe it should tear down for symmetry
	kmem_move_fini();

}

void
spl_kmem_mp_init(void)
{
#ifndef APPLE
//	mutex_enter(&cpu_lock);
//    register_cpu_setup_func(kmem_cpu_setup, NULL);
//    mutex_exit(&cpu_lock);
#endif

    kmem_update_timeout(NULL);

#ifndef APPLE
//	taskq_mp_init();
#endif
}

/*
 * Return the slab of the allocated buffer, or NULL if the buffer is not
 * allocated. This function may be called with a known slab address to determine
 * whether or not the buffer is allocated, or with a NULL slab address to obtain
 * an allocated buffer's slab.
 */
static kmem_slab_t *
kmem_slab_allocated(kmem_cache_t *cp, kmem_slab_t *sp, void *buf)
{
    kmem_bufctl_t *bcp, *bufbcp;

    ASSERT(MUTEX_HELD(&cp->cache_lock));
    ASSERT(sp == NULL || KMEM_SLAB_MEMBER(sp, buf));

    if (cp->cache_flags & KMF_HASH) {
        for (bcp = *KMEM_HASH(cp, buf);
             (bcp != NULL) && (bcp->bc_addr != buf);
             bcp = bcp->bc_next) {
            continue;
        }
        ASSERT(sp != NULL && bcp != NULL ? sp == bcp->bc_slab : 1);
        return (bcp == NULL ? NULL : bcp->bc_slab);
    }

    if (sp == NULL) {
        sp = KMEM_SLAB(cp, buf);
    }
    bufbcp = KMEM_BUFCTL(cp, buf);
    for (bcp = sp->slab_head;
         (bcp != NULL) && (bcp != bufbcp);
         bcp = bcp->bc_next) {
        continue;
    }
    return (bcp == NULL ? sp : NULL);
}

static boolean_t
kmem_slab_is_reclaimable(kmem_cache_t *cp, kmem_slab_t *sp, int flags)
{
    long refcnt = sp->slab_refcnt;

    ASSERT(cp->cache_defrag != NULL);

    /*
     * For code coverage we want to be able to move an object within the
     * same slab (the only partial slab) even if allocating the destination
     * buffer resulted in a completely allocated slab.
     */
    if (flags & KMM_DEBUG) {
        return ((flags & KMM_DESPERATE) ||
                ((sp->slab_flags & KMEM_SLAB_NOMOVE) == 0));
    }

    /* If we're desperate, we don't care if the client said NO. */
    if (flags & KMM_DESPERATE) {
        return (refcnt < sp->slab_chunks); /* any partial */
    }

    if (sp->slab_flags & KMEM_SLAB_NOMOVE) {
        return (B_FALSE);
    }

    if ((refcnt == 1) || kmem_move_any_partial) {
        return (refcnt < sp->slab_chunks);
    }

    /*
     * The reclaim threshold is adjusted at each kmem_cache_scan() so that
     * slabs with a progressively higher percentage of used buffers can be
     * reclaimed until the cache as a whole is no longer fragmented.
     *
     *	sp->slab_refcnt   kmd_reclaim_numer
     *	--------------- < ------------------
     *	sp->slab_chunks   KMEM_VOID_FRACTION
     */
    return ((refcnt * KMEM_VOID_FRACTION) <
            (sp->slab_chunks * cp->cache_defrag->kmd_reclaim_numer));
}

static void *
kmem_hunt_mag(kmem_cache_t *cp, kmem_magazine_t *m, int n, void *buf,
              void *tbuf)
{
    int i;		/* magazine round index */

    for (i = 0; i < n; i++) {
        if (buf == m->mag_round[i]) {
            if (cp->cache_flags & KMF_BUFTAG) {
                (void) kmem_cache_free_debug(cp, tbuf,
                                             caller());
            }
            m->mag_round[i] = tbuf;
            return (buf);
        }
    }

    return (NULL);
}

/*
 * Hunt the magazine layer for the given buffer. If found, the buffer is
 * removed from the magazine layer and returned, otherwise NULL is returned.
 * The state of the returned buffer is freed and constructed.
 */
static void *
kmem_hunt_mags(kmem_cache_t *cp, void *buf)
{
    kmem_cpu_cache_t *ccp;
    kmem_magazine_t	*m;
    int cpu_seqid;
    int n;		/* magazine rounds */
    void *tbuf;	/* temporary swap buffer */

    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));

    /*
     * Allocated a buffer to swap with the one we hope to pull out of a
     * magazine when found.
     */
    tbuf = kmem_cache_alloc(cp, KM_NOSLEEP);
    if (tbuf == NULL) {
        KMEM_STAT_ADD(kmem_move_stats.kms_hunt_alloc_fail);
        return (NULL);
    }
    if (tbuf == buf) {
        KMEM_STAT_ADD(kmem_move_stats.kms_hunt_lucky);
        if (cp->cache_flags & KMF_BUFTAG) {
            (void) kmem_cache_free_debug(cp, buf, caller());
        }
        return (buf);
    }

    /* Hunt the depot. */
    mutex_enter(&cp->cache_depot_lock);
    n = cp->cache_magtype->mt_magsize;
    for (m = cp->cache_full.ml_list; m != NULL; m = m->mag_next) {
        if (kmem_hunt_mag(cp, m, n, buf, tbuf) != NULL) {
            mutex_exit(&cp->cache_depot_lock);
            return (buf);
        }
    }
    mutex_exit(&cp->cache_depot_lock);

    /* Hunt the per-CPU magazines. */
    for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
        ccp = &cp->cache_cpu[cpu_seqid];

        mutex_enter(&ccp->cc_lock);
        m = ccp->cc_loaded;
        n = ccp->cc_rounds;
        if (kmem_hunt_mag(cp, m, n, buf, tbuf) != NULL) {
            mutex_exit(&ccp->cc_lock);
            return (buf);
        }
        m = ccp->cc_ploaded;
        n = ccp->cc_prounds;
        if (kmem_hunt_mag(cp, m, n, buf, tbuf) != NULL) {
            mutex_exit(&ccp->cc_lock);
            return (buf);
        }
        mutex_exit(&ccp->cc_lock);
    }

    kmem_cache_free(cp, tbuf);
    return (NULL);
}

/*
 * May be called from the kmem_move_taskq, from kmem_cache_move_notify_task(),
 * or when the buffer is freed.
 */
static void
kmem_slab_move_yes(kmem_cache_t *cp, kmem_slab_t *sp, void *from_buf)
{
    ASSERT(MUTEX_HELD(&cp->cache_lock));
    ASSERT(KMEM_SLAB_MEMBER(sp, from_buf));

    if (!KMEM_SLAB_IS_PARTIAL(sp)) {
        return;
    }

    if (sp->slab_flags & KMEM_SLAB_NOMOVE) {
        if (KMEM_SLAB_OFFSET(sp, from_buf) == sp->slab_stuck_offset) {
            avl_remove(&cp->cache_partial_slabs, sp);
            sp->slab_flags &= ~KMEM_SLAB_NOMOVE;
            sp->slab_stuck_offset = (uint32_t)-1;
            avl_add(&cp->cache_partial_slabs, sp);
        }
    } else {
        sp->slab_later_count = 0;
        sp->slab_stuck_offset = (uint32_t)-1;
    }
}

static void
kmem_slab_move_no(kmem_cache_t *cp, kmem_slab_t *sp, void *from_buf)
{
    ASSERT(taskq_member(kmem_move_taskq, curthread));
    ASSERT(MUTEX_HELD(&cp->cache_lock));
    ASSERT(KMEM_SLAB_MEMBER(sp, from_buf));

    if (!KMEM_SLAB_IS_PARTIAL(sp)) {
        return;
    }

    avl_remove(&cp->cache_partial_slabs, sp);
    sp->slab_later_count = 0;
    sp->slab_flags |= KMEM_SLAB_NOMOVE;
    sp->slab_stuck_offset = KMEM_SLAB_OFFSET(sp, from_buf);
    avl_add(&cp->cache_partial_slabs, sp);
}

static void kmem_move_end(kmem_cache_t *, kmem_move_t *);

/*
 * The move callback takes two buffer addresses, the buffer to be moved, and a
 * newly allocated and constructed buffer selected by kmem as the destination.
 * It also takes the size of the buffer and an optional user argument specified
 * at cache creation time. kmem guarantees that the buffer to be moved has not
 * been unmapped by the virtual memory subsystem. Beyond that, it cannot
 * guarantee the present whereabouts of the buffer to be moved, so it is up to
 * the client to safely determine whether or not it is still using the buffer.
 * The client must not free either of the buffers passed to the move callback,
 * since kmem wants to free them directly to the slab layer. The client response
 * tells kmem which of the two buffers to free:
 *
 * YES		kmem frees the old buffer (the move was successful)
 * NO		kmem frees the new buffer, marks the slab of the old buffer
 *              non-reclaimable to avoid bothering the client again
 * LATER	kmem frees the new buffer, increments slab_later_count
 * DONT_KNOW	kmem frees the new buffer, searches mags for the old buffer
 * DONT_NEED	kmem frees both the old buffer and the new buffer
 *
 * The pending callback argument now being processed contains both of the
 * buffers (old and new) passed to the move callback function, the slab of the
 * old buffer, and flags related to the move request, such as whether or not the
 * system was desperate for memory.
 *
 * Slabs are not freed while there is a pending callback, but instead are kept
 * on a deadlist, which is drained after the last callback completes. This means
 * that slabs are safe to access until kmem_move_end(), no matter how many of
 * their buffers have been freed. Once slab_refcnt reaches zero, it stays at
 * zero for as long as the slab remains on the deadlist and until the slab is
 * freed.
 */
static void
kmem_move_buffer(kmem_move_t *callback)
{
    kmem_cbrc_t response;
    kmem_slab_t *sp = callback->kmm_from_slab;
    kmem_cache_t *cp = sp->slab_cache;
    boolean_t free_on_slab;

    ASSERT(taskq_member(kmem_move_taskq, curthread));
    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));
    ASSERT(KMEM_SLAB_MEMBER(sp, callback->kmm_from_buf));

    /*
     * The number of allocated buffers on the slab may have changed since we
     * last checked the slab's reclaimability (when the pending move was
     * enqueued), or the client may have responded NO when asked to move
     * another buffer on the same slab.
     */
    if (!kmem_slab_is_reclaimable(cp, sp, callback->kmm_flags)) {
        KMEM_STAT_ADD(kmem_move_stats.kms_no_longer_reclaimable);
        KMEM_STAT_COND_ADD((callback->kmm_flags & KMM_NOTIFY),
                           kmem_move_stats.kms_notify_no_longer_reclaimable);
        kmem_slab_free(cp, callback->kmm_to_buf);
        kmem_move_end(cp, callback);
        return;
    }

    /*
     * Hunting magazines is expensive, so we'll wait to do that until the
     * client responds KMEM_CBRC_DONT_KNOW. However, checking the slab layer
     * is cheap, so we might as well do that here in case we can avoid
     * bothering the client.
     */
    mutex_enter(&cp->cache_lock);
    free_on_slab = (kmem_slab_allocated(cp, sp,
                                        callback->kmm_from_buf) == NULL);
    mutex_exit(&cp->cache_lock);

    if (free_on_slab) {
        KMEM_STAT_ADD(kmem_move_stats.kms_hunt_found_slab);
        kmem_slab_free(cp, callback->kmm_to_buf);
        kmem_move_end(cp, callback);
        return;
    }

    if (cp->cache_flags & KMF_BUFTAG) {
        /*
         * Make kmem_cache_alloc_debug() apply the constructor for us.
         */
        if (kmem_cache_alloc_debug(cp, callback->kmm_to_buf,
                                   KM_NOSLEEP, 1, caller()) != 0) {
            KMEM_STAT_ADD(kmem_move_stats.kms_alloc_fail);
            kmem_move_end(cp, callback);
            return;
        }
    } else if (cp->cache_constructor != NULL &&
               cp->cache_constructor(callback->kmm_to_buf, cp->cache_private,
                                     KM_NOSLEEP) != 0) {
                   atomic_inc_64(&cp->cache_alloc_fail);
                   KMEM_STAT_ADD(kmem_move_stats.kms_constructor_fail);
                   kmem_slab_free(cp, callback->kmm_to_buf);
                   kmem_move_end(cp, callback);
                   return;
               }

    KMEM_STAT_ADD(kmem_move_stats.kms_callbacks);
    KMEM_STAT_COND_ADD((callback->kmm_flags & KMM_NOTIFY),
                       kmem_move_stats.kms_notify_callbacks);
    cp->cache_defrag->kmd_callbacks++;
	cp->cache_defrag->kmd_thread = spl_current_thread();
    cp->cache_defrag->kmd_from_buf = callback->kmm_from_buf;
    cp->cache_defrag->kmd_to_buf = callback->kmm_to_buf;
    DTRACE_PROBE2(kmem__move__start, kmem_cache_t *, cp, kmem_move_t *,
                  callback);

    response = cp->cache_move(callback->kmm_from_buf,
                              callback->kmm_to_buf, cp->cache_bufsize, cp->cache_private);

    DTRACE_PROBE3(kmem__move__end, kmem_cache_t *, cp, kmem_move_t *,
                  callback, kmem_cbrc_t, response);
    cp->cache_defrag->kmd_thread = NULL;
    cp->cache_defrag->kmd_from_buf = NULL;
    cp->cache_defrag->kmd_to_buf = NULL;

    if (response == KMEM_CBRC_YES) {
        KMEM_STAT_ADD(kmem_move_stats.kms_yes);
        cp->cache_defrag->kmd_yes++;
        kmem_slab_free_constructed(cp, callback->kmm_from_buf, B_FALSE);
        /* slab safe to access until kmem_move_end() */
        if (sp->slab_refcnt == 0)
            cp->cache_defrag->kmd_slabs_freed++;
        mutex_enter(&cp->cache_lock);
        kmem_slab_move_yes(cp, sp, callback->kmm_from_buf);
        mutex_exit(&cp->cache_lock);
        kmem_move_end(cp, callback);
        return;
    }

    switch (response) {
        case KMEM_CBRC_NO:
            KMEM_STAT_ADD(kmem_move_stats.kms_no);
            cp->cache_defrag->kmd_no++;
            mutex_enter(&cp->cache_lock);
            kmem_slab_move_no(cp, sp, callback->kmm_from_buf);
            mutex_exit(&cp->cache_lock);
            break;
        case KMEM_CBRC_LATER:
            KMEM_STAT_ADD(kmem_move_stats.kms_later);
            cp->cache_defrag->kmd_later++;
            mutex_enter(&cp->cache_lock);
            if (!KMEM_SLAB_IS_PARTIAL(sp)) {
                mutex_exit(&cp->cache_lock);
                break;
            }

            if (++sp->slab_later_count >= KMEM_DISBELIEF) {
                KMEM_STAT_ADD(kmem_move_stats.kms_disbelief);
                kmem_slab_move_no(cp, sp, callback->kmm_from_buf);
            } else if (!(sp->slab_flags & KMEM_SLAB_NOMOVE)) {
                sp->slab_stuck_offset = KMEM_SLAB_OFFSET(sp,
                                                         callback->kmm_from_buf);
            }
            mutex_exit(&cp->cache_lock);
            break;
        case KMEM_CBRC_DONT_NEED:
            KMEM_STAT_ADD(kmem_move_stats.kms_dont_need);
            cp->cache_defrag->kmd_dont_need++;
            kmem_slab_free_constructed(cp, callback->kmm_from_buf, B_FALSE);
            if (sp->slab_refcnt == 0)
                cp->cache_defrag->kmd_slabs_freed++;
            mutex_enter(&cp->cache_lock);
            kmem_slab_move_yes(cp, sp, callback->kmm_from_buf);
            mutex_exit(&cp->cache_lock);
            break;
        case KMEM_CBRC_DONT_KNOW:
            KMEM_STAT_ADD(kmem_move_stats.kms_dont_know);
            cp->cache_defrag->kmd_dont_know++;
            if (kmem_hunt_mags(cp, callback->kmm_from_buf) != NULL) {
                KMEM_STAT_ADD(kmem_move_stats.kms_hunt_found_mag);
                cp->cache_defrag->kmd_hunt_found++;
                kmem_slab_free_constructed(cp, callback->kmm_from_buf,
                                           B_TRUE);
                if (sp->slab_refcnt == 0)
                    cp->cache_defrag->kmd_slabs_freed++;
                mutex_enter(&cp->cache_lock);
                kmem_slab_move_yes(cp, sp, callback->kmm_from_buf);
                mutex_exit(&cp->cache_lock);
            }
            break;
        default:
            panic("'%s' (%p) unexpected move callback response %d\n",
                  cp->cache_name, (void *)cp, response);
    }

    kmem_slab_free_constructed(cp, callback->kmm_to_buf, B_FALSE);
    kmem_move_end(cp, callback);
}

/* Return B_FALSE if there is insufficient memory for the move request. */
static boolean_t
kmem_move_begin(kmem_cache_t *cp, kmem_slab_t *sp, void *buf, int flags)
{
    void *to_buf;
    avl_index_t index;
    kmem_move_t *callback, *pending;
    ulong_t n;

    ASSERT(taskq_member(kmem_taskq, curthread));
    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));
    ASSERT(sp->slab_flags & KMEM_SLAB_MOVE_PENDING);

    callback = kmem_cache_alloc(kmem_move_cache, KM_NOSLEEP);
    if (callback == NULL) {
        KMEM_STAT_ADD(kmem_move_stats.kms_callback_alloc_fail);
        return (B_FALSE);
    }

    callback->kmm_from_slab = sp;
    callback->kmm_from_buf = buf;
    callback->kmm_flags = flags;

    mutex_enter(&cp->cache_lock);

    n = avl_numnodes(&cp->cache_partial_slabs);
    if ((n == 0) || ((n == 1) && !(flags & KMM_DEBUG))) {
        mutex_exit(&cp->cache_lock);
        kmem_cache_free(kmem_move_cache, callback);
        return (B_TRUE); /* there is no need for the move request */
    }

    pending = avl_find(&cp->cache_defrag->kmd_moves_pending, buf, &index);
    if (pending != NULL) {
        /*
         * If the move is already pending and we're desperate now,
         * update the move flags.
         */
        if (flags & KMM_DESPERATE) {
            pending->kmm_flags |= KMM_DESPERATE;
        }
        mutex_exit(&cp->cache_lock);
        KMEM_STAT_ADD(kmem_move_stats.kms_already_pending);
        kmem_cache_free(kmem_move_cache, callback);
        return (B_TRUE);
    }

    to_buf = kmem_slab_alloc_impl(cp, avl_first(&cp->cache_partial_slabs),
                                  B_FALSE);
    callback->kmm_to_buf = to_buf;
    avl_insert(&cp->cache_defrag->kmd_moves_pending, callback, index);

    mutex_exit(&cp->cache_lock);

    if (!taskq_dispatch(kmem_move_taskq, (task_func_t *)kmem_move_buffer,
                        callback, TQ_NOSLEEP)) {
        KMEM_STAT_ADD(kmem_move_stats.kms_callback_taskq_fail);
        mutex_enter(&cp->cache_lock);
        avl_remove(&cp->cache_defrag->kmd_moves_pending, callback);
        mutex_exit(&cp->cache_lock);
        kmem_slab_free(cp, to_buf);
        kmem_cache_free(kmem_move_cache, callback);
        return (B_FALSE);
    }

    return (B_TRUE);
}

static void
kmem_move_end(kmem_cache_t *cp, kmem_move_t *callback)
{
    avl_index_t index;

    ASSERT(cp->cache_defrag != NULL);
    ASSERT(taskq_member(kmem_move_taskq, curthread));
    ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));

    mutex_enter(&cp->cache_lock);
    VERIFY(avl_find(&cp->cache_defrag->kmd_moves_pending,
                    callback->kmm_from_buf, &index) != NULL);
    avl_remove(&cp->cache_defrag->kmd_moves_pending, callback);
    if (avl_is_empty(&cp->cache_defrag->kmd_moves_pending)) {
        list_t *deadlist = &cp->cache_defrag->kmd_deadlist;
        kmem_slab_t *sp;

        /*
         * The last pending move completed. Release all slabs from the
         * front of the dead list except for any slab at the tail that
         * needs to be released from the context of kmem_move_buffers().
         * kmem deferred unmapping the buffers on these slabs in order
         * to guarantee that buffers passed to the move callback have
         * been touched only by kmem or by the client itself.
         */
        while ((sp = list_remove_head(deadlist)) != NULL) {
            if (sp->slab_flags & KMEM_SLAB_MOVE_PENDING) {
                list_insert_tail(deadlist, sp);
                break;
            }
            cp->cache_defrag->kmd_deadcount--;
            cp->cache_slab_destroy++;
            mutex_exit(&cp->cache_lock);
            kmem_slab_destroy(cp, sp);
            KMEM_STAT_ADD(kmem_move_stats.kms_dead_slabs_freed);
            mutex_enter(&cp->cache_lock);
        }
    }
    mutex_exit(&cp->cache_lock);
    kmem_cache_free(kmem_move_cache, callback);
}

/*
 * Move buffers from least used slabs first by scanning backwards from the end
 * of the partial slab list. Scan at most max_scan candidate slabs and move
 * buffers from at most max_slabs slabs (0 for all partial slabs in both cases).
 * If desperate to reclaim memory, move buffers from any partial slab, otherwise
 * skip slabs with a ratio of allocated buffers at or above the current
 * threshold. Return the number of unskipped slabs (at most max_slabs, -1 if the
 * scan is aborted) so that the caller can adjust the reclaimability threshold
 * depending on how many reclaimable slabs it finds.
 *
 * kmem_move_buffers() drops and reacquires cache_lock every time it issues a
 * move request, since it is not valid for kmem_move_begin() to call
 * kmem_cache_alloc() or taskq_dispatch() with cache_lock held.
 */
static int
kmem_move_buffers(kmem_cache_t *cp, size_t max_scan, size_t max_slabs,
                  int flags)
{
    kmem_slab_t *sp;
    void *buf;
    int i, j; /* slab index, buffer index */
    int s; /* reclaimable slabs */
    int b; /* allocated (movable) buffers on reclaimable slab */
    boolean_t success;
    int refcnt;
    int nomove;

    ASSERT(taskq_member(kmem_taskq, curthread));
    ASSERT(MUTEX_HELD(&cp->cache_lock));
    ASSERT(kmem_move_cache != NULL);
    ASSERT(cp->cache_move != NULL && cp->cache_defrag != NULL);
    ASSERT((flags & KMM_DEBUG) ? !avl_is_empty(&cp->cache_partial_slabs) :
           avl_numnodes(&cp->cache_partial_slabs) > 1);

    if (kmem_move_blocked) {
        return (0);
    }

    if (kmem_move_fulltilt) {
        flags |= KMM_DESPERATE;
    }

    if (max_scan == 0 || (flags & KMM_DESPERATE)) {
        /*
         * Scan as many slabs as needed to find the desired number of
         * candidate slabs.
         */
        max_scan = (size_t)-1;
    }

    if (max_slabs == 0 || (flags & KMM_DESPERATE)) {
        /* Find as many candidate slabs as possible. */
        max_slabs = (size_t)-1;
    }

    sp = avl_last(&cp->cache_partial_slabs);
    ASSERT(KMEM_SLAB_IS_PARTIAL(sp));
    for (i = 0, s = 0; (i < max_scan) && (s < max_slabs) && (sp != NULL) &&
         ((sp != avl_first(&cp->cache_partial_slabs)) ||
          (flags & KMM_DEBUG));
         sp = AVL_PREV(&cp->cache_partial_slabs, sp), i++) {

        if (!kmem_slab_is_reclaimable(cp, sp, flags)) {
            continue;
        }
        s++;

        /* Look for allocated buffers to move. */
        for (j = 0, b = 0, buf = sp->slab_base;
             (j < sp->slab_chunks) && (b < sp->slab_refcnt);
             buf = (((char *)buf) + cp->cache_chunksize), j++) {

            if (kmem_slab_allocated(cp, sp, buf) == NULL) {
                continue;
            }

            b++;

            /*
             * Prevent the slab from being destroyed while we drop
             * cache_lock and while the pending move is not yet
             * registered. Flag the pending move while
             * kmd_moves_pending may still be empty, since we can't
             * yet rely on a non-zero pending move count to prevent
             * the slab from being destroyed.
             */
            ASSERT(!(sp->slab_flags & KMEM_SLAB_MOVE_PENDING));
            sp->slab_flags |= KMEM_SLAB_MOVE_PENDING;
            /*
             * Recheck refcnt and nomove after reacquiring the lock,
             * since these control the order of partial slabs, and
             * we want to know if we can pick up the scan where we
             * left off.
             */
            refcnt = sp->slab_refcnt;
            nomove = (sp->slab_flags & KMEM_SLAB_NOMOVE);
            mutex_exit(&cp->cache_lock);

            success = kmem_move_begin(cp, sp, buf, flags);

            /*
             * Now, before the lock is reacquired, kmem could
             * process all pending move requests and purge the
             * deadlist, so that upon reacquiring the lock, sp has
             * been remapped. Or, the client may free all the
             * objects on the slab while the pending moves are still
             * on the taskq. Therefore, the KMEM_SLAB_MOVE_PENDING
             * flag causes the slab to be put at the end of the
             * deadlist and prevents it from being destroyed, since
             * we plan to destroy it here after reacquiring the
             * lock.
             */
            mutex_enter(&cp->cache_lock);
            ASSERT(sp->slab_flags & KMEM_SLAB_MOVE_PENDING);
            sp->slab_flags &= ~KMEM_SLAB_MOVE_PENDING;

            if (sp->slab_refcnt == 0) {
                list_t *deadlist =
                &cp->cache_defrag->kmd_deadlist;
                list_remove(deadlist, sp);

                if (!avl_is_empty(
                                  &cp->cache_defrag->kmd_moves_pending)) {
                    /*
                     * A pending move makes it unsafe to
                     * destroy the slab, because even though
                     * the move is no longer needed, the
                     * context where that is determined
                     * requires the slab to exist.
                     * Fortunately, a pending move also
                     * means we don't need to destroy the
                     * slab here, since it will get
                     * destroyed along with any other slabs
                     * on the deadlist after the last
                     * pending move completes.
                     */
                    list_insert_head(deadlist, sp);
                    KMEM_STAT_ADD(kmem_move_stats.
                                  kms_endscan_slab_dead);
                    return (-1);
                }

                /*
                 * Destroy the slab now if it was completely
                 * freed while we dropped cache_lock and there
                 * are no pending moves. Since slab_refcnt
                 * cannot change once it reaches zero, no new
                 * pending moves from that slab are possible.
                 */
                cp->cache_defrag->kmd_deadcount--;
                cp->cache_slab_destroy++;
                mutex_exit(&cp->cache_lock);
                kmem_slab_destroy(cp, sp);
                KMEM_STAT_ADD(kmem_move_stats.
                              kms_dead_slabs_freed);
                KMEM_STAT_ADD(kmem_move_stats.
                              kms_endscan_slab_destroyed);
                mutex_enter(&cp->cache_lock);
                /*
                 * Since we can't pick up the scan where we left
                 * off, abort the scan and say nothing about the
                 * number of reclaimable slabs.
                 */
                return (-1);
            }

            if (!success) {
                /*
                 * Abort the scan if there is not enough memory
                 * for the request and say nothing about the
                 * number of reclaimable slabs.
                 */
                KMEM_STAT_COND_ADD(s < max_slabs,
                                   kmem_move_stats.kms_endscan_nomem);
                return (-1);
            }

            /*
             * The slab's position changed while the lock was
             * dropped, so we don't know where we are in the
             * sequence any more.
             */
            if (sp->slab_refcnt != refcnt) {
                /*
                 * If this is a KMM_DEBUG move, the slab_refcnt
                 * may have changed because we allocated a
                 * destination buffer on the same slab. In that
                 * case, we're not interested in counting it.
                 */
                KMEM_STAT_COND_ADD(!(flags & KMM_DEBUG) &&
                                   (s < max_slabs),
                                   kmem_move_stats.kms_endscan_refcnt_changed);
                return (-1);
            }
            if ((sp->slab_flags & KMEM_SLAB_NOMOVE) != nomove) {
                KMEM_STAT_COND_ADD(s < max_slabs,
                                   kmem_move_stats.kms_endscan_nomove_changed);
                return (-1);
            }

            /*
             * Generating a move request allocates a destination
             * buffer from the slab layer, bumping the first partial
             * slab if it is completely allocated. If the current
             * slab becomes the first partial slab as a result, we
             * can't continue to scan backwards.
             *
             * If this is a KMM_DEBUG move and we allocated the
             * destination buffer from the last partial slab, then
             * the buffer we're moving is on the same slab and our
             * slab_refcnt has changed, causing us to return before
             * reaching here if there are no partial slabs left.
             */
            ASSERT(!avl_is_empty(&cp->cache_partial_slabs));
            if (sp == avl_first(&cp->cache_partial_slabs)) {
                /*
                 * We're not interested in a second KMM_DEBUG
                 * move.
                 */
                goto end_scan;
            }
        }
    }
end_scan:

    KMEM_STAT_COND_ADD(!(flags & KMM_DEBUG) &&
                       (s < max_slabs) &&
                       (sp == avl_first(&cp->cache_partial_slabs)),
                       kmem_move_stats.kms_endscan_freelist);

    return (s);
}

typedef struct kmem_move_notify_args {
    kmem_cache_t *kmna_cache;
    void *kmna_buf;
} kmem_move_notify_args_t;

static void
kmem_cache_move_notify_task(void *arg)
{
    kmem_move_notify_args_t *args = arg;
    kmem_cache_t *cp = args->kmna_cache;
    void *buf = args->kmna_buf;
    kmem_slab_t *sp;

    ASSERT(taskq_member(kmem_taskq, curthread));
    ASSERT(list_link_active(&cp->cache_link));

    zfs_kmem_free(args, sizeof (kmem_move_notify_args_t));
    mutex_enter(&cp->cache_lock);
    sp = kmem_slab_allocated(cp, NULL, buf);

    /* Ignore the notification if the buffer is no longer allocated. */
    if (sp == NULL) {
        mutex_exit(&cp->cache_lock);
        return;
    }

    /* Ignore the notification if there's no reason to move the buffer. */
    if (avl_numnodes(&cp->cache_partial_slabs) > 1) {
        /*
         * So far the notification is not ignored. Ignore the
         * notification if the slab is not marked by an earlier refusal
         * to move a buffer.
         */
        if (!(sp->slab_flags & KMEM_SLAB_NOMOVE) &&
            (sp->slab_later_count == 0)) {
            mutex_exit(&cp->cache_lock);
            return;
        }

        kmem_slab_move_yes(cp, sp, buf);
        ASSERT(!(sp->slab_flags & KMEM_SLAB_MOVE_PENDING));
        sp->slab_flags |= KMEM_SLAB_MOVE_PENDING;
        mutex_exit(&cp->cache_lock);
        /* see kmem_move_buffers() about dropping the lock */
        (void) kmem_move_begin(cp, sp, buf, KMM_NOTIFY);
        mutex_enter(&cp->cache_lock);
        ASSERT(sp->slab_flags & KMEM_SLAB_MOVE_PENDING);
        sp->slab_flags &= ~KMEM_SLAB_MOVE_PENDING;
        if (sp->slab_refcnt == 0) {
            list_t *deadlist = &cp->cache_defrag->kmd_deadlist;
            list_remove(deadlist, sp);

            if (!avl_is_empty(
                              &cp->cache_defrag->kmd_moves_pending)) {
                list_insert_head(deadlist, sp);
                mutex_exit(&cp->cache_lock);
                KMEM_STAT_ADD(kmem_move_stats.
                              kms_notify_slab_dead);
                return;
            }

            cp->cache_defrag->kmd_deadcount--;
            cp->cache_slab_destroy++;
            mutex_exit(&cp->cache_lock);
            kmem_slab_destroy(cp, sp);
            KMEM_STAT_ADD(kmem_move_stats.kms_dead_slabs_freed);
            KMEM_STAT_ADD(kmem_move_stats.
                          kms_notify_slab_destroyed);
            return;
        }
    } else {
        kmem_slab_move_yes(cp, sp, buf);
    }
    mutex_exit(&cp->cache_lock);
}

void
kmem_cache_move_notify(kmem_cache_t *cp, void *buf)
{
    kmem_move_notify_args_t *args;

    KMEM_STAT_ADD(kmem_move_stats.kms_notify);
    args = zfs_kmem_alloc(sizeof (kmem_move_notify_args_t), KM_NOSLEEP);
    if (args != NULL) {
        args->kmna_cache = cp;
        args->kmna_buf = buf;
        if (!taskq_dispatch(kmem_taskq,
                            (task_func_t *)kmem_cache_move_notify_task, args,
                            TQ_NOSLEEP))
            zfs_kmem_free(args, sizeof (kmem_move_notify_args_t));
    }
}

static void
kmem_cache_defrag(kmem_cache_t *cp)
{
    size_t n;

    ASSERT(cp->cache_defrag != NULL);

    mutex_enter(&cp->cache_lock);
    n = avl_numnodes(&cp->cache_partial_slabs);
    if (n > 1) {
        /* kmem_move_buffers() drops and reacquires cache_lock */
        KMEM_STAT_ADD(kmem_move_stats.kms_defrags);
        cp->cache_defrag->kmd_defrags++;
        (void) kmem_move_buffers(cp, n, 0, KMM_DESPERATE);
    }
    mutex_exit(&cp->cache_lock);
}

/* Is this cache above the fragmentation threshold? */
static boolean_t
kmem_cache_frag_threshold(kmem_cache_t *cp, uint64_t nfree)
{
    /*
     *	nfree		kmem_frag_numer
     * ------------------ > ---------------
     * cp->cache_buftotal	kmem_frag_denom
     */
    return ((nfree * kmem_frag_denom) >
            (cp->cache_buftotal * kmem_frag_numer));
}

static boolean_t
kmem_cache_is_fragmented(kmem_cache_t *cp, boolean_t *doreap)
{
    boolean_t fragmented;
    uint64_t nfree;

    ASSERT(MUTEX_HELD(&cp->cache_lock));
    *doreap = B_FALSE;

    if (kmem_move_fulltilt) {
        if (avl_numnodes(&cp->cache_partial_slabs) > 1) {
            return (B_TRUE);
        }
    } else {
        if ((cp->cache_complete_slab_count + avl_numnodes(
                                                          &cp->cache_partial_slabs)) < kmem_frag_minslabs) {
            return (B_FALSE);
        }
    }

    nfree = cp->cache_bufslab;
    fragmented = ((avl_numnodes(&cp->cache_partial_slabs) > 1) &&
                  kmem_cache_frag_threshold(cp, nfree));

    /*
     * Free buffers in the magazine layer appear allocated from the point of
     * view of the slab layer. We want to know if the slab layer would
     * appear fragmented if we included free buffers from magazines that
     * have fallen out of the working set.
     */
    if (!fragmented) {
        long reap;

        mutex_enter(&cp->cache_depot_lock);
        reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
        reap = MIN(reap, cp->cache_full.ml_total);
        mutex_exit(&cp->cache_depot_lock);

        nfree += ((uint64_t)reap * cp->cache_magtype->mt_magsize);
        if (kmem_cache_frag_threshold(cp, nfree)) {
            *doreap = B_TRUE;
        }
    }

    return (fragmented);
}

/* Called periodically from kmem_taskq */
static void
kmem_cache_scan(kmem_cache_t *cp)
{
    boolean_t reap = B_FALSE;
    kmem_defrag_t *kmd;

    ASSERT(taskq_member(kmem_taskq, curthread));

    mutex_enter(&cp->cache_lock);

    kmd = cp->cache_defrag;
    if (kmd->kmd_consolidate > 0) {
        kmd->kmd_consolidate--;
        mutex_exit(&cp->cache_lock);
        kmem_cache_reap(cp);
        return;
    }

    if (kmem_cache_is_fragmented(cp, &reap)) {
        size_t slabs_found;

        /*
         * Consolidate reclaimable slabs from the end of the partial
         * slab list (scan at most kmem_reclaim_scan_range slabs to find
         * reclaimable slabs). Keep track of how many candidate slabs we
         * looked for and how many we actually found so we can adjust
         * the definition of a candidate slab if we're having trouble
         * finding them.
         *
         * kmem_move_buffers() drops and reacquires cache_lock.
         */
        KMEM_STAT_ADD(kmem_move_stats.kms_scans);
        kmd->kmd_scans++;
        slabs_found = kmem_move_buffers(cp, kmem_reclaim_scan_range,
                                        kmem_reclaim_max_slabs, 0);
//        if (slabs_found >= 0) {
            kmd->kmd_slabs_sought += kmem_reclaim_max_slabs;
            kmd->kmd_slabs_found += slabs_found;
//        }

        if (++kmd->kmd_tries >= kmem_reclaim_scan_range) {
            kmd->kmd_tries = 0;

            /*
             * If we had difficulty finding candidate slabs in
             * previous scans, adjust the threshold so that
             * candidates are easier to find.
             */
            if (kmd->kmd_slabs_found == kmd->kmd_slabs_sought) {
                kmem_adjust_reclaim_threshold(kmd, -1);
            } else if ((kmd->kmd_slabs_found * 2) <
                       kmd->kmd_slabs_sought) {
                kmem_adjust_reclaim_threshold(kmd, 1);
            }
            kmd->kmd_slabs_sought = 0;
            kmd->kmd_slabs_found = 0;
        }
    } else {
        kmem_reset_reclaim_threshold(cp->cache_defrag);
#ifdef	DEBUG
        if (!avl_is_empty(&cp->cache_partial_slabs)) {
            /*
             * In a debug kernel we want the consolidator to
             * run occasionally even when there is plenty of
             * memory.
             */
            uint16_t debug_rand;

            (void) random_get_bytes((uint8_t *)&debug_rand, 2);
            if (!kmem_move_noreap &&
                ((debug_rand % kmem_mtb_reap) == 0)) {
                mutex_exit(&cp->cache_lock);
                KMEM_STAT_ADD(kmem_move_stats.kms_debug_reaps);
                kmem_cache_reap(cp);
                return;
            } else if ((debug_rand % kmem_mtb_move) == 0) {
                KMEM_STAT_ADD(kmem_move_stats.kms_scans);
                KMEM_STAT_ADD(kmem_move_stats.kms_debug_scans);
                kmd->kmd_scans++;
                (void) kmem_move_buffers(cp,
                                         kmem_reclaim_scan_range, 1, KMM_DEBUG);
            }
        }
#endif	/* DEBUG */
    }

    mutex_exit(&cp->cache_lock);

    if (reap) {
        KMEM_STAT_ADD(kmem_move_stats.kms_scan_depot_ws_reaps);
        kmem_depot_ws_reap(cp);
    }
}

//===============================================================
// Status
//===============================================================

size_t
kmem_num_pages_wanted()
{

	if (pressure_bytes_target && (pressure_bytes_target < kmem_used())) {
		return (kmem_used() - pressure_bytes_target) / PAGE_SIZE;
	}

    return 0;
}

size_t
kmem_size(void)
{
    return (physmem * PAGE_SIZE);
}

size_t
kmem_used(void)
{
    return kmem_size() - kmem_avail();
}


int spl_vm_pool_low(void)
{
	if (pressure_bytes_target && (pressure_bytes_target < kmem_used())) {
		return 1;
	}

	if ( vm_page_free_count < vm_page_free_min ) {
		uint64_t newtarget;
		newtarget = kmem_used() -
			((vm_page_free_min - vm_page_free_count) * PAGE_SIZE*MULT);
		if (!pressure_bytes_target || (newtarget < pressure_bytes_target)) {
			pressure_bytes_target = newtarget;
			//printf("pool low: new target %llu\n", newtarget);
		}
		return 1;
	}

	pressure_bytes_target = 0;

	return 0;
}

//===============================================================
// String handling
//===============================================================

void
strfree(char *str)
{
    zfs_kmem_free(str, strlen(str) + 1);
}

char *kvasprintf(const char *fmt, va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    p = zfs_kmem_alloc(len+1, KM_SLEEP);
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

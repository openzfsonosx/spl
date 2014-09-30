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


// Flag to cause tasks and threads to terminate as
// the kmem module is preparing to unload.
int					shutting_down = 0;

// Activation counter for the monitor thread
uint64_t            monitor_thread_wake_count = 0;

// Number of pages requested by the OS
uint64_t            last_pressure_pages_wanted = 0;

// Number of pages released on last call to bmalloc_release_pages()
uint64_t			last_pressure_pages_released = 0;

// Number of time the garbage collector has woken
uint64_t			gc_wake_count = 0;

// Number of pages released on last call to bmalloc_garbage_collect()
uint64_t			last_gc_pages_released = 0;

// Amount of physical memory
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

// Task queue for processing kmem internal tasks.
static taskq_t		*kmem_taskq;

// Collection of kmem caches
static kmutex_t		kmem_cache_lock;/* inter-cache linkage only */
static list_t		kmem_caches;

// Lock manager stuff
static lck_grp_t        *kmem_lock_group = NULL;
static lck_attr_t       *kmem_lock_attr = NULL;
static lck_grp_attr_t	*kmem_group_attr = NULL;

// Various timeout periods
static struct timespec	kmem_reap_all_task_timeout	= {15, 0};			// 15 seconds
static struct timespec	reap_finish_task_timeout	= {0, 500000000};	// 0.5 seconds
static struct timespec	bmalloc_task_timeout		= {2, 0};           // 2 Seconds

//===============================================================
// Kstats published for bmalloc
//===============================================================

typedef struct bmalloc_stats {
	kstat_named_t bmalloc_app_allocated;
	kstat_named_t bmalloc_system_allocated;
	kstat_named_t bmalloc_space_efficiency_percent;
	kstat_named_t bmalloc_active_threads;
	kstat_named_t monitor_thread_wake_count;
	kstat_named_t num_pages_wanted;
	kstat_named_t last_pressure_pages_released;
	kstat_named_t gc_wake_count;
	kstat_named_t last_gc_pages_released;
} bmalloc_stats_t;

static bmalloc_stats_t bmalloc_stats = {
	{"apps_allocated", KSTAT_DATA_UINT64},
	{"bmalloc_allocated", KSTAT_DATA_UINT64},
	{"space_efficiency_percent", KSTAT_DATA_UINT64},
	{"active_threads", KSTAT_DATA_UINT64},
	{"pressure_thr_wakes", KSTAT_DATA_UINT64},
	{"pressure_pages_wanted", KSTAT_DATA_UINT64},
	{"pressure_pages_released", KSTAT_DATA_UINT64},
	{"gc_wake_count", KSTAT_DATA_UINT64},
	{"gc_pages_released", KSTAT_DATA_UINT64}
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

//===============================================================
// Allocation and release calls
//===============================================================

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
	ASSERT(size);
	return bmalloc(size, KM_SLEEP);
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
	ASSERT(buf && size);
	bfree(buf, size);
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
	return num_pages_wanted;
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
// CACHE - stubbed implementation
// ===========================================================

kmem_cache_t *
kmem_cache_create(char *name, size_t bufsize, size_t align,
				  int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
				  void (*reclaim)(void *), void *private, vmem_t *vmp, int cflags)
{
	kmem_cache_t *cache;

	ASSERT(vmp == NULL);

	cache = zfs_kmem_alloc(sizeof(*cache), KM_SLEEP);
	strlcpy(cache->cache_name, name, sizeof(cache->cache_name));
	cache->cache_constructor = constructor;
	cache->cache_destructor = destructor;
	cache->cache_reclaim = reclaim;
	cache->cache_private = private;
	cache->cache_bufsize = bufsize;

	mutex_enter(&kmem_cache_lock);
	list_insert_tail(&kmem_caches, cache);
	mutex_exit(&kmem_cache_lock);

	return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
	mutex_enter(&kmem_cache_lock);
	list_remove(&kmem_caches, cp);
	mutex_exit(&kmem_cache_lock);

	zfs_kmem_free(cp, sizeof(kmem_cache_t));
}

void *
kmem_cache_alloc(kmem_cache_t *cp, int flags)
{
	void *buf = zfs_kmem_alloc(cp->cache_bufsize, flags);
	if (buf != NULL && cp->cache_constructor != NULL)
		cp->cache_constructor(buf, cp->cache_private, flags);

	return (buf);
}

void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
	if (cp->cache_destructor != NULL)
		cp->cache_destructor(buf, cp->cache_private);
	zfs_kmem_free(buf, cp->cache_bufsize);
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
	if (cp->cache_reclaim != NULL)
		cp->cache_reclaim(cp->cache_private);
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
	/*
	 * A mechanism to allow ZFS to request SPL to release memory
	 * after a cleanup action. Currenly not utilised.
	 */
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

void memory_monitor_thread()
{
	kern_return_t kr;
	unsigned int nsecs_monitored = 1000000000 / 4;
	unsigned int pages_reclaimed = 0;
	unsigned int		tmp_pages_wanted = 0;

	while (!shutting_down) {
		kr = mach_vm_pressure_monitor(TRUE, nsecs_monitored,
									  &pages_reclaimed, &tmp_pages_wanted);

		if (!shutting_down) {
			if (kr == KERN_SUCCESS && tmp_pages_wanted) {

				num_pages_wanted = tmp_pages_wanted;

				last_pressure_pages_wanted = num_pages_wanted;

				monitor_thread_wake_count++;

				last_pressure_pages_released = bmalloc_release_pages(num_pages_wanted);

				if (last_pressure_pages_released < num_pages_wanted) {
					// Update amount of memory needed to free
					num_pages_wanted -= last_pressure_pages_released;

					// And request memory holders release memory.
					kmem_cache_applyall(kmem_cache_reap, 0, TQ_NOSLEEP);
				}
			}
		}
	}

	thread_exit();
}

static void start_memory_monitor()
{
	(void)thread_create(NULL, 0, memory_monitor_thread, 0, 0, 0, 0, 0);
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
	gc_wake_count++;
	last_gc_pages_released = bmalloc_garbage_collect();
	if(!shutting_down) {
		bsd_timeout(bmalloc_maintenance_task_proc, 0, &bmalloc_task_timeout);
	}
}

static void bmalloc_maintenance_task_proc(void *p)
{
	taskq_dispatch(kmem_taskq, bmalloc_maintenance_task, 0, TQ_PUSHPAGE);
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
	last_gc_pages_released = bmalloc_garbage_collect();

	//bmalloc_release_memory();
}

static void reap_finish_task_proc()
{
	if(!shutting_down) {
		taskq_dispatch(kmem_taskq, kmem_reap_task_finish, 0, TQ_PUSHPAGE);
	}
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
		bs->monitor_thread_wake_count.value.ui64 = monitor_thread_wake_count;
		bs->num_pages_wanted.value.ui64 = last_pressure_pages_wanted;
		bs->last_pressure_pages_released.value.ui64 = last_pressure_pages_released;
		bs->last_gc_pages_released.value.ui64 = last_gc_pages_released;
		bs->gc_wake_count.value.ui64 = gc_wake_count;
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
}

void spl_kmem_tasks_fini()
{
	shutting_down = 1;
	bsd_untimeout(bmalloc_maintenance_task_proc, 0);
	bsd_untimeout(kmem_reap_all_task_proc, 0);
	bsd_untimeout(reap_finish_task_proc, 0);
	stop_memory_monitor();

	taskq_destroy(kmem_taskq);
}

void
spl_kmem_fini(void)
{
	kstat_delete(bmalloc_ksp);
}

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
 *
 */

#include <spl-debug.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <kern/sched_prim.h>
#include "spl-bmalloc.h"

//===============================================================
// OS Interface
//===============================================================

// This variable is a count of the number of threads
// blocked waiting for memory pages to become free.
// The variable is also used as an event to wake
// threads waiting for memory pages to become free.
// http://fxr.watson.org/fxr/source/osfmk/vm/vm_resident.c?v=xnu-2050.18.24;im=excerpts#L2141)
// and other locations.
//
// We are using wake indications on this event as a
// indication of paging activity, and therefore as a
// proxy to the machine experiencing memory pressure.
extern unsigned int    vm_page_free_wanted;

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

//===============================================================
// Variables
//===============================================================

unsigned int my_test_event = 0;

// Measure the wakeup count of the memory monitor thread
unsigned long wake_count = 0; // DEBUG

// Indicates that the machine is believed to be swapping
// due to thread waking. This is reset when spl_vm_pool_low()
// is called and reports the activity to ZFS.
int machine_is_swapping = 0;

// Flag to cause tasks and threads to terminate as
// the kmem module is preparing to unload.
int shutting_down = 0;

uint64_t physmem = 0;

// Size in bytes of the memory allocated by ZFS in calls to the SPL,
static uint64_t total_in_use = 0;

// Size in bytes of the memory allocated by bmalloc resuling from
// allocation calls to the SPL. The ratio of
// total_in_use :bmalloc_allocated_total is an indication of
// the space efficiency of bmalloc.
extern uint64_t bmalloc_allocated_total;

// Number of pages the OS last reported that it needed freed
unsigned int num_pages_wanted = 0;

// Protects the list of kmem_caches
static kmutex_t kmem_cache_lock;

// List of kmem_caches
static list_t  kmem_caches;

// Task queue for processing kmem internal tasks.
static taskq_t* kmem_taskq;

static struct timespec bmalloc_task_timeout = {5, 0}; // 5 Seconds
static struct timespec reap_finish_task_timeout = {0, 500000000}; // 0.5 seconds

//===============================================================
// Forward Declarations
//===============================================================

void spl_register_oids(void);
void spl_unregister_oids(void);

static void bmalloc_maintenance_task_proc(void *p);
static void kmem_reap_task(void *p);

void bmalloc_release_memory_task();
void memory_pressure_task();

static void kmem_reap_task_finish(void *p);
static void reap_finish_task_proc();

//===============================================================
// Sysctls
//===============================================================

SYSCTL_DECL(_spl);
SYSCTL_NODE( , OID_AUTO, spl, CTLFLAG_RW, 0, "Solaris Porting Layer");
struct sysctl_oid_list sysctl__spl_children;

SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_total, CTLFLAG_RD,
            &total_in_use, "kmem.total bytes allocated to ZFS");

SYSCTL_QUAD(_spl, OID_AUTO, bmalloc_allocated_total, CTLFLAG_RD,
            &bmalloc_allocated_total, "kmem.total bytes allocated by SPL");

extern uint32_t zfs_threads;
SYSCTL_INT(_spl, OID_AUTO, num_threads,
           CTLFLAG_RD, &zfs_threads, 0,
           "Num threads");


//===============================================================
// Allocation and release calls
//===============================================================

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
    ASSERT(size);
	
    void *p = bmalloc(size);
	
    if (p) {
        if (kmflags & KM_ZERO) {
            bzero(p, size);
        }
        atomic_add_64(&total_in_use, size);
    } else {
        printf("[spl] kmem_alloc(%lu) failed: \n", size);
    }
	
    return (p);
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
    return zfs_kmem_alloc(size, kmflags | KM_ZERO);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    ASSERT(buf && size);
	
    bfree(buf, size);
    atomic_sub_64(&total_in_use, size);
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
    return total_in_use;
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


//===============================================================
// Object Caches
//===============================================================

static int
kmem_std_constructor(void *mem, int size __unused, void *private, int flags)
{
	struct kmem_cache *cache = private;
	return (cache->kc_constructor(mem, cache->kc_private, flags));
}

static void
kmem_std_destructor(void *mem, int size __unused, void *private)
{
	struct kmem_cache *cache = private;
	cache->kc_destructor(mem, cache->kc_private);
}

kmem_cache_t *
kmem_cache_create(char *name, size_t bufsize, size_t align,
                  int (*constructor)(void *, void *, int),
				  void (*destructor)(void *, void *),
                  void (*reclaim)(void *),
				  void *private, vmem_t *vmp, int cflags)
{
	kmem_cache_t *cache;
	
	ASSERT(vmp == NULL);
	
	cache = zfs_kmem_alloc(sizeof(*cache), KM_SLEEP);
	strlcpy(cache->kc_name, name, sizeof(cache->kc_name));
	cache->kc_constructor = constructor;
	cache->kc_destructor = destructor;
	cache->kc_reclaim = reclaim;
	cache->kc_private = private;
	cache->kc_size = bufsize;
	
	/*
     * Add the cache to the global list.  This makes it visible
     * to kmem_update(), so the cache must be ready for business.
     */
    mutex_enter(&kmem_cache_lock);
    list_insert_tail(&kmem_caches, cache);
    mutex_exit(&kmem_cache_lock);
	
	return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cache)
{
    /*
     * Remove the cache from the global cache list so that no one else
     * can schedule tasks on its behalf, wait for any pending tasks to
     * complete, purge the cache, and then destroy it.
     */
    mutex_enter(&kmem_cache_lock);
    list_remove(&kmem_caches, cache);
    mutex_exit(&kmem_cache_lock);
	
	zfs_kmem_free(cache, sizeof(*cache));
}

void *
kmem_cache_alloc(kmem_cache_t *cache, int flags)
{
	void *p;
	
	p = zfs_kmem_alloc(cache->kc_size, flags);
	if (p != NULL && cache->kc_constructor != NULL)
		kmem_std_constructor(p, cache->kc_size, cache, flags);
	return (p);
}

void
kmem_cache_free(kmem_cache_t *cache, void *buf)
{
	if (cache->kc_destructor != NULL)
		kmem_std_destructor(buf, cache->kc_size, cache);
	zfs_kmem_free(buf, cache->kc_size);
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
kmem_cache_reap(kmem_cache_t *cache)
{
	//printf("kmem_cache_reap\n");
    /*
     * Ask the cache's owner to free some memory if possible.
     * The idea is to handle things like the inode cache, which
     * typically sits on a bunch of memory that it doesn't truly
     * *need*.  Reclaim policy is entirely up to the owner; this
     * callback is just an advisory plea for help.
     */
    if (cache->kc_reclaim != NULL) {
		cache->kc_reclaim(cache->kc_private);
	}
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
	
    p = bmalloc(len+1);
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

static struct timespec memory_pressure_timeout = {0, 12500000}; // 0.125 Seconds

static void my_test_event_proc(void *p)
{
	//printf("my test event\n");
	thread_wakeup((event_t) &my_test_event);
}

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
				// Asynchronously react to the memory pressure notification
				taskq_dispatch(kmem_taskq, memory_pressure_task,
							   (void *)num_pages_wanted, TQ_PUSHPAGE);
			}
			
			
			// Rate limiting mechanism - not sure the we should enable this.
			// Note though that this thread can be waken a LOT of times per
			// second in the absence of the throttle. But this is load
			// is representing the real VM behavior when the machine is under load.
			if (!shutting_down) {
				assert_wait((event_t) &vm_page_free_wanted, THREAD_INTERRUPTIBLE);
				bsd_timeout(my_test_event_proc, 0, &memory_pressure_timeout);
				thread_block(THREAD_CONTINUE_NULL);
			}
			
		}
	}
	
	//printf("memory monitor thread exiting\n");
	thread_exit();
}

static void start_memory_monitor()
{
	kthread_t* thread = thread_create(NULL, 0, memory_monitor_thread_continue, 0, 0, 0, 0, 0);
	//bsd_timeout(my_test_event_proc, 0, &memory_pressure_timeout);
}

static void stop_memory_monitor()
{
    shutting_down = 1;
	bsd_untimeout(my_test_event_proc, 0);
	
	thread_wakeup((event_t) &my_test_event);
	thread_wakeup((event_t) &vm_page_free_wanted);
	return;
	
    delay(1000);
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

void memory_pressure_task(void *p)
{
	uint64_t num_pages = (uint64_t)(p);
	
	// Attempt to give the OS as many pages as it is
	// seeking from the memory cached by bmalloc.
	//
	// If bmalloc cant satisfy the request completely
	// then we have to resort to having ZFS start releasing memory.
	if (!bmalloc_release_memory_num(num_pages)) {
		// Set flag for spl_vm_pool_low callers
		machine_is_swapping = 1;
		
		// And request memory holders release memory.
		kmem_cache_applyall(kmem_cache_reap, 0, TQ_NOSLEEP);
		
		// Cache reaping is likely to be async, give the memory owners some
		// time to implement before cleaning out unwanted memory.
		bsd_timeout(reap_finish_task_proc, 0, &reap_finish_task_timeout);
	}
}

static void bmalloc_maintenance_task_proc(void *p)
{
	taskq_dispatch(kmem_taskq, bmalloc_maintenance_task, 0, TQ_PUSHPAGE);
}

void bmalloc_release_memory_task()
{
	//printf("bmalloc_release_memory_task\n");
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

//===============================================================
// Initialisation/Finalisation
//===============================================================

void spl_register_oids(void)
{
    sysctl_register_oid(&sysctl__spl);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_register_oid(&sysctl__spl_num_threads);
    sysctl_register_oid(&sysctl__spl_bmalloc_allocated_total);
}

void spl_unregister_oids(void)
{
    sysctl_unregister_oid(&sysctl__spl);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_unregister_oid(&sysctl__spl_num_threads);
    sysctl_unregister_oid(&sysctl__spl_bmalloc_allocated_total);
}

void
spl_kmem_init(uint64_t total_memory)
{
    printf("SPL: Total memory %llu\n", total_memory);
	
	printf("SPL: WARNING:\n");
    printf("SPL: This is an experimental branch of OpenZFS.\n");
    printf("SPL: It relies on kernel notifications to control\n");
	printf("SPL: memory allocation and release under load.\n");
	printf("SPL: It might be faster/better/shinier than master.\n");
    printf("SPL: but it may also eat your datasets and take your.\n");
    printf("SPL: firstborn child.\n");
    printf("SPL: Then again it might just work! Over to you.\n");
	
    spl_register_oids();
	
    // Initialise the cache list
    mutex_init(&kmem_cache_lock, "kmem", MUTEX_DEFAULT, NULL);
    list_create(&kmem_caches, sizeof(kmem_cache_t), offsetof(kmem_cache_t, kc_cache_link_node));
}

void spl_kmem_tasks_init()
{
	printf("tasks init\n");
    kmem_taskq = taskq_create("kmem-taskq",
                              1,
                              minclsyspri,
                              300, INT_MAX, TASKQ_PREPOPULATE);
    
    bsd_timeout(bmalloc_maintenance_task_proc, 0, &bmalloc_task_timeout);
	start_memory_monitor();
}

void spl_kmem_tasks_fini()
{
	printf("Tasks fini");
	
    // FIXME - might have to put a flush-through task into the task q
    // in here somewhere to ensure that all tasks are dead during
    // shutdown.
    
    bsd_untimeout(bmalloc_maintenance_task_proc, 0);
    bsd_untimeout(reap_finish_task_proc, 0);
	
    shutting_down = 1;
    taskq_destroy(kmem_taskq);
	stop_memory_monitor();
}

void
spl_kmem_fini(void)
{
    spl_unregister_oids();
}


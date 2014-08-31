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
 * Copyright 2014 Brendon Humphrey (brendon.humphrey@mac.com)
 *
 * CDDL HEADER END
 */

/*
 * The allocator in this file is an example of a slice allocator. It works by
 * claiming large blocks of memory from an underlying slow allocator, and
 * retaining this memory for as long as the application can plausably require
 * it. By nature slice allocators are fast, non-fragmenting, and potentially
 * quite space inefficient depending on the size of the allocations from the
 * calling application.
 *
 * A memory pool contains ready to use blocks of memory. These are periodically
 * garbage collected and returned to the underlying allocator after a certain
 * age.
 *
 * The allocator contains a number of Slice Allocators, which in turn have three
 * collections of Slices. Slices are claimed from the memory pool and returned
 * there if they become unused.
 *
 * The Slice Allocator tracks the state of the Slices by placing them in one of
 * three lists: free, partial, and full. Allocations are made from slices in the
 * partial list. If a slice becomes full it is moved to the full list. If there
 * are no partial slices available the next available free slice is moved from
 * the free list into the partial list. When memory is freed from the slices
 * they move from the full list, into the partial list, and ultimately into the
 * free list depending on how many allocations have been taken from the slice.
 *
 * Slices are blocks of memory that have been claimed from the memory pool. They
 * have a header which contains some basic state, and a list node to allow the
 * Slice to be moved into a linked list of Slices. The remainder of the Slice is
 * divided into rows of memory that can be allocated to an application. The
 * Slice contains a single linked list of free rows. Allocating a row is as
 * simple as removing the list head. Freeing inserts the freed row at the list
 * head.
 *
 * The Slice rows consist of a header and a block of bytes which are the memory
 * allocated to the application. The header constists of a pointer to the Slice
 * header and a next pointer allowing the row to be inserted into the Slices'
 * free lists. The header pointer is there to eliminate the need to search
 * backwards in memory from the row to the slice header when memory is being
 * freed (this search can be very slow).
 *
 * The allocator must be initialized by calling bmalloc_init() before any
 * attempts to allocate memory are made. The allocator can release all free
 * memory on an emergency basis by calling bmalloc_release_memory(). The
 * allocator requires periodic garbage collecting to migrate free blocks of
 * memory from the Slice free lists, to the Memory Pool, to the underlying
 * allocator - by calling bmalloc_garbage_collect().
 */

/*
 * Place the allocator in thread-safe mode. If you have an application where the
 * allocator does not have to be thread safe, then removing the mutexes will
 * improve the allocator performance by about 30%.
 */
#define	THREAD_SAFE 1

/*
 * Provide extra locking around the slice lists, as under some conditions,
 * memory handling errors in the application can interfere with the locking
 * strategy used.
 */
// #define	SLICE_SPINLOCK 1

/*
 * Turn on counting of the number of allocations made to each allocator. Major
 * performance killer. Keep turned off.
 */
// #define	COUNT_ALLOCATIONS 1

/*
 * Borrow an idea from the Linux kernel SLUB allocator - namely, have the Slice
 * Allocator simply forget about full slices. They are "found" again when a free
 * occurs from the full slice, and added to the partial list again. This saves a
 * small amount of list processing overhead and storage space. (The performance
 * difference is probably purely academic.)
 *
 * You will want to enable this if hunting memory leaks.
 */
// #define	SLICE_ALLOCATOR_TRACK_FULL_SLABS 1

// #define	DEBUG 1

#ifdef DEBUG

/* Select a logging mechanism. */
// #define	REPORT_PANIC 1
#define	REPORT_LOG 1

/*
 * Check whether an application is writing beyond the number of bytes allocated
 * in a call to bmalloc(). Implemented using buffer poisoning.
 */
#define	SLICE_CHECK_BOUNDS_WRITE 1

/*
 * Check for writes to memory after free. Works in part by poisoning the user
 * memory on free. The idea is that if a buffer is not fully poisoned on
 * allocate, there is evidence of use after free. This may have the side effect
 * of causing other failures - if an application relies on valid data in the
 * memory after free, bad things can happen.
 */
#define	SLICE_CHECK_WRITE_AFTER_FREE 1

/* Check integrity of slice row headers. */
#define	SLICE_CHECK_ROW_HEADERS 1

/*
 * Check that the number of bytes passed to bmalloc to release matches the
 * number of bytes allocated.
 */
#define	SLICE_CHECK_FREE_SIZE 1

/*
 * Instrument the Slice object to detect concurrent threads accessing the data
 * structures - indicative of a serious programming error.
 */
#define	SLICE_CHECK_THREADS 1

/*
 * Have the SA check that any operations performed on a slice are performed on a
 * slice that the the SA actually owns.
 */
#define	SA_CHECK_SLICE_SIZE 1

/* Select correct dependencies based on debug flags. */

#ifdef SLICE_CHECK_WRITE_AFTER_FREE
/* Poison user allocatable portions of slice rows on free. */
#define	SLICE_POISON_USER_SPACE 1
#endif /* SLICE_CHECK_WRITE_AFTER_FREE */

#ifdef SLICE_CHECK_BOUNDS_WRITE
#define	SLICE_POISON_USER_SPACE 1
#define	SLICE_CHECK_FREE_SIZE 1
#define	SLICE_CHECK_ROW_HEADERS 1
#endif /* SLICE_CHECK_BOUNDS_WRITE */

#endif /* DEBUG */

#ifdef REPORT_PANIC
#define	REPORT(STR, ...) panic(STR, __VA_ARGS__);
#define	REPORT0(STR)    panic(STR);
#else
#define	REPORT(STR, ...) OSReportWithBacktrace(STR, __VA_ARGS__);
#define	REPORT0(STR)    OSReportWithBacktrace(STR);
#endif /* REPORT_PANIC */

#ifdef _KERNEL
#define	IN_KERNEL 1
#else
#undef	IN_KERNEL
#endif /* _KERNEL */

#include <stdint.h>
#include <string.h>

#ifdef IN_KERNEL
#include <kern/locks.h>
#include <sys/atomic.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <libkern/OSDebug.h>
#else
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include "list.h"
#include "pthread.h"
#endif /* IN_KERNEL */

// =============================================================================
// Base Types
// =============================================================================

typedef uint64_t sa_size_t;
typedef uint8_t sa_byte_t;
typedef uint8_t sa_bool_t;
typedef uint64_t sa_hrtime_t;
typedef uint32_t large_offset_t;

#define	SA_TRUE (sa_bool_t)1;
#define	SA_FALSE (sa_bool_t)0;

#define	SA_NSEC_PER_SEC  1000000000ULL
#define	SA_NSEC_PER_USEC 1000;

/*
 * Dual purpose pointer
 */
union row_navigation {
	struct slice			*slice;
	struct allocatable_row	*next;
};
 
/*
 * Make sure this structure remains a multiple of 8 bytes to prevent problems
 * with alignment of memory allocated to the caller.
 */
typedef struct allocatable_row {
#ifdef SLICE_CHECK_ROW_HEADERS
	sa_size_t	prefix;
#endif /* SLICE_CHECK_ROW_HEADERS */
	union		row_navigation navigation;
#ifdef SLICE_CHECK_FREE_SIZE
	sa_size_t	allocated_bytes;
#endif /* SLICE_CHECK_FREE_SIZE */
#ifdef SLICE_CHECK_ROW_HEADERS
	sa_size_t	suffix;
#endif /* SLICE_CHECK_ROW_HEADERS */
} allocatable_row_t;

/*
 * For slices operating in small mode, the row header overlays
 * the user allocatable memory in part, and so the header content
 * can only be valid when the row is not allocated.
 *
 * Since the smallest size of allocation in bmalloc, this structure
 * must not grow beyond that size.
 */
typedef struct small_allocatable_row {
	struct small_allocatable_row *next;
} small_allocatable_row_t;

struct slice_allocator;

typedef union row_free_lists {
	struct allocatable_row			*large;
	struct small_allocatable_row	*small;
} row_free_lists_t;

typedef struct slice {
	struct slice_allocator			*sa;				// parent slice allocator
	row_free_lists_t				free_list;
	sa_size_t						alloc_count;
#ifdef SLICE_CHECK_THREADS
	UInt64							semaphore;
#endif /* SLICE_CHECK_THREADS */
	sa_hrtime_t						time_freed;
	list_node_t						slice_link_node;
#ifdef SLICE_SPINLOCK
	lck_spin_t						*spinlock;
#endif /* SLICE_SPINLOCK */
} slice_t;

#define SMALL_ALLOC 0x01

typedef struct slice_allocator {
	uint64_t						flags;
	sa_size_t						slice_size;
	list_t							free;
	list_t							partial;
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
	list_t							full;
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */
	/* Max alloc size for slice */
	sa_size_t						max_alloc_size;
	/* Number of rows to be allocated in the Slices */
	sa_size_t						num_allocs_per_slice;
	lck_spin_t						*spinlock;
} slice_allocator_t;

// =============================================================================
// Constants
// =============================================================================

#ifdef SLICE_CHECK_ROW_HEADERS
static const sa_size_t ROW_HEADER_GUARD = 0xFEEDFACEC0DEBABE;
#endif /* SLICE_CHECK_ROW_HEADERS */

#ifdef SLICE_POISON_USER_SPACE
static const unsigned char POISON_VALUE = 0xFF;
#endif /* SLICE_POISON_USER_SPACE */

/*
 * Maximum size of allocation size for which "small allocation mode"
 * will be enabled in the slices.
 */
const sa_size_t MAX_SMALL_ALLOC_SIZE = 512; // bytes

/*
 * Standardised size for large slices.
 */
const sa_size_t LARGE_SLICE_SIZE = 4096 + (128 * 1024); // bytes

/*
 * Once there are no remaining allocations from a slice of memory, the Slice
 * Allocator places the slice on its free list. If no allocations are made from
 * the slice within SA_MAX_SLICE_FREE_MEM_AGE seconds, the slice is released to
 * the memory pool for allocation by another slice allocator or release to the
 * underlying allocator.
 */
const sa_hrtime_t SA_MAX_SLICE_FREE_MEM_AGE = 15 * SA_NSEC_PER_SEC;

/*
 * Sizes of various slices that are used by zfs. This table started out as a
 * naive ^2 table, and more slice sizes were added as a result of instrumenting
 * allocations. In terms of allocator efficiency it's beneficial to closely
 * match allocation requests to slice size. Slice size % 8 must = 0, or the
 * allocator will allocate non-8-byte-alligned memory.
 */
const sa_size_t ALLOCATOR_SLICE_SIZES[] = {
	8,
	16,
	32,
	40,
	48,
	64,
	80,
	96,
	128,
	168,
	224,
	256,
	320,
	512,
	856,
	936,
	1024,
	1920,
	2048,
	4096,
	12288,
	16384,
	32768,
	36864,
	40960,
	49152,
	57344,
	65536,
	131072
};

const long NUM_ALLOCATORS = sizeof (ALLOCATOR_SLICE_SIZES) / sizeof (sa_size_t);

// =============================================================================
// Variables
// =============================================================================

/* Lock manager stuff */
static lck_grp_t *bmalloc_lock_group = NULL;
static lck_attr_t *bmalloc_lock_attr = NULL;
static lck_grp_attr_t *bmalloc_group_attr = NULL;

/* Collection of slice allocators */
static slice_allocator_t *allocators = 0;

/* Allocation size to slice allocator lookup table */
static slice_allocator_t **allocator_lookup_table = 0;

#ifdef COUNT_ALLOCATIONS
/* Allocation counter array */
static sa_size_t *allocation_counters = 0;
#endif /* COUNT_ALLOCATIONS */

/* Total memory held allocated */
uint64_t bmalloc_allocated_total = 0;


// =============================================================================
// OS Compatability interface
// =============================================================================

#ifdef IN_KERNEL
extern vm_map_t kernel_map;

extern kern_return_t kernel_memory_allocate(vm_map_t map, void **addrp,
    vm_size_t size, vm_offset_t mask, int flags);

extern void kmem_free(vm_map_t map, void *addr, vm_size_t size);

extern int vm_pool_low(void);
#endif /* IN_KERNEL */

static void *
osif_malloc(sa_size_t size)
{
#ifdef IN_KERNEL
	void *tr;
	kern_return_t kr;

	kr = kernel_memory_allocate(kernel_map, &tr, size, 0, 0);

	if (kr == KERN_SUCCESS) {
		atomic_add_64(&bmalloc_allocated_total, size);
		return (tr);
	} else {
		return (NULL);
	}
#else
	return ((void*)malloc(size));
#endif /* IN_KERNEL */
}

static inline void
osif_free(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
	kmem_free(kernel_map, buf, size);
	atomic_sub_64(&bmalloc_allocated_total, size);
#else
	free(buf);
#endif /* IN_KERNEL */
}

static inline void
osif_zero_memory(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
	bzero(buf, size);
#else
	memset(buf, 0, size);
#endif /* IN_KERNEL */
}

static sa_hrtime_t
osif_gethrtime()
{
#ifdef IN_KERNEL
	return (gethrtime());
#else
	struct timeval t;
	struct timezone zone;

	gettimeofday(&t, &zone);

	return ((t.tv_sec * 1000000000) + (t.tv_usec * 1000));
#endif /* IN_KERNEL */
}

// =============================================================================
// Large Slice
// =============================================================================

#ifdef SLICE_POISON_USER_SPACE
static void
slice_poison_row(slice_t *slice, allocatable_row_t *row)
{
	allocatable_row_t *tmp = row;
	tmp++;
	unsigned char *user_memory = (unsigned char *)tmp;
	memset(user_memory, POISON_VALUE, slice->sa->max_alloc_size);
}

static Boolean
slice_row_is_poisoned(slice_t *slice, allocatable_row_t *row)
{
	Boolean poisoned = TRUE;
	allocatable_row_t *tmp = row;
	tmp++;
	unsigned char *user_memory = (unsigned char *)tmp;

	for (int i = 0; i < slice->sa->max_alloc_size; i++, user_memory++) {
		if (*user_memory != POISON_VALUE) {
			poisoned = FALSE;
			break;
		}
	}

	return (poisoned);
}

static Boolean
slice_row_is_within_bounds(slice_t *slice, allocatable_row_t *row)
{
	Boolean within_bounds = TRUE;
	allocatable_row_t *tmp = row;
	tmp++;
	unsigned char *user_memory_end = (unsigned char *)tmp +
	    slice->sa->max_alloc_size;
	unsigned char *user_memory = (unsigned char *)tmp;

	if (slice->sa->max_alloc_size != row->allocated_bytes) {
		user_memory += row->allocated_bytes;

		for (; user_memory < user_memory_end; user_memory++) {
			if ((*user_memory) != POISON_VALUE) {
				within_bounds = FALSE;
				break;
			}
		}
	}

	return (within_bounds);
}
#endif /* SLICE_POISON_USER_SPACE */

static inline allocatable_row_t *
slice_get_row_address(slice_t *slice, int index)
{
	sa_byte_t *p = (sa_byte_t *)slice;
	p = p + sizeof (slice_t) + (index * (slice->sa->max_alloc_size +
	    sizeof (allocatable_row_t)));

	return ((allocatable_row_t *)p);
}

static inline small_allocatable_row_t *
slice_small_get_row_address(slice_t *slice, int index)
{
	sa_byte_t *p = (sa_byte_t *)slice;
	p = p + sizeof (slice_t) + (index * slice->sa->max_alloc_size);
	return ((small_allocatable_row_t *)p);
}

static inline void
slice_insert_free_row(slice_t *slice, allocatable_row_t *row)
{
#ifdef SLICE_SPINLOCK
	lck_spin_lock(slice->spinlock);
#endif /* SLICE_SPINLOCK */

	row->navigation.next = slice->free_list.large;
	slice->free_list.large = row;

#ifdef SLICE_SPINLOCK
	lck_spin_unlock(slice->spinlock);
#endif /* SLICE_SPINLOCK */
}

static inline void
slice_small_insert_free_row(slice_t *slice, small_allocatable_row_t *row)
{
	row->next = slice->free_list.small;
	slice->free_list.small = row;
}

static inline allocatable_row_t *
slice_get_row(slice_t *slice)
{
	if (slice->free_list.large == 0) {
		return (0);
	} else {
		allocatable_row_t *row;

#ifdef SLICE_SPINLOCK
		lck_spin_lock(slice->spinlock);
#endif /* SLICE_SPINLOCK */

		row = slice->free_list.large;
		slice->free_list.large = row->navigation.next;
		row->navigation.slice = slice;

#ifdef SLICE_SPINLOCK
		lck_spin_unlock(slice->spinlock);
#endif /* SLICE_SPINLOCK */
		return (row);
	}
}

static inline small_allocatable_row_t *
slice_small_get_row(slice_t *slice)
{
	if (slice->free_list.small == 0) {
		return (0);
	} else {
		small_allocatable_row_t *row = slice->free_list.small;
		slice->free_list.small = row->next;
		return (row);
	}
}

static void
slice_init(slice_t *slice, slice_allocator_t *sa)
{
	list_link_init(&slice->slice_link_node);
	slice->sa = sa;
	slice->alloc_count = 0;
	
	if (sa->flags & SMALL_ALLOC) {
		slice->free_list.small = 0;
		
		for (int i = 0; i < slice->sa->num_allocs_per_slice; i++) {
			small_allocatable_row_t *row = slice_small_get_row_address(slice, i);
			slice_small_insert_free_row(slice, row);
		}
		
	} else {
		slice->free_list.large = 0;

#ifdef SLICE_CHECK_THREADS
		slice->semaphore = 0;
#endif /* SLICE_CHECK_THREADS */
		
#ifdef SLICE_SPINLOCK
		slice->spinlock = lck_spin_alloc_init(bmalloc_lock_group,
											  bmalloc_lock_attr);
#endif /* SLICE_SPINLOCK */
		
		for (int i = 0; i < slice->sa->num_allocs_per_slice; i++) {
			allocatable_row_t *row = slice_get_row_address(slice, i);
			row->navigation.slice = slice;
			
#ifdef SLICE_CHECK_FREE_SIZE
			row->allocated_bytes = 0;
#endif /* SLICE_CHECK_FREE_SIZE */
			
#ifdef SLICE_CHECK_ROW_HEADERS
			row->prefix = ROW_HEADER_GUARD;
			row->suffix = ROW_HEADER_GUARD;
#endif /* SLICE_CHECK_ROW_HEADERS */
			
#ifdef SLICE_POISON_USER_SPACE
			slice_poison_row(slice, row);
#endif /* SLICE_POISON_USER_SPACE */
			
			slice_insert_free_row(slice, row);
		}
	}
}

static inline void
slice_fini(slice_t *slice)
{
#ifdef SLICE_SPINLOCK
	lck_spin_destroy(slice->spinlock, bmalloc_lock_group);
#endif /* SLICE_SPINLOCK */
}

static inline int
slice_is_full(slice_t *slice)
{
	if (slice->sa->flags & SMALL_ALLOC) {
		return (slice->free_list.small == 0);
	} else {
		return (slice->free_list.large == 0);
	}
}

static inline int slice_is_empty(slice_t *slice)
{
	return (slice->alloc_count == 0);
}

static void *
#ifndef DEBUG
slice_alloc(slice_t *slice)
#else
slice_alloc(slice_t *slice, sa_size_t alloc_size)
#endif /* !DEBUG */
{
	if (slice->sa->flags & SMALL_ALLOC) {
		small_allocatable_row_t *row = slice_small_get_row(slice);
		
		if (row) {
			slice->alloc_count++;
		}

		return (void*)(row);
	} else {
	
#ifdef SLICE_CHECK_THREADS
	Boolean res = OSCompareAndSwap64(0, 1, &slice->semaphore);
	if (!res) {
		REPORT0("slice_alloc - thread already present\n");
	}
#endif /* SLICE_CHECK_THREADS */
	
	allocatable_row_t *row = slice_get_row(slice);
	if (row) {
#ifdef SLICE_CHECK_ROW_HEADERS
		if (row->prefix != ROW_HEADER_GUARD ||
		    row->suffix != ROW_HEADER_GUARD) {
			REPORT0("slice_alloc - detected corrupted row "
			    "header\n");
		}
#endif /* SLICE_CHECK_ROW_HEADERS */

#ifdef SLICE_CHECK_FREE_SIZE
		row->allocated_bytes = alloc_size;
#endif /* SLICE_CHECK_FREE_SIZE */

#ifdef SLICE_CHECK_WRITE_AFTER_FREE
		if (!slice_row_is_poisoned(slice, row)) {
			REPORT("slice_alloc - write after free detected - sa "
			    "size %llu\n", slice->sa->max_alloc_size);
		}
#endif /* SLICE_CHECK_WRITE_AFTER_FREE */

#ifdef SLICE_CHECK_BOUNDS_WRITE
		slice_poison_row(slice, row);
#endif /* SLICE_CHECK_BOUNDS_WRITE */

		slice->alloc_count++;
		row++;
	}

#ifdef SLICE_CHECK_THREADS
	if (res) {
		OSDecrementAtomic64(&slice->semaphore);
	}
#endif /* SLICE_CHECK_THREADS */

		return ((void *)row);
	}
}

static void
#ifndef DEBUG
slice_free_row(slice_t *slice, allocatable_row_t *row)
#else
slice_free_row(slice_t *slice, allocatable_row_t *row, sa_size_t alloc_size)
#endif /* !DEBUG */
{
#ifdef SLICE_CHECK_THREADS
	Boolean res = OSCompareAndSwap64(0, 1, &slice->semaphore);
	if (!res) {
		REPORT0("slice_free_row - thread already present\n");
	}
#endif /* SLICE_CHECK_THREADS */

	slice->alloc_count--;

#ifdef SLICE_CHECK_ROW_HEADERS
	if (row->prefix != ROW_HEADER_GUARD ||
	    row->suffix != ROW_HEADER_GUARD) {
		REPORT0("slice_free_row - detected corrupted row header\n");
	}
#endif /* SLICE_CHECK_ROW_HEADERS */

#ifdef SLICE_CHECK_BOUNDS_WRITE
	if (!slice_row_is_within_bounds(slice, row)) {
		REPORT("slice_free_row - write outside of allocated memory "
		    "detected alloc_size = %llu\n", row->allocated_bytes);
	}
#endif /* SLICE_CHECK_BOUNDS_WRITE */

#ifdef SLICE_CHECK_FREE_SIZE
	if (row->allocated_bytes != alloc_size) {
		REPORT("slice_free_row - free of %llu bytes when allcated %llu",
		    alloc_size, row->allocated_bytes);
	}
	row->allocated_bytes = 0;
#endif /* SLICE_CHECK_FREE_SIZE */

#ifdef SLICE_CHECK_WRITE_AFTER_FREE
	slice_poison_row(slice, row);
#endif /* SLICE_CHECK_WRITE_AFTER_FREE */

	slice_insert_free_row(slice, row);

#ifdef SLICE_CHECK_THREADS
	if (res) {
		OSDecrementAtomic64(&slice->semaphore);
	}
#endif /* SLICE_CHECK_THREADS */
}

static void
slice_small_free_row(slice_t *slice, small_allocatable_row_t *row)
{
	slice->alloc_count--;
	slice_small_insert_free_row(slice, row);
}

static inline slice_t *
slice_get_slice_from_row(void *buf, allocatable_row_t **row)
{
	(*row) = (allocatable_row_t *)buf;
	(*row)--;
	return ((*row)->navigation.slice);
}

static inline slice_t *
slice_small_get_slice_from_row(void *buf, small_allocatable_row_t **row)
{
	(*row) = (small_allocatable_row_t *)buf;
	return (slice_t*)P2ALIGN((uint64_t)buf, (uint64_t)PAGE_SIZE);
}

// =============================================================================
// Slice Allocator
// =============================================================================

static void
slice_allocator_empty_list(slice_allocator_t *sa, list_t *list)
{
	lck_spin_lock(sa->spinlock);

	while (!list_is_empty(list)) {
		slice_t *slice = list_head(list);
		list_remove(list, slice);

		lck_spin_unlock(sa->spinlock);
		slice_fini(slice);
		osif_free(slice, sa->slice_size);
		lck_spin_lock(sa->spinlock);
	}

	lck_spin_unlock(sa->spinlock);
}

static void
slice_allocator_init(slice_allocator_t *sa, sa_size_t max_alloc_size)
{
	osif_zero_memory(sa, sizeof (slice_allocator_t));

	/* Select a memory pool allocation size of the allocator. */
#ifndef DEBUG
	if (max_alloc_size <=  MAX_SMALL_ALLOC_SIZE) {
		sa->flags = SMALL_ALLOC;
		sa->slice_size = PAGE_SIZE;
	} else {
		sa->flags = 0;
		sa->slice_size = LARGE_SLICE_SIZE;
	}
#else
	sa->flags = 0;
	sa->slice_size = LARGE_SLICE_SIZE;
#endif

	sa->spinlock = lck_spin_alloc_init(bmalloc_lock_group,
	    bmalloc_lock_attr);

	/*
	 * Create lists for tracking the state of the slices as memory is
	 * allocated.
	 */
	list_create(&sa->free, sizeof (slice_t),
	    offsetof(slice_t, slice_link_node));
	list_create(&sa->partial, sizeof (slice_t),
	    offsetof(slice_t, slice_link_node));
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
	list_create(&sa->full, sizeof (slice_t),
	    offsetof(slice_t, slice_link_node));
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */

	sa->max_alloc_size = max_alloc_size;
	sa->num_allocs_per_slice = (sa->slice_size - sizeof (slice_t)) /
	    (sizeof (allocatable_row_t) + max_alloc_size);
}

static void
slice_allocator_fini(slice_allocator_t *sa)
{
	slice_allocator_empty_list(sa, &sa->free);
	slice_allocator_empty_list(sa, &sa->partial);

#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
	slice_allocator_empty_list(sa, &sa->full);
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */

	list_destroy(&sa->free);
	list_destroy(&sa->partial);
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
	list_destroy(&sa->full);
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */

	/* Destroy spinlock */
	lck_spin_destroy(sa->spinlock, bmalloc_lock_group);
}

static sa_size_t
slice_allocator_get_allocation_size(slice_allocator_t *sa)
{
	return (sa->max_alloc_size);
}

static void *
#ifndef DEBUG
slice_allocator_alloc(slice_allocator_t *sa)
#else
slice_allocator_alloc(slice_allocator_t *sa, sa_size_t size)
#endif /* !DEBUG */
{
	slice_t *slice = 0;

	lck_spin_lock(sa->spinlock);

	/*
	 * Locate a slice with residual capacity. First, check for a partially
	 * full slice, and use some more of its capacity. Next, look to see if
	 * we have a ready to go empty slice. If not, finally go to underlying
	 * allocator for a new slice.
	 */
	if (!list_is_empty(&sa->partial)) {
		slice = list_head(&sa->partial);
	} else if (!list_is_empty(&sa->free)) {
		slice = list_tail(&sa->free);
		list_remove_tail(&sa->free);
		list_insert_head(&sa->partial, slice);
	} else {
		lck_spin_unlock(sa->spinlock);
		slice = (slice_t *)osif_malloc(sa->slice_size);;
		slice_init(slice, sa);
		lck_spin_lock(sa->spinlock);

		list_insert_head(&sa->partial, slice);
	}

#ifdef SA_CHECK_SLICE_SIZE
	if (sa->max_alloc_size != slice->sa->max_alloc_size) {
		REPORT("slice_allocator_alloc - alloc size (%llu) sa %llu slice"
		    " %llu\n", size, sa->max_alloc_size,
		    slice->sa->max_alloc_size);
	}
#endif /* SA_CHECK_SLICE_SIZE */

	/* Grab memory from the slice */
#ifndef DEBUG
	void *p = slice_alloc(slice);
#else
	void *p = slice_alloc(slice, size);
#endif /* !DEBUG */

	/*
	 * Check to see if the slice buffer has become full. If it has, then
	 * move it into the full list so that we no longer keep trying to
	 * allocate from it.
	 */
	if (slice_is_full(slice)) {
		list_remove(&sa->partial, slice);
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
		list_insert_head(&sa->full, slice);
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */
	}

	lck_spin_unlock(sa->spinlock);

	return (p);
}

static void
#ifndef DEBUG
slice_allocator_free(slice_allocator_t *sa, void *buf)
#else
slice_allocator_free(slice_allocator_t *sa, void *buf, sa_size_t size)
#endif /* !DEBUG */
{
	lck_spin_lock(sa->spinlock);

	/* Locate the slice buffer that the allocation lives within. */
	slice_t *slice;
	allocatable_row_t *row = 0;
	small_allocatable_row_t *small_row = 0;
	
	if (sa->flags & SMALL_ALLOC) {
		slice = slice_small_get_slice_from_row(buf, &small_row);
	} else {
		slice = slice_get_slice_from_row(buf, &row);
	}

#ifdef SA_CHECK_SLICE_SIZE
	if (sa != slice->sa) {
		REPORT0("slice_allocator_free - slice not owned by sa detected.\n")
	}
#endif /* SA_CHECK_SLICE_SIZE */

	/*
	 * If the slice was previously full, remove it from the free list and
	 * place it in the available list.
	 */
	if (slice_is_full(slice)) {
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
		list_remove(&sa->full, slice);
#endif /* SLICE_ALLOCATOR_TRACK_FULL_SLABS */
		list_insert_tail(&sa->partial, slice);
	}

#ifndef DEBUG
	if (sa->flags & SMALL_ALLOC) {
		slice_small_free_row(slice, small_row);
	} else {
		slice_free_row(slice, row);
	}
#else
	slice_free_row(slice, row, size);
#endif /* !DEBUG */

	/* Finally migrate to the free list if needed. */
	if (slice_is_empty(slice)) {
		list_remove(&sa->partial, slice);
		slice->time_freed = osif_gethrtime();
		list_insert_head(&sa->free, slice);
	}

	lck_spin_unlock(sa->spinlock);
}

static void
slice_allocator_release_memory(slice_allocator_t *sa)
{
	slice_allocator_empty_list(sa, &sa->free);
}

static void
slice_allocator_garbage_collect(slice_allocator_t *sa)
{
	sa_hrtime_t now = osif_gethrtime();
	int done = 0;

	lck_spin_lock(sa->spinlock);

	do {
		if (!list_is_empty(&sa->free)) {
			slice_t *slice = list_tail(&sa->free);

#ifdef SA_CHECK_SLICE_SIZE
			if (sa != slice->sa) {
				REPORT0("slice_allocator_free - slice not owned by sa detected.\n")
			}
#endif /* SA_CHECK_SLICE_SIZE */

			if (now - slice->time_freed >
			    SA_MAX_SLICE_FREE_MEM_AGE) {
				list_remove_tail(&sa->free);

				lck_spin_unlock(sa->spinlock);
				slice_fini(slice);
				osif_free(slice, sa->slice_size);
				lck_spin_lock(sa->spinlock);
			} else {
				done = 1;
			}
		} else {
			done = 1;
		}
	} while (!done);

	lck_spin_unlock(sa->spinlock);
}

// =============================================================================
// Public Interface
// =============================================================================

static sa_size_t
bmalloc_allocator_array_size()
{
	return (NUM_ALLOCATORS * sizeof (slice_allocator_t));
}

static slice_allocator_t *
bmalloc_allocator_for_size(sa_size_t size)
{
	for (int i = 0; i < NUM_ALLOCATORS; i++) {
		if (slice_allocator_get_allocation_size(&allocators[i]) >=
		    size) {
			return (&allocators[i]);
		}
	}

	return ((void *)0);
}

static sa_size_t
bmalloc_allocator_lookup_table_size(sa_size_t max_allocation_size)
{
	return (max_allocation_size * sizeof (slice_allocator_t *) + 1);
}

void
bmalloc_init()
{
	printf("[SPL] bmalloc slice allocator initialised\n");

	printf("[SPL] small object allocator mode active.\n");
	
#ifdef DEBUG
	printf("[SPL] Memory debugging enabled.\n");

#ifdef REPORT_PANIC
	printf("[SPL] the machine will panic on detection of a memory "
	    "fault.\n");
#endif /* REPORT_PANIC */

#ifdef REPORT_LOG
	printf("[SPL] memory faults will be logged to the system log.\n");
#endif /* REPORT_LOG */

#ifdef SLICE_CHECK_BOUNDS_WRITE
	printf("[SPL] checking for out of bounds writes (slows performance)\n");
#endif /* SLICE_CHECK_BOUNDS_WRITE */

#ifdef SLICE_CHECK_WRITE_AFTER_FREE
	printf("[SPL] checking for write after free (slows performance)\n");
#endif /* SLICE_CHECK_WRITE_AFTER_FREE */

#ifdef SLICE_CHECK_ROW_HEADERS
	printf("[SPL] checking slice internal data structure integrity.\n");
#endif /* SLICE_CHECK_ROW_HEADERS */

#ifdef SLICE_CHECK_FREE_SIZE
	printf("[SPL] checking that allocation size is matched by free "
	    "size.\n");
#endif /* SLICE_CHECK_FREE_SIZE */

#ifdef SLICE_CHECK_THREADS
	printf("[SPL] checking the unexpected concurrency in slices.\n");
#endif /* SLICE_CHECK_THREADS */

#ifdef SA_CHECK_SLICE_SIZE
	printf("[SPL] checking for incorrect slice <-> sa sharing.\n");
#endif /* SA_CHECK_SLICE_SIZE */
#endif /* DEBUG */

	/* Initialize spinlocks */
	bmalloc_lock_attr = lck_attr_alloc_init();
	bmalloc_group_attr = lck_grp_attr_alloc_init();
	bmalloc_lock_group  = lck_grp_alloc_init("bmalloc-spinlocks",
	    bmalloc_group_attr);

	sa_size_t max_allocation_size =
	    ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1];

	/* Create the slice allocators */
	sa_size_t array_size = NUM_ALLOCATORS * sizeof (slice_allocator_t);
	allocators = (slice_allocator_t *)osif_malloc(array_size);
	osif_zero_memory(allocators, array_size);

	for (int i = 0; i < NUM_ALLOCATORS; i++) {
		slice_allocator_init(&allocators[i], ALLOCATOR_SLICE_SIZES[i]);
	}

	/* Create the allocator lookup array */
	allocator_lookup_table = osif_malloc(
	    bmalloc_allocator_lookup_table_size(
	    ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));
	for (int i = 1; i <= max_allocation_size; i++) {
		allocator_lookup_table[i] = bmalloc_allocator_for_size(i);
	}

	/*
	 * There is a requirement for bmalloc(0) to return a valid pointer.
	 * Beyond that the behavior is implementation dependant. Bmalloc will
	 * support bmalloc(0) by treating it the same as bmalloc(1), which
	 * returns a pointer to the smallest slice of memory supported by the
	 * allocator. The returned pointer can be safely freed.
	 *
	 * This simple implementation preserves maximum performance by not
	 * inserting any conditional behavior in the path of other non-zero
	 * allocations.
	 */
	allocator_lookup_table[0] = allocator_lookup_table[1];

#ifdef COUNT_ALLOCATIONS
	/* Create the allocation counters */
	allocation_counters = osif_malloc((1 +
	    ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) * sizeof (sa_size_t));
	osif_zero_memory(allocation_counters, (1 +
	    ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) * sizeof (sa_size_t));
#endif /* COUNT_ALLOCATIONS */
}

void
bmalloc_fini()
{
#ifdef COUNT_ALLOCATIONS
	/* Print out allocation statistics */
	printf("Allocator stats begin\n");
	for (int i = 0; i < ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]; i++) {
		if (allocation_counters[i]) {
			printf("%llu %llu\n", i, allocation_counters[i]);
		}
	}
	printf("Allocator stats end\n");
#endif /* COUNT_ALLOCATIONS */

	/* Clean up the allocators */
	for (int i = 0; i < NUM_ALLOCATORS; i++) {
		slice_allocator_fini(&allocators[i]);
	}

	/* Free local resources */
	osif_free(allocators, bmalloc_allocator_array_size());
	osif_free(allocator_lookup_table, bmalloc_allocator_lookup_table_size(
	    ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));

	/* Cleanup our locks */
	lck_attr_free(bmalloc_lock_attr);
	bmalloc_lock_attr = NULL;

	lck_grp_attr_free(bmalloc_group_attr);
	bmalloc_group_attr = NULL;

	lck_grp_free(bmalloc_lock_group);
	bmalloc_lock_group = NULL;
}

void *
bmalloc(sa_size_t size)
{
	void *p = 0;

	if (size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
#ifdef COUNT_ALLOCATIONS
		atomic_add_64(&allocation_counters[size], 1);
#endif /* COUNT_ALLOCATIONS */
#ifndef DEBUG
		p = slice_allocator_alloc(allocator_lookup_table[size]);
#else
		p = slice_allocator_alloc(allocator_lookup_table[size], size);
#endif /* !DEBUG */
	} else {
		p = osif_malloc(size);
	}

	return (p);
}

void
bfree(void *buf, sa_size_t size)
{
	if (size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
#ifndef DEBUG
		slice_allocator_free(allocator_lookup_table[size], buf);
#else
		slice_allocator_free(allocator_lookup_table[size], buf, size);
#endif /* !DEBUG */
	} else {
		osif_free(buf, size);
	}
}

void
bmalloc_release_memory()
{
	for (int i = 0; i < NUM_ALLOCATORS; i++) {
		slice_allocator_release_memory(&allocators[i]);
	}
}

void
bmalloc_garbage_collect()
{
	for (int i = 0; i < NUM_ALLOCATORS; i++) {
		slice_allocator_garbage_collect(&allocators[i]);
	}
}

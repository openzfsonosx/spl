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
 
 * CDDL HEADER END
 */

// The allocator in this file is an example of a slice allocator.
// It works by claiming large blocks of memory from an underlying
// slow allocator, and retaining this memory for as long as the
// application can plausably require it. By nature slice allocators
// are fast, non-fragmenting, and potentially quite space inefficient
// depending on the size of the allocations from the calling application.
//
// A memory pool contains ready to use blocks of memory. These are
// periodically garbage collected and returned to the underlying
// allocator after a certain age.
//
// The allocator contains a number of Slice Allocators, which in
// turn have three collections of Slices. Slices are claimed from
// the memory pool and returned there if they become unused.
//
// The Slice Allocator tracks the state of the Slices by placing them
// in one of three lists, free, partial, and full. Allocations are made
// from slices in the partial list. If a slice becomes full it is
// moved to the full list. If there are no partial slices available
// the next available free slice is moved from the free list into
// the partial list. When memory is freed from the slices they
// move from the full list, into the partial list, and ultimately
// into the free list depending on how many allocations have been
// taken from the slice.
//
// Slices are blocks of memory that have been claimed from the memory
// pool. They have a header which contains some basic state, and
// a list node to allow the slice to be moved into a linked list of
// Slices. The remainder of the Slice is divided into rows of memory
// that can be allocated to an application. The Slice contains
// a single linked list of free rows. Allocating a row is as simple
// a removing the list head. Freeing inserts the freed row at
// the list head.
//
// The Slice rows consist of a header and a block of bytes which
// are the memory allocated to the application. The header constists
// of a pointer to the Slice header and a next pointer allowing
// the row to be inserted into the Slices free lists. The header
// pointer is there to eliminate the need to search backwards
// in memory from the row to the slice header when memory is
// being freed (this search can be very slow).
//
// The allocator must be initialised by calling bmalloc_init()
// before any attempts to allocate memory are made. The allocator
// can release all free memory on an emergency basis
// by calling bmalloc_release_memory(). The allocator requires
// periodic garbage collecting to migrate free blocks
// of memory from the Slice free lists, to the Memory Pool, to
// the underlying allocator - by calling bmalloc_garbage_collect().
//

// The allocator is by its nature quite space inefficient.
// defining SPACE_EFFICIENT will swap some 64 bit pointers
// inside the Slices for 32 bit offsets, and some additional
// pointer arithmetic. Better space efficiency for lower
// performance.
//
// It seems that the performance penalty is about 4% on a
// user space instrumentation tool, apparently within the
// margin for error when running iozone.
#define SPACE_EFFICIENT 1

// Place the allocator in thread safe mode. If you have an application
// where the allocator does not have to be thread safe then removing
// the mutexes will improve the allocator performance by about 30%.
#define THREAD_SAFE 1

// Enable/Disable fine grained locking strategy in the memory
// The performance benefits of this are not measurable.
#define MEM_POOL_FINE_LOCKING 1

// Enables finer grained locking in the slice allocator
// Performance change not measurable.
#define SLICE_ALLOCATOR_FINE_LOCKING 1

// Borrow an idea from the linux kernel SLUB allocator,
// that is have the Slice Allocator simply forget about
// full slices. They are "found" again when a free
// occurs from the full slice, and added to the 
// partial list again. This save a small amount
// of list processing overhead and storage space.
// (Performance difference is probably purely academic)
//
// You will want to enable this if hunting memory leaks.
//#define SLICE_ALLOCATOR_TRACK_FULL_SLABS 1

#ifdef _KERNEL
#define IN_KERNEL 1
#else
#undef IN_KERNEL
#endif

#include <stdint.h>
#include <string.h>

#ifdef IN_KERNEL
#include <sys/list.h>
#else
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include "list.h"
#include "pthread.h"
#endif

// ============================================================================================
// Base Types
// ============================================================================================

typedef uint64_t sa_size_t;
typedef uint8_t sa_byte_t;
typedef uint8_t sa_bool_t;
typedef uint64_t sa_hrtime_t;
typedef uint32_t large_offset_t;
typedef uint16_t small_offset_t;

#ifdef IN_KERNEL
typedef kmutex_t osif_mutex;
#else
typedef pthread_mutex_t osif_mutex;
#endif

#define SA_TRUE (sa_bool_t)1;
#define SA_FALSE (sa_bool_t)0;

#ifdef IN_KERNEL
#define SA_NSEC_PER_SEC  NSEC_PER_SEC
#else
#define SA_NSEC_PER_SEC  1000000000ULL
#endif

#define SA_NSEC_PER_USEC  1000;

typedef struct {
    sa_hrtime_t time_freed;
    list_node_t memory_block_link_node;
} memory_block_t;

typedef struct {
    sa_size_t  count;
    list_t     blocks;
    osif_mutex mutex;
} memory_block_list_t;

typedef struct {
    memory_block_list_t large_blocks;
} memory_pool_t;

// Make sure this structure remains a 
// multiple of 8 bytes to prevent
// problems with alignment of memory
// allocated to the caller.
typedef struct allocatable_row {
#ifdef SPACE_EFFICIENT
    large_offset_t slice_offset;
    large_offset_t next_offset;
#else
    struct slice* slice;
    struct allocatable_row* next;
#endif
} allocatable_row_t;

typedef struct slice {
    allocatable_row_t* free_list;
    sa_size_t    allocation_size;
    sa_size_t    num_allocations;
    sa_size_t    alloc_count;
    sa_hrtime_t  time_freed;
    list_node_t  slice_link_node;
} slice_t;

typedef struct {
    list_t       free;
    list_t       partial;
    
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
    list_t       full;
#endif

    sa_size_t    max_alloc_size;       /* Max alloc size for slice */
    sa_size_t    num_allocs_per_slice; /* Number of rows to be allocated in the Slices */
    osif_mutex   mutex;
} slice_allocator_t;

// ============================================================================================
// Constants
// ============================================================================================

// Low water mark for amount of memory to be retained in the block lists
// when garbage collecting.
const sa_size_t RETAIN_MEMORY_SIZE = 10 * 1024 * 1024;   // bytes

// Block size and free block count for the large_blocks list
// NOTE: This value must be larger than the largets
//       configured Slice Allocator max_allocation_size
const sa_size_t LARGE_BLOCK_SIZE = (128 * 1024) + 4096;  // bytes
const sa_size_t LARGE_FREE_MEMORY_BLOCK_COUNT =
RETAIN_MEMORY_SIZE / LARGE_BLOCK_SIZE;

// Block size and free block count for the small_blocks list
const sa_size_t SMALL_BLOCK_SIZE = 64 * 1024;            // bytes
const sa_size_t SMALL_FREE_MEMORY_BLOCK_COUNT =
RETAIN_MEMORY_SIZE / SMALL_BLOCK_SIZE;

// Slices of memory that have no allocations in them will
// be returned to the memory pool for use by other slice
// allocators. SA_MAX_POOL_FREE_MEM_AGE after being placed
// in the pool, if not claimed by a slice, the memory
// is released to the underlying alloctor.
const sa_hrtime_t SA_MAX_POOL_FREE_MEM_AGE = 120 * SA_NSEC_PER_SEC;

// Once there are no remaining allocations from a slice of memory
// the Slice Allocator places the slice on its free list.
// If no allocations are made from the slice within
// SA_MAX_SLICE_FREE_MEM_AGE seconds, the slice is
// released to the memory pool for allocation
// by another slice allocator or release to the underlying allocator.
const sa_hrtime_t SA_MAX_SLICE_FREE_MEM_AGE = 5 * SA_NSEC_PER_SEC;

// Sizes of various slices that are used by zfs
// This table started out as a naive ^2 table,
// and more slice sizes were added as a result
// of instrumenting allocations. In terms of allocator
// efficiency its beneficial to closely match allocation
// requests to slice size. Slice size % 8 must = 0
// or the allocator will allocate non-8 byte alligned
// memory.

const sa_size_t ALLOCATOR_SLICE_SIZES[] = {
    32,
    64,
    96,
    128,
    160,
    256,
    320,
    384,
    448,
    512,
    856,
    944,
    1024,
    1920,
    2048,
    4096,
    6144,
    7168,
    8192,
    12288,
    16384,
    32768,
    36864,
    40960,
    49152,
    57344,
    65536,
    81920,
    90112,
    98304,
    106496,
    114688,
    122880,
    131072
};

const long NUM_ALLOCATORS = sizeof(ALLOCATOR_SLICE_SIZES)/sizeof(sa_size_t);

// ============================================================================================
// Variables
// ============================================================================================

// Blocks of memory allocated from the underlying allocator, but not
// yet used as a slice by one of the slice allocators.
memory_pool_t pool;

// Collection of slice allocators
slice_allocator_t* allocators = 0;

// Allocation size to slice allocator lookup table
slice_allocator_t** allocator_lookup_table = 0;

// ============================================================================================
// OS Compatability interface
// ============================================================================================

#ifdef IN_KERNEL

extern vm_map_t kernel_map;

extern kern_return_t kernel_memory_allocate(vm_map_t       map,
                                            vm_offset_t   *addrp,
                                            vm_size_t      size,
                                            vm_offset_t    mask,
                                            int            flags);

extern void kmem_free(vm_map_t map, vm_offset_t addr, vm_size_t size);

extern int              vm_pool_low(void);

#endif

static inline void* osif_malloc(sa_size_t size)
{
#ifdef IN_KERNEL
    
    void *tr;
    kern_return_t kr;
    
    kr = kernel_memory_allocate(
                                kernel_map,
                                &tr,
                                size,
                                0,
                                0);
    
    if (kr == KERN_SUCCESS) {
        return tr;
    } else {
        return NULL;
    }
    
#else
    
    return (void*)malloc(size);
    
#endif
}

static inline void osif_free(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    kmem_free(kernel_map, buf, size);
#else
    free(buf);
#endif
}

static inline void osif_zero_memory(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    bzero(buf, size);
#else
    memset(buf, 0, size);
#endif
}

static inline void osif_mutex_init(osif_mutex* mutex)
{
#ifdef THREAD_SAFE
#ifdef IN_KERNEL
    mutex_init(mutex, "bmalloc", MUTEX_DEFAULT, NULL);
#else
    pthread_mutex_init(mutex, 0);
#endif
#endif
}

static inline void osif_mutex_enter(osif_mutex* mutex)
{
#ifdef THREAD_SAFE
#ifdef IN_KERNEL
    mutex_enter(mutex);
#else
    pthread_mutex_lock(mutex);
#endif
#endif
}

static inline void osif_mutex_exit(osif_mutex* mutex)
{
#ifdef THREAD_SAFE
#ifdef IN_KERNEL
    mutex_exit(mutex);
#else
    pthread_mutex_unlock(mutex);
#endif
#endif
}

static inline void osif_mutex_destroy(osif_mutex* mutex)
{
#ifdef THREAD_SAFE
#ifdef IN_KERNEL
    mutex_destroy(mutex);
#else
    pthread_mutex_destroy(mutex);
#endif
#endif
}

static inline sa_hrtime_t osif_gethrtime()
{
#ifdef IN_KERNEL
    return gethrtime();
#else
    struct timeval t;
    struct timezone zone;
    
    gettimeofday(&t, &zone);
    
    return (t.tv_sec * 1000000000) + (t.tv_usec * 1000);
#endif
}

// ============================================================================================
// Memory Pool
// ============================================================================================

void memory_pool_block_list_init(memory_block_list_t* list)
{
    list->count = 0;
    osif_mutex_init(&list->mutex);
    list_create(&list->blocks, sizeof(memory_block_t),
                offsetof(memory_block_t, memory_block_link_node));
}

void memory_pool_block_list_fini(memory_block_list_t* list)
{
    list_destroy(&list->blocks);
    // FIXME - despite the & this still panics.
    //osif_mutex_destroy(&list->mutex);
}

void memory_pool_init()
{
    memory_pool_block_list_init(&pool.large_blocks);
}

static inline sa_size_t memory_pool_claim_size()
{
    return LARGE_BLOCK_SIZE;
}

void memory_pool_release_memory()
{
    memory_block_list_t* list = &pool.large_blocks;

    osif_mutex_enter(&list->mutex);
    
    while(!list_is_empty(&list->blocks)) {
        memory_block_t* block = list_head(&list->blocks);
        list_remove_head(&list->blocks);
        list->count--;
        
#ifdef MEM_POOL_FINE_LOCKING
        osif_mutex_exit(&list->mutex);
#endif
        
        osif_free(block, LARGE_BLOCK_SIZE);
        
#ifdef MEM_POOL_FINE_LOCKING
        osif_mutex_enter(&list->mutex);
#endif
    }
    
    osif_mutex_exit(&list->mutex);
}

void memory_pool_garbage_collect()
{
    memory_block_list_t* list = &pool.large_blocks;

    osif_mutex_enter(&list->mutex);
    
    sa_hrtime_t stale_time = osif_gethrtime() - SA_MAX_POOL_FREE_MEM_AGE;
    int done = 0;
    
    do {
        if (list->count <= LARGE_FREE_MEMORY_BLOCK_COUNT) {
            done = 1;
        } else {
            memory_block_t* block = list_tail(&list->blocks);
            if(block->time_freed <= stale_time) {
                list_remove_tail(&list->blocks);
                list->count--;
                
#ifdef MEM_POOL_FINE_LOCKING
                osif_mutex_exit(&list->mutex);
#endif
                
                osif_free(block, LARGE_BLOCK_SIZE);
                
#ifdef MEM_POOL_FINE_LOCKING
                osif_mutex_enter(&list->mutex);
#endif
            } else {
                done = 1;
            }
        }
    } while (!done);
    
    osif_mutex_exit(&list->mutex);
}

void* memory_pool_claim()
{
    memory_block_t* block = 0;
    memory_block_list_t* list = &pool.large_blocks;
    
    osif_mutex_enter(&list->mutex);
    
    if (!list_is_empty(&list->blocks)) {
        block = list_tail(&list->blocks);
        list_remove_tail(&list->blocks);
        list->count--;
    }
    
    osif_mutex_exit(&list->mutex);
    
    if(!block) {
        block = (memory_block_t*)osif_malloc(LARGE_BLOCK_SIZE);
    }
    
    return (void*)block;
}

void memory_pool_return(void* memory)
{
    memory_block_t* block = (memory_block_t*)(memory);
    memory_block_list_t* list = &pool.large_blocks;
    
    list_link_init(&block->memory_block_link_node);
    block->time_freed = osif_gethrtime();
    
    osif_mutex_enter(&list->mutex);
    list_insert_head(&list->blocks, block);
    list->count++;
    osif_mutex_exit(&list->mutex);
}

void memory_pool_fini()
{
    memory_pool_release_memory();
    memory_pool_block_list_fini(&pool.large_blocks);
}

// ============================================================================================
// Large Slice
// ============================================================================================

static inline void set_slice(allocatable_row_t* row, slice_t* slice)
{
#ifdef SPACE_EFFICIENT
    row->slice_offset = (large_offset_t)((sa_byte_t*)(&(row->slice_offset)) - (sa_byte_t*)(slice));
#else
    row->slice = slice;
#endif
}

static inline slice_t* get_slice(allocatable_row_t* row)
{
#ifdef SPACE_EFFICIENT
    return (slice_t*)((sa_byte_t*)(&row->slice_offset) - row->slice_offset);
#else
    return row->slice;
#endif
}

static inline void set_next(allocatable_row_t* row, slice_t* base_addr, allocatable_row_t* next)
{
#ifdef SPACE_EFFICIENT
    if(next) {
        row->next_offset = (large_offset_t)((sa_byte_t*)(next) - (sa_byte_t*)(base_addr));
    } else {
        row->next_offset = 0;
    }
#else
    row->next = next;
#endif
    
}

static inline allocatable_row_t* get_next(allocatable_row_t* row, slice_t* base_addr)
{
#ifdef SPACE_EFFICIENT
    if(row->next_offset) {
        return (allocatable_row_t*)((sa_byte_t*)(base_addr) + row->next_offset);
    } else {
        return 0;
    }
#else
    return row->next;
#endif
}

allocatable_row_t* slice_get_row_address(slice_t* slice, int index)
{
    sa_byte_t* p = (sa_byte_t*)slice;
    p = p + sizeof(slice_t) + (index * (slice->allocation_size + sizeof(allocatable_row_t)));
    
    return (allocatable_row_t*)(p);
}

void slice_insert_free_row(slice_t* slice, allocatable_row_t* row)
{
    allocatable_row_t* curr_free = slice->free_list;
    slice->free_list = row;
    set_next(slice->free_list, slice, curr_free);
}

allocatable_row_t* slice_get_row(slice_t* slice)
{
    if (slice->free_list == 0) {
        return 0;
    } else {
        allocatable_row_t* row = slice->free_list;
        slice->free_list = get_next(row, slice);
        return row;
    }
}

void slice_init(slice_t* slice,
                sa_size_t allocation_size,
                sa_size_t num_allocations)
{
    // Copy parameters
    //osif_zero_memory(slice, sizeof(slice_t));
    
    list_link_init(&slice->slice_link_node);
    slice->free_list = 0;
    slice->alloc_count = 0;
    slice->num_allocations = num_allocations;
    slice->allocation_size = allocation_size;
    
    for(int i=0; i < slice->num_allocations; i++) {
        allocatable_row_t* row = slice_get_row_address(slice, i);
        set_slice(row, slice);
        slice_insert_free_row(slice, row);
    }
    
}

static inline int slice_is_full(slice_t* slice)
{
    return (slice->free_list == 0);
}

static inline int slice_is_empty(slice_t* slice)
{
    return (slice->alloc_count == 0);
}

void* slice_alloc(slice_t* slice, sa_size_t size)
{
    allocatable_row_t* row = slice_get_row(slice);
    if(row) {
        slice->alloc_count++;
        row++;
        return (void*)(row);
    } else {
        return (void*)0;
    }
}

static inline void slice_free_row(slice_t* slice, allocatable_row_t* row)
{
    slice->alloc_count--;
    slice_insert_free_row(slice, row);
}

static inline slice_t* slice_get_slice_from_row(void* buf, allocatable_row_t** row)
{
    (*row) = (allocatable_row_t*)(buf);
    (*row)--;
    return get_slice(*row);
}

// ============================================================================================
// Slice Allocator
// ============================================================================================

void slice_allocator_empty_list(slice_allocator_t* sa, list_t* list)
{
    osif_mutex_enter(&sa->mutex);
    
    while(!list_is_empty(list)) {
        slice_t* slice = list_head(list);
        list_remove_head(list);

#ifdef SLICE_ALLOCATOR_FINE_LOCKING
        osif_mutex_exit(&sa->mutex);
#endif
        memory_pool_return(slice);

#ifdef SLICE_ALLOCATOR_FINE_LOCKING
        osif_mutex_enter(&sa->mutex);
#endif
}
    
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_init(slice_allocator_t* sa, sa_size_t max_alloc_size)
{
    osif_zero_memory(sa, sizeof(slice_allocator_t));
    osif_mutex_init(&sa->mutex);
    
    // Create lists for tracking the state of the slices as memory is allocated

    list_create(&sa->free, sizeof(slice_t), offsetof(slice_t, slice_link_node));
    list_create(&sa->partial, sizeof(slice_t), offsetof(slice_t, slice_link_node));
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
    list_create(&sa->full, sizeof(slice_t), offsetof(slice_t, slice_link_node));
#endif
    
    sa->max_alloc_size = max_alloc_size;
    sa->num_allocs_per_slice = (memory_pool_claim_size() - sizeof(slice_t))/(sizeof(allocatable_row_t) + max_alloc_size);
}

void slice_allocator_fini(slice_allocator_t* sa)
{
    slice_allocator_empty_list(sa, &sa->free);
    slice_allocator_empty_list(sa, &sa->partial);
   
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
    slice_allocator_empty_list(sa, &sa->full);
#endif
    
    list_destroy(&sa->free);
    list_destroy(&sa->partial);
#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
    list_destroy(&sa->full);
#endif
}

sa_size_t slice_allocator_get_allocation_size(slice_allocator_t* sa)
{
    return sa->max_alloc_size;
}

void* slice_allocator_alloc(slice_allocator_t* sa, sa_size_t size)
{
    slice_t* slice = 0;
    
    osif_mutex_enter(&sa->mutex);
    
    // Locate a slice with residual capacity, first check for a partially
    // full slice, use some more of its capacity. Next, look to see if we
    // have a ready to go empty slice. If not finally go to underlying
    // allocator for a new slice.
    if(!list_is_empty(&sa->partial)) {
        slice = list_head(&sa->partial);
    } else if (!list_is_empty(&sa->free)) {
        slice = list_tail(&sa->free);
        list_remove_tail(&sa->free);
        list_insert_head(&sa->partial, slice);
    } else {

#ifdef SLICE_ALLOCATOR_FINE_LOCKING
        osif_mutex_exit(&sa->mutex);
#endif
        
        slice = (slice_t*)memory_pool_claim();
        slice_init(slice, sa->max_alloc_size, sa->num_allocs_per_slice);

#ifdef SLICE_ALLOCATOR_FINE_LOCKING
        osif_mutex_enter(&sa->mutex);
#endif
        
        list_insert_head(&sa->partial, slice);
    }
    
    // Grab memory from the slice
    void *p = slice_alloc(slice, size);
    
    // Check to see if the slice buffer has become
    // full. If it has, then move it into the
    // full list so that we no longer keep
    // trying to allocate from it.
    if(slice_is_full(slice)) {
        list_remove(&sa->partial, slice);

#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
        list_insert_head(&sa->full, slice);
#endif
    }
    
    osif_mutex_exit(&sa->mutex);
    
    return p;
}

void slice_allocator_free(slice_allocator_t* sa, void* buf)
{
    osif_mutex_enter(&sa->mutex);
    
    // Locate the slice buffer that the allocation lives within
    slice_t* slice;
    allocatable_row_t* row;
    slice = slice_get_slice_from_row(buf, &row);
    
    // If the slice was previously full remove it from the free list
    // and place in the available list
    if(slice_is_full(slice)) {

#ifdef SLICE_ALLOCATOR_TRACK_FULL_SLABS
        list_remove(&sa->full, slice);
#endif
        
        list_insert_head(&sa->partial, slice);
    }
    
    slice_free_row(slice, row);
    
    // Finally migrate to the free list if needed.
    if(slice_is_empty(slice)) {
        list_remove(&sa->partial, slice);
        slice->time_freed = osif_gethrtime();
        list_insert_head(&sa->free, slice);
    }
    
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_release_memory(slice_allocator_t* sa)
{
    slice_allocator_empty_list(sa, &sa->free);
}

void slice_allocator_garbage_collect(slice_allocator_t* sa)
{
    osif_mutex_enter(&sa->mutex);
    
    sa_hrtime_t stale_time = osif_gethrtime() - SA_MAX_SLICE_FREE_MEM_AGE;
    
    int done = 0;
    
    do {
        if (!list_is_empty(&sa->free)) {
            slice_t* slice = list_tail(&sa->free);
            if(slice->time_freed <= stale_time) {
                list_remove_tail(&sa->free);
                
#ifdef SLICE_ALLOCATOR_FINE_LOCKING
                osif_mutex_exit(&sa->mutex);
#endif
                
                memory_pool_return(slice);
                
#ifdef SLICE_ALLOCATOR_FINE_LOCKING
                osif_mutex_enter(&sa->mutex);
#endif
            } else {
                done = 1;
            }
        } else {
            done = 1;
        }
    } while (!done);
    
    osif_mutex_exit(&sa->mutex);
}

// ============================================================================================
// Public Interface
// ============================================================================================

static inline sa_size_t bmalloc_allocator_array_size()
{
    return NUM_ALLOCATORS * sizeof(slice_allocator_t);
}

slice_allocator_t* bmalloc_allocator_for_size(sa_size_t size)
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        if (slice_allocator_get_allocation_size(&allocators[i]) >= size) {
            return &allocators[i];
        }
    }
    
    return (void*)0;
}

static inline sa_size_t bmalloc_allocator_lookup_table_size(sa_size_t max_allocation_size)
{
    return max_allocation_size * sizeof(slice_allocator_t*);
}

void bmalloc_init()
{
    printf("[SPL] bmalloc slice allocator initialised\n");

    sa_size_t max_allocation_size = ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1];
    
    // Initialise the memory pool
    memory_pool_init();
    
    // Create the slice allocators
    sa_size_t array_size = NUM_ALLOCATORS * sizeof(slice_allocator_t);
    allocators = (slice_allocator_t*)osif_malloc(array_size);
    osif_zero_memory(allocators, array_size);
    
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_init(&allocators[i], ALLOCATOR_SLICE_SIZES[i]);
    }
    
    // Create the allocator lookup array
    allocator_lookup_table = osif_malloc(bmalloc_allocator_lookup_table_size(ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));
    
    for(int i=1; i<=max_allocation_size; i++) {
        allocator_lookup_table[i-1] = bmalloc_allocator_for_size(i);
    }
}

void bmalloc_fini()
{
    // Clean up the allocators
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_fini(&allocators[i]);
    }
    
    // Free local resources
    osif_free(allocators, bmalloc_allocator_array_size());
    osif_free(allocator_lookup_table,
              bmalloc_allocator_lookup_table_size(ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));
    
    // Clean up the memory pool
    memory_pool_fini();
}

void* bmalloc(sa_size_t size)
{
    void* p = 0;
    
    if(size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
        p = slice_allocator_alloc(allocator_lookup_table[size-1], size);
    } else {
        p = osif_malloc(size);
    }
    
    return p;
}

void bfree(void* buf, sa_size_t size)
{
    if(size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
        slice_allocator_free(allocator_lookup_table[size-1], buf);
    } else {
        osif_free(buf, size);
    }
}

void bmalloc_release_memory()
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_release_memory(&allocators[i]);
    }
    
    memory_pool_release_memory();
}

void bmalloc_garbage_collect()
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_garbage_collect(&allocators[i]);
    }
    
    memory_pool_garbage_collect();
}

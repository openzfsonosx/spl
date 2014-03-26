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

#include "slice_allocator.h"
#include "slice.h"
#include "osif.h"
#include "memory_pool.h"

// Sizes of various slices that are used by zfs
// This table started out as a naive ^2 table,
// and more slice sizes were added as a result
// of instrumenting allocations. In terms of allocator
// efficiency its beneficial to closely match allocation
// requests to slice size.

    // These buckets are all serviced using the "small allocator"
sa_size_t allocator_params[] = {

    16,
    32,
    48, 
    64,
    80,
    96,
    128,
    144,
    160,
    196,
    224,
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

long num_allocators = sizeof(allocator_params)/sizeof(sa_size_t);

SliceAllocator* allocators = 0;

SliceAllocator** allocator_lookup_table = 0;
sa_size_t max_allocation_size = 0;
int initalised = 0;

sa_size_t bmalloc_allocator_array_size()
{
    return num_allocators * sizeof(struct SliceAllocator);
}

SliceAllocator* bmalloc_allocator_for_size(sa_size_t size)
{
    for(int i=0; i<num_allocators; i++) {
      if (slice_allocator_get_allocation_size(&allocators[i]) >= size) {
        return &allocators[i];
      }
    }
    
    return (void*)0;
}

sa_size_t bmalloc_allocator_lookup_table_size()
{
    return max_allocation_size * sizeof(void*);
}

void bmalloc_init()
{
    printf("[SPL] bmalloc slice allocator initialised\n");

    max_allocation_size = allocator_params[num_allocators - 1];

    // Initialise the memory pool
    memory_pool_init();
    
    // Create the slice allocators
    sa_size_t array_size = bmalloc_allocator_array_size();
    allocators = (SliceAllocator*)osif_malloc(array_size);
    osif_zero_memory(allocators, array_size);
    
    for(int i=0; i<num_allocators; i++) {
        slice_allocator_init(&allocators[i], allocator_params[i]);
    }
    
    // Create the allocator lookup array
    allocator_lookup_table = osif_malloc(bmalloc_allocator_lookup_table_size());
    
    for(int i=1; i<=max_allocation_size; i++) {
        allocator_lookup_table[i-1] = bmalloc_allocator_for_size(i);
    }
    
    initalised = 1;
}

void bmalloc_fini()
{
    // Clean up the allocators
    for(int i=0; i<num_allocators; i++) {
        slice_allocator_fini(&allocators[i]);
    }
    
    // Free local resources
    osif_free(allocators, bmalloc_allocator_array_size());
    osif_free(allocator_lookup_table, bmalloc_allocator_lookup_table_size());
    
    // Clean up the memory pool
    memory_pool_fini();
    
    initalised = 0;
}

void* bmalloc(sa_size_t size)
{
    void* p = 0;
    
    if(size <= max_allocation_size) {
        p = slice_allocator_alloc(allocator_lookup_table[size-1], size);
    } else {
        p = osif_malloc(size);
    }
    
    return p;
}

void bfree(void* buf, sa_size_t size)
{
    if(size <= max_allocation_size) {
        slice_allocator_free(allocator_lookup_table[size-1], buf);
    } else {
        osif_free(buf, size);
    }
}

void bmalloc_release_memory()
{
    for(int i=0; i<num_allocators; i++) {
        slice_allocator_release_memory(&allocators[i]);
    }

    memory_pool_release_memory();
}

void bmalloc_garbage_collect()
{
    for(int i=0; i<num_allocators; i++) {
        slice_allocator_garbage_collect(&allocators[i]);
    }

    memory_pool_garbage_collect();
}

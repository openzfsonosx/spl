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

#include <string.h>

const hrtime_t SA_MAX_FREE_MEM_AGE = 30 * NSEC_PER_SEC; 

Slice* slice_allocator_create_slice(SliceAllocator* sa)
{
    Slice* slice = (Slice*)memory_pool_claim();
    slice_init(slice, sa->max_alloc_size, sa->num_allocs_per_buffer);
    
    return slice;
}

void slice_allocator_destroy_slice(SliceAllocator*sa, Slice* slice)
{
    memory_pool_return(slice);
}

void slice_allocator_empty_list(SliceAllocator* sa, Slice_List* list)
{
    while(slice_list_size(list)) {
        Slice* slice = slice_list_front(list);
        slice_list_remove_front(list);
        slice_allocator_destroy_slice(sa, slice);
    }
}

void slice_allocator_init(SliceAllocator* sa, sa_size_t max_alloc_size)
{
    osif_zero_memory(sa, sizeof(struct SliceAllocator));
    
    slice_list_init(&sa->free);
    slice_list_init(&sa->partial);
    slice_list_init(&sa->full);
    
    // Calculate the number of allocations that will fit into a standard
    // memory_pool block
    sa_size_t num_allocations_per_slice =
        (memory_pool_claim_size() - sizeof(struct SliceAllocator))/(sizeof(struct AllocatableRow) + max_alloc_size);
    
    sa->max_alloc_size = max_alloc_size;
    sa->num_allocs_per_buffer = num_allocations_per_slice;

    osif_mutex_init(&sa->mutex);
}

void slice_allocator_fini(SliceAllocator* sa)
{
    slice_allocator_empty_list(sa, &sa->free);
    slice_allocator_empty_list(sa, &sa->partial);
    slice_allocator_empty_list(sa, &sa->full);
    
    slice_list_fini(&sa->free);
    slice_list_fini(&sa->partial);
    slice_list_fini(&sa->full);
}

sa_size_t slice_allocator_get_allocation_size(SliceAllocator* sa)
{
    return sa->max_alloc_size;
}

void* slice_allocator_alloc(SliceAllocator* sa, sa_size_t size)
{
    Slice* slice = 0;
    
    osif_mutex_enter(&sa->mutex);
    
    // Locate a Slice with residual capacity, first check for a partially
    // full slice, use some more of its capacity. Next, look to see if we
    // have a ready to go empty slice. If not finally go to underlying
    // allocator for a new slice.
    if(slice_list_size(&sa->partial)) {
        slice = slice_list_front(&sa->partial);
    } else if (slice_list_size(&sa->free)) {
        slice = slice_list_tail(&sa->free);
        slice_list_remove_tail(&sa->free);
        slice_list_push_front(&sa->partial, slice);
    } else {
        slice = slice_allocator_create_slice(sa);
        slice_list_push_front(&sa->partial, slice);
    }
    
    // FIXME: we might crash here if slice_allocator_create_slice returns null.
    
    // Grab memory from the slice
    void *p = slice_alloc(slice, size);
    
    // Check to see if the slice buffer has become
    // full. If it has, then move it into the
    // full list so that we no longer keep
    // trying to allocate from it.
    if(slice_is_full(slice)) {
        slice_list_remove(&sa->partial, slice);
        slice_list_push_front(&sa->full, slice);
    }
    
    osif_mutex_exit(&sa->mutex);
    
    return p;
}

void slice_allocator_free(SliceAllocator* sa, void* buf)
{
    osif_mutex_enter(&sa->mutex);
    
    // Locate the slice buffer that the allocation lives within
    Slice* slice = slice_get_owner(buf);

    // If the slice was previously full remove it from the free list
    // and place in the available list
    if(slice_is_full(slice)) {
        slice_list_remove(&sa->full, slice);
        slice_list_push_front(&sa->partial, slice);
    }
    
    slice_free(slice, buf);
    
    if(slice_is_empty(slice)) {
        slice_list_remove(&sa->partial, slice);
        slice->time_freed = gethrtime();
        slice_list_push_front(&sa->free, slice);
    }
    
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_release_memory(SliceAllocator* sa)
{
    osif_mutex_enter(&sa->mutex);
    slice_allocator_empty_list(sa, &sa->free);
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_garbage_collect(SliceAllocator* sa)
{
    osif_mutex_enter(&sa->mutex);

    hrtime_t stale_time = gethrtime() - SA_MAX_FREE_MEM_AGE;

    int done = 0;

    do {
        sa_size_t free_slices = slice_list_size(&sa->free);
        if (free_slices) {
            Slice* slice = slice_list_tail(&sa->free);
            if(slice->time_freed <= stale_time) {
                slice_list_remove_tail(&sa->free);
                slice_allocator_destroy_slice(sa, slice);
            } else {
                done = 1;
            }
        } else {
            done = 1;
        }
    } while (!done);

    osif_mutex_exit(&sa->mutex);
}


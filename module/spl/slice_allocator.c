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

#include <string.h>

// If a memory is released and the slice allocator contains
// more than this number of bytes of allocated memory then
// start returning memory to the OS.
const sa_size_t SLICE_ALLOCATOR_RELEASE_MEMORY_THRESHOLD = 1024*1024; // bytes

Slice* slice_allocator_create_slice(SliceAllocator* sa)
{
    sa_size_t size = slice_calculate_size(sa->max_alloc_size, sa->num_allocs_per_buffer);
    Slice* slice = (Slice*)osif_malloc(size);
    slice_init(slice, sa->max_alloc_size, sa->num_allocs_per_buffer);
    
    return slice;
}

void slice_allocator_destroy_slice(SliceAllocator*sa, Slice* slice)
{
    sa_size_t size = slice_calculate_size(sa->max_alloc_size, sa->num_allocs_per_buffer);
    osif_free(slice, size);
}

void slice_allocator_init(SliceAllocator* sa, sa_size_t max_alloc_size, sa_size_t num_allocs_per_buffer)
{
    osif_zero_memory(sa, sizeof(struct SliceAllocator));
    sa->available = 0;
    sa->full = 0;
    sa->max_alloc_size = max_alloc_size;
    sa->num_allocs_per_buffer = num_allocs_per_buffer;
    sa->num_slices = 0;
    osif_mutex_init(&sa->mutex);
}

void slice_allocator_fini(SliceAllocator* sa)
{
    Slice* next = sa->available;
    
    while(next) {
        Slice* slice = next;
        next = slice->next;
        slice_allocator_destroy_slice(sa, slice);
    }
    
    next = sa->full;
    while(next) {
        Slice* slice = next;
        next = slice->next;
        slice_allocator_destroy_slice(sa, slice);
    }
    
    sa->full = 0;
    sa->available = 0;
    sa->num_slices = 0;
}

sa_size_t slice_allocator_get_allocation_size(SliceAllocator* sa)
{
    return sa->max_alloc_size;
}


void slice_allocator_insert_available_slice(SliceAllocator* sa,
                                            Slice* slice)
{
    Slice* curr_available = sa->available;
    
    sa->available = slice;
    sa->available->next = curr_available;
    if(curr_available) {
        curr_available->prev = sa->available;
    }
    sa->available->prev = 0;
}

void slice_allocator_remove_available_slice(SliceAllocator* sa,
                                            Slice* slice)
{
    if(sa->available == slice) {
        sa->available = slice->next;
        
        if(sa->available) {
            sa->available->prev = 0;
        }
    } else {
        Slice* before = slice->prev;
        Slice* after = slice->next;
        
        if(before) {
            before->next = after;
        }
        
        if(after) {
            after->prev = before;
        }
    }
    
    slice->prev = 0;
    slice->next = 0;
}

void slice_allocator_insert_full_slice(SliceAllocator* sa, Slice* slice)
{
    Slice* curr_full = sa->full;
    
    sa->full = slice;
    sa->full->next = curr_full;
    if(curr_full) {
        curr_full->prev = sa->full;
    }
    sa->full->prev = 0;
}

void slice_allocator_remove_full_slice(SliceAllocator* sa,
                                       Slice* slice)
{
    if(sa->full == slice) {
        sa->full = slice->next;
        
        if(sa->full) {
            sa->full->prev = 0;
        }
    } else {
        Slice* before = slice->prev;
        Slice* after = slice->next;
        
        if(before) {
            before->next = after;
        }
        
        if(after) {
            after->prev = before;
        }
    }
    
    slice->prev = 0;
    slice->next = 0;
}

void* slice_allocator_alloc(SliceAllocator* sa, sa_size_t size)
{
    Slice* slice = 0;
    
    osif_mutex_enter(&sa->mutex);
    
    // Locate a Slice with residual capacity
    if(sa->available == 0) {
        slice = slice_allocator_create_slice(sa);
        slice_allocator_insert_available_slice(sa, slice);
        sa->num_slices++;
    } else {
        slice = sa->available;
    }
    
    // Grab memory from the slice
    void *p = slice_alloc(slice, size);
    
    // Check to see if the slice buffer has become
    // full. If it has, then move it into the
    // full list so that we no longer keep
    // trying to allocate from it.
    if(slice_is_full(slice)) {
        slice_allocator_remove_available_slice(sa, slice);
        slice_allocator_insert_full_slice(sa, slice);
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
        slice_allocator_remove_full_slice(sa, slice);
        slice_allocator_insert_available_slice(sa, slice);
    }
    
    slice_free(slice, buf);
    
    // If appropriate, return memory to the underlying allocator
    int need_to_release = 0;
    if(slice_is_empty(slice)) {
        
        if(osif_memory_pressure()) {
            need_to_release = 1;
        } else {
            sa_size_t size = slice_calculate_size(sa->max_alloc_size, sa->num_allocs_per_buffer);
            if(sa->num_slices * size > SLICE_ALLOCATOR_RELEASE_MEMORY_THRESHOLD) {
                need_to_release = 1;
            }
        }
        
        if(need_to_release) {
            slice_allocator_remove_available_slice(sa, slice);
            slice_allocator_destroy_slice(sa, slice);
            sa->num_slices--;
        }
    }
    
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_release_memory(SliceAllocator* sa)
{
    // Unlike the memory release strategy in _free,
    // this function locates all empty slices and returns
    // the memory to the underlying allocator as the
    // underlying allocator is reporting memory pressure.
    osif_mutex_enter(&sa->mutex);

    Slice* next = sa->available;
    
    while(next) {
        Slice* slice = next;
        next = slice->next;
        if(slice_is_empty(slice)) {
            slice_allocator_remove_available_slice(sa, slice);
            slice_allocator_destroy_slice(sa, slice);
            sa->num_slices--;
        }
    }

    osif_mutex_exit(&sa->mutex);
}


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

#include "slice.h"
#include "osif.h"

sa_size_t slice_calculate_size(sa_size_t allocation_size, sa_size_t num_allocations)
{
    return sizeof(struct Slice) +
    (num_allocations * (sizeof(struct AllocatableRow) + allocation_size));
}

sa_size_t slice_row_size_bytes(Slice* slice)
{
    return slice->allocation_size + sizeof(struct AllocatableRow);
}

AllocatableRow* slice_get_row_address(Slice* slice, int index)
{
    char* p = (char*)slice;
    p = p + sizeof(struct Slice) + (index * slice_row_size_bytes(slice));
    
    return (AllocatableRow*)(p);
}

void slice_insert_free_row(Slice* slice, AllocatableRow* row)
{
    AllocatableRow* curr_free = slice->free;
    
    slice->free = row;
    slice->free->prev = 0;
    if(curr_free) {
        curr_free->prev = slice->free;
    }
    slice->free->next = curr_free;
}

AllocatableRow* slice_get_row(Slice* slice)
{
    if (slice->free == 0) {
        // FIXME panic? this is a programming error
        return 0;
    } else {
        AllocatableRow* row = slice->free;
        slice->free = row->next;
        
        if(slice->free) {
            slice->free->prev = 0;
        }
        
        row->next = 0;
        row->prev = 0;
        
        return row;
    }
}

void slice_init(Slice* slice,
                sa_size_t allocation_size,
                sa_size_t num_allocations)
{
    // Copy parameters
    osif_zero_memory(slice, sizeof(struct Slice));
    slice->num_allocations = num_allocations;
    slice->allocation_size = allocation_size;
    slice->alloc_count = 0;
    slice->destroyed = 0;
    
    // Add all rows to the free list. Set pointers to the slice.
    for(int i=0; i < slice->num_allocations; i++) {
        AllocatableRow* row = slice_get_row_address(slice, i);
        row->next = 0;
        row->prev = 0;
        row->owner = slice;
        
        slice_insert_free_row(slice, row);
    }
}

void slice_fini(Slice* slice)
{
    
}

int slice_is_full(Slice* slice)
{
    return (slice->free == 0);
}

int slice_is_empty(Slice* slice)
{
    return (slice->alloc_count == 0);
}

void* slice_alloc(Slice* slice, sa_size_t size)
{
    AllocatableRow* row = slice_get_row(slice);
    if(row) {
        char* p = (char*)(row);
        p = p + sizeof(AllocatableRow);
        slice->alloc_count++;
        return (void*)(p);
    } else {
        return (void*)0;
    }
}

void slice_free(Slice* slice, void* buf)
{
    char* p = (char*)(buf);
    p = p - sizeof(AllocatableRow);
    
    // FIXME - the +/- should probably be conditional on success
    slice->alloc_count--;
    AllocatableRow* row = (AllocatableRow*)(p);
    slice_insert_free_row(slice, row);
}

Slice* slice_get_owner(void* buf)
{
    char* p = (char*)(buf);
    p = p - sizeof(AllocatableRow);
    AllocatableRow* row = (AllocatableRow*)(p);
    return row->owner;
}


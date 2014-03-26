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

#ifndef SLICE_ALLOCATOR_H
#define SLICE_ALLOCATOR_H

#include "osif.h"
#include "slice_list.h"

struct Slice;

typedef struct SliceAllocator {
    Slice_List free;
    Slice_List partial;
    Slice_List full;
    sa_size_t  max_alloc_size;        /*  Max alloc size for slice */
    sa_size_t  num_allocs_per_buffer; /* Number of rows to be allocated in the Slices */
    osif_mutex mutex;
} SliceAllocator;

void slice_allocator_init(SliceAllocator* sa, sa_size_t max_alloc_size);
void slice_allocator_fini(SliceAllocator* sa);

void* slice_allocator_alloc(SliceAllocator* sa, sa_size_t size);
void slice_allocator_free(SliceAllocator* sa, void* buf);

sa_size_t slice_allocator_get_allocation_size(SliceAllocator* sa);
void slice_allocator_release_memory(SliceAllocator* sa);
void slice_allocator_garbage_collect(SliceAllocator* sa);


#endif

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

#include "osif.h"

#ifndef SLICE_H
#define SLICE_H

struct Slice;

// This structure describes the header of an allocatable row within a slice.
// non-allocated rows reside in a doubly linked list of free rows.
// Allocated rows are unlinked as they are of no further interest
// until freed, at which point they are added into the free list again.

// Maybe a better techique would be to host the metadata outside of the user data area,
// with the exeption of a pointer to the metadata in the row.

// Also these three 64 bit points make small allocations seriously expensive.

struct AllocatableRow;
typedef struct AllocatableRow {
    struct Slice*    owner;      // a pointer back to the header for this SliceAllocator
    struct AllocatableRow* prev;       // Links for inclusion into free and allocated lists.
    struct AllocatableRow* next;
} AllocatableRow;

// This stucture describes the header of a slice.
typedef struct Slice {
    struct Slice* prev;          // Doubly linked list of Slices
    struct Slice* next;
    struct AllocatableRow* free; // List of available rows
    sa_size_t allocation_size;
    sa_size_t num_allocations;
    sa_size_t alloc_count;
    sa_size_t destroyed; // FIXME remove
} Slice;

void slice_init(Slice* slice,
                sa_size_t allocation_size,
                sa_size_t num_allocations);

void slice_fini(Slice* slice);

void* slice_alloc(Slice* slice, sa_size_t size);
void slice_free(Slice* slice, void* buf);

int slice_is_full(Slice* slice);
int slice_is_empty(Slice* slice);
sa_size_t slice_calculate_size(sa_size_t allocation_size, sa_size_t num_allocations);
Slice* slice_get_owner(void* buf);

#endif

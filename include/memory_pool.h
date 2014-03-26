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

#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include "osif.h"

struct memory_block;

typedef struct memory_block {
    struct memory_block* next;
    struct memory_block* prev;
    hrtime_t             time_freed;
} memory_block;


void memory_pool_init();
void memory_pool_fini();

sa_size_t memory_pool_claim_size();

void* memory_pool_claim();
void memory_pool_return(void* memory);

void memory_pool_release_memory();
void memory_pool_garbage_collect();



#endif

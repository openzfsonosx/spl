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

#ifndef MEMORY_BLOCK_LIST_H
#define MEMORY_BLOCK_LIST_H

#include "osif.h"

struct memory_block;

typedef struct memory_block_list {
    struct memory_block* head;
    struct memory_block* tail;
    sa_size_t size;
} memory_block_list;

void memory_block_list_init(memory_block_list* list);
void memory_block_list_fini(memory_block_list* list);

void memory_block_list_push_front(memory_block_list* list, struct memory_block* block);
void memory_block_list_push_back(memory_block_list* list, struct memory_block* block);
void memory_block_list_remove(memory_block_list* list, struct memory_block* block);
struct memory_block* memory_block_list_front(memory_block_list* list);
struct memory_block* memory_block_list_tail(memory_block_list* list);
void memory_block_list_remove_front(memory_block_list* list);
void memory_block_list_remove_tail(memory_block_list* list);
sa_size_t memory_block_list_size(memory_block_list* list);


#endif

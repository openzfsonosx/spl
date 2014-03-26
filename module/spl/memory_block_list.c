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

#include "memory_block_list.h"
#include "memory_pool.h"


void memory_block_list_init(memory_block_list* list)
{
    list->tail = 0;
    list->head = 0;
    list->size = 0;
}

void memory_block_list_fini(memory_block_list* list)
{
    
}

void memory_block_list_push_front(memory_block_list* list, struct memory_block* block)
{
    memory_block* curr_head = list->head;
    
    if(!curr_head) {
        block->next = 0;
        block->prev = 0;
        list->head = list->tail = block;
        list->size = 1;
    } else {
        block->next = curr_head;
        block->prev = 0;
        curr_head->prev = block;
        list->head = block;
        list->size++;
    }
}

void memory_block_list_push_back(memory_block_list* list, struct memory_block* block)
{
    memory_block* curr_head = list->head;
    memory_block* curr_tail = list->tail;
    
    if (!curr_head) {
        block->next = 0;
        block->prev = 0;
        list->head = list->tail = block;
        list->size = 1;
    } else {
        block->prev = curr_tail;
        block->next = 0;
        curr_tail->next = block;
        list->tail = block;
        list->size++;
    }
}

void memory_block_list_remove_front(struct memory_block_list* list)
{
    memory_block_list_remove(list, list->head);
}

void memory_block_list_remove_tail(struct memory_block_list* list)
{
    memory_block_list_remove(list, list->tail);
}

void memory_block_list_remove(memory_block_list* list, struct memory_block* block)
{
    if(list->head == block) {
        if (list->size == 1) {
            list->head = list-> tail = 0;
        } else {
            memory_block* curr_head = list->head;
            list->head = curr_head->next;
            list->head->prev = 0;
            
        }
    } else if(list->tail == block) {
        if (list->size == 1) {
            list->head = list->tail = 0;
        } else {
            memory_block* curr_tail = list->tail;
            list->tail = curr_tail->prev;
            list->tail->next = 0;
        }
    } else {
        memory_block* before = block->prev;
        memory_block* after = block->next;
        
        if(before) {
            before->next = after;
        }
        
        if(after) {
            after->prev = before;
        }
    }
    
    list->size--;
}

struct memory_block* memory_block_list_front(memory_block_list* list)
{
    return list->head;
}

struct memory_block* memory_block_list_tail(memory_block_list* list)
{
    return list->tail;
}

sa_size_t memory_block_list_size(memory_block_list* list)
{
    return list->size;
}
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

#include "slice_list.h"

void slice_list_init(Slice_List* list)
{
    list->size = 0;
    list->tail = 0;
    list->head = 0;
}

void slice_list_fini(Slice_List* list)
{
}

void slice_list_push_front(Slice_List* list, Slice* slice)
{
    Slice* curr_head = list->head;

    if(!curr_head) {
        slice->next = 0;
        slice->prev = 0;
        list->head = list->tail = slice;
        list->size = 1;
    } else {
        slice->next = curr_head;
        slice->prev = 0;
        curr_head->prev = slice;
        list->head = slice;
        list->size++;
    }
}

void slice_list_push_back(Slice_List* list, Slice* slice)
{
    Slice* curr_head = list->head;
    Slice* curr_tail = list->tail;
    
    if (!curr_head) {
        slice->next = 0;
        slice->prev = 0;
        list->head = list->tail = slice;
        list->size = 1;
    } else {
        slice->prev = curr_tail;
        slice->next = 0;
        curr_tail->next = slice;
        list->tail = slice;
        list->size++;
    }
}

Slice* slice_list_front(Slice_List* list)
{
    return list->head;
}

Slice* slice_list_tail(Slice_List* list)
{
    return list->tail;
}

void slice_list_remove_tail(Slice_List* list)
{
    slice_list_remove(list, list->tail);
}

void slice_list_remove_front(Slice_List* list)
{
    slice_list_remove(list, list->head);
}

void slice_list_remove(Slice_List* list, Slice* slice)
{
    if(list->head == slice) {
        if (list->size == 1) {
            list->head = list-> tail = 0;
        } else {
            Slice* curr_head = list->head;
            list->head = curr_head->next;
            list->head->prev = 0;

        }
    } else if(list->tail == slice) {
        if (list->size == 1) {
            list->head = list->tail = 0;
        } else {
            Slice* curr_tail = list->tail;
            list->tail = curr_tail->prev;
            list->tail->next = 0;
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
    
    list->size--;
}


sa_size_t slice_list_size(Slice_List* list)
{
    return list->size;
}

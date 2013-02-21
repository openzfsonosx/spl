/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://github.com/behlendorf/spl/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
\*****************************************************************************/

#ifndef _SPL_LIST_H
#define _SPL_LIST_H

#include <sys/types.h>

//#include <linux/list.h>

/*
 * NOTE: I have implemented the Solaris list API in terms of the native
 * linux API.  This has certain advantages in terms of leveraging the linux
 * list debugging infrastructure, but it also means that the internals of a
 * list differ slightly than on Solaris.  This is not a problem as long as
 * all callers stick to the published API.  The two major differences are:
 *
 * 1) A list_node_t is mapped to a linux list_head struct which changes
 *    the name of the list_next/list_prev pointers to next/prev respectively.
 *
 * 2) A list_node_t which is not attached to a list on Solaris is denoted
 *    by having its list_next/list_prev pointers set to NULL.  Under linux
 *    the next/prev pointers are set to LIST_POISON1 and LIST_POISON2
 *    respectively.  At this moment this only impacts the implementation
 *    of the list_link_init() and list_link_active() functions.
 */

//typedef struct list_head list_node_t;

typedef struct list_node {
    struct list_node *list_next;
    struct list_node *list_prev;
} list_node_t;



typedef struct list {
	size_t list_size;
	size_t list_offset;
	list_node_t list_head;
} list_t;

void list_create(list_t *, size_t, size_t);
void list_destroy(list_t *);

void list_insert_after(list_t *, void *, void *);
void list_insert_before(list_t *, void *, void *);
void list_insert_head(list_t *, void *);
void list_insert_tail(list_t *, void *);
void list_remove(list_t *, void *);
void list_move_tail(list_t *, list_t *);

void *list_head(list_t *);
void *list_tail(list_t *);
void *list_next(list_t *, void *);
void *list_prev(list_t *, void *);

int list_link_active(list_node_t *);
int list_is_empty(list_t *);

#define LIST_POISON1 NULL
#define LIST_POISON2 NULL

#define	list_d2l(a, obj) ((list_node_t *)(((char *)obj) + (a)->list_offset))
#define	list_object(a, node) ((void *)(((char *)node) - (a)->list_offset))
#define	list_empty(a) ((a)->list_head.list_next == &(a)->list_head)


static inline void
list_link_init(list_node_t *node)
{
        node->list_next = LIST_POISON1;
        node->list_prev = LIST_POISON2;
}

static inline void
__list_del(list_node_t * prev, list_node_t * next)
{
    next->list_prev = prev;
    prev->list_next = next;
}

static inline void list_del(list_node_t *entry)
{
    __list_del(entry->list_prev, entry->list_next);
    entry->list_next = LIST_POISON1;
    entry->list_prev = LIST_POISON2;
}

static inline void *
list_remove_head(list_t *list)
{
        list_node_t *head = list->list_head.list_next;
        if (head == &list->list_head)
                return NULL;

        list_del(head);
        return list_object(list, head);
}

static inline void *
list_remove_tail(list_t *list)
{
        list_node_t *tail = list->list_head.list_prev;
        if (tail == &list->list_head)
                return NULL;

        list_del(tail);
        return list_object(list, tail);
}

static inline void
list_link_replace(list_node_t *old_node, list_node_t *new_node)
{
        ASSERT(list_link_active(old_node));
        ASSERT(!list_link_active(new_node));

        new_node->list_next = old_node->list_next;
        new_node->list_prev = old_node->list_prev;
        old_node->list_prev->list_next = new_node;
        old_node->list_next->list_prev = new_node;
        list_link_init(old_node);
}

#endif /* SPL_LIST_H */

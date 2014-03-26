//
//  slice_queue.h
//  allocator
//
//  Created by brendon on 18/03/2014.
//  Copyright (c) 2014 brendon. All rights reserved.
//

#ifndef SLICE_LIST_H
#define SLICE_LIST_H

#include "osif.h"
#include "slice.h"

struct Slice;

typedef struct {
    struct Slice* head;
    struct Slice* tail;
    sa_size_t size;
} Slice_List;

void slice_list_init(Slice_List* list);
void slice_list_fini(Slice_List* list);

void slice_list_push_front(Slice_List* list, struct Slice* slice);
void slice_list_push_back(Slice_List* list, Slice* slice);
void slice_list_remove(Slice_List* list, struct Slice* slice);
struct Slice* slice_list_front(Slice_List* list);
void slice_list_remove_front(Slice_List* list);
Slice* slice_list_tail(Slice_List* list);
void slice_list_remove_tail(Slice_List* list);
sa_size_t slice_list_size(Slice_List* list);

#endif

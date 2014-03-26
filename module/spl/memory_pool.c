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

#include "memory_pool.h"
#include "memory_block_list.h"

// The size of the memory blocks is calculated to allow ~512 of user allocatable
// space in the block + row header overhead + slice overhead + block header overhead.
//
// Going to a simple 512k per block does not work well for the large slice sizes, 25%
// of the memory is being wasted even before size mismatch waste is taken account of
// within the slices.
//
const sa_size_t RETAIN_MEMORY_SIZE = 10 * 1024 * 1024;
const sa_size_t MEMORY_BLOCK_SIZE = (512 * 1024) + 8192; 
const sa_size_t FREE_MEMORY_BLOCK_COUNT = RETAIN_MEMORY_SIZE / MEMORY_BLOCK_SIZE;
const hrtime_t MAX_FREE_MEM_AGE = 60 * NSEC_PER_SEC; // 60 seconds

sa_size_t amount_allocated = 0;

// Linked list of free memory blocks
memory_block_list block_list;

osif_mutex memory_pool_mutex;

void memory_pool_init()
{
    osif_mutex_init(&memory_pool_mutex);
    memory_block_list_init(&block_list);
}

void memory_pool_fini()
{
    memory_pool_release_memory();
    memory_block_list_fini(&block_list);
    //osif_mutex_destroy(&memory_pool_mutex);
}

memory_block* memory_pool_create_block()
{
    amount_allocated += MEMORY_BLOCK_SIZE;
    memory_block* block = (memory_block*)osif_malloc(MEMORY_BLOCK_SIZE);
    osif_zero_memory(block, sizeof(struct memory_block));
    return block;
}

void memory_pool_destroy_block(memory_block* block)
{
    amount_allocated -= MEMORY_BLOCK_SIZE;
    osif_free((void*)block, MEMORY_BLOCK_SIZE);
}

sa_size_t memory_pool_claim_size()
{
    return MEMORY_BLOCK_SIZE;
}

void memory_pool_release_memory()
{
    osif_mutex_enter(&memory_pool_mutex);
    
    // empty the large block list
    while(memory_block_list_size(&block_list)) {
        memory_block* block = memory_block_list_front(&block_list);
        memory_block_list_remove_front(&block_list);
        
        osif_free((void*)block, MEMORY_BLOCK_SIZE);
    }
    
    osif_mutex_exit(&memory_pool_mutex);
}

void memory_pool_garbage_collect()
{
    osif_mutex_enter(&memory_pool_mutex);

    hrtime_t stale_time = gethrtime() - MAX_FREE_MEM_AGE;

    int done = 0;
    
    do {
        sa_size_t free_blocks = memory_block_list_size(&block_list);
        if (free_blocks <= FREE_MEMORY_BLOCK_COUNT) {
            done = 1;
        } else {
            memory_block* block = memory_block_list_tail(&block_list);
            if(block->time_freed <= stale_time) {
                memory_block_list_remove_tail(&block_list);
                memory_pool_destroy_block(block);
            } else {
                done = 1;
            }
        }
    } while (!done);
    
    osif_mutex_exit(&memory_pool_mutex);
}

void* memory_pool_claim()
{
    osif_mutex_enter(&memory_pool_mutex);

    memory_block* block = 0;
    
    if (memory_block_list_size(&block_list)) {
        block = memory_block_list_tail(&block_list);
        memory_block_list_remove_tail(&block_list);
    } else {
        block = memory_pool_create_block();
    }
    
    osif_mutex_exit(&memory_pool_mutex);
    
    return (void*)block;
}

void memory_pool_return(void* memory)
{
    osif_mutex_enter(&memory_pool_mutex);
    
    struct memory_block* block = (struct memory_block*)(memory);
    block->time_freed = gethrtime();
    memory_block_list_push_front(&block_list, block);
    
    osif_mutex_exit(&memory_pool_mutex);
}


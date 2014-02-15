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

#ifdef IN_KERNEL

extern vm_map_t kernel_map;

extern kern_return_t kernel_memory_allocate(vm_map_t       map,
                                            vm_offset_t   *addrp,
                                            vm_size_t      size,
                                            vm_offset_t    mask,
                                            int            flags);

extern void kmem_free(vm_map_t map, vm_offset_t addr, vm_size_t size);

extern int              vm_pool_low(void);

#else

#include <stdlib.h>

#endif

void* osif_malloc(sa_size_t size)
{
#ifdef IN_KERNEL
    
    void *tr;
    kern_return_t kr;

    kr = kernel_memory_allocate(
                                kernel_map,
                                &tr,
                                size,
                                0,
                                0);

    if (kr == KERN_SUCCESS) {
        return tr;
    } else {
        return NULL;
    }
    
#else

    return (void*)malloc(size);
    
#endif
}

void osif_free(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    kmem_free(kernel_map, buf, size);
#else
    free(buf);
#endif
}

void osif_zero_memory(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    bzero(buf, size);
#else
    memset(buf, 0, size);
#endif
}

void osif_mutex_init(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_init(mutex, "bmalloc", MUTEX_DEFAULT, NULL);
#else
    pthread_mutex_init(mutex, 0);
#endif
}

void osif_mutex_enter(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_enter(mutex);
#else
    pthread_mutex_lock(mutex);
#endif
}

void osif_mutex_exit(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_exit(mutex);
#else
    pthread_mutex_unlock(mutex);
#endif
}

void osif_mutex_destroy(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_destroy(mutex);
#else
    pthread_mutex_destroy(mutex);
#endif
}

int osif_memory_pressure()
{
#ifdef IN_KERNEL
    return vm_pool_low();
#else
    return 0;
#endif
}

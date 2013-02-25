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
 *****************************************************************************
 *  Solaris Porting Layer (SPL) Kmem Implementation.
\*****************************************************************************/

#include <sys/kmem.h>
#include <spl-debug.h>

/*-
 * Copyright (c) 2006-2007 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/mutex.h>

//#include <vm/vm_page.h>
//#include <vm/vm_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>
#include <libkern/OSMalloc.h>

#ifdef _KERNEL

#else
#define	malloc(size, type, flags)	malloc(size)
#define	free(addr, type)		free(addr)
#endif

extern uint64_t    max_mem;
uint64_t    physmem;

//extern uint64_t    max_mem;
static OSMallocTag zfs_kmem_alloc_tag = NULL;


void
strfree(char *str)
{
    kmem_free(str, strlen(str) + 1);
}



void *
zfs_kmem_alloc(size_t size, int kmflags)
{
	void *p;
#ifdef KMEM_DEBUG
	struct kmem_item *i;

	size += sizeof(struct kmem_item);
#endif

    if (kmflags & KM_NOSLEEP)
        p = OSMalloc_noblock(size, zfs_kmem_alloc_tag);
    else
        p = OSMalloc(size, zfs_kmem_alloc_tag);

#ifndef _KERNEL
	if (kmflags & KM_SLEEP)
		assert(p != NULL);
#endif
#ifdef KMEM_DEBUG
	if (p != NULL) {
		i = p;
		p = (u_char *)p + sizeof(struct kmem_item);
		stack_save(&i->stack);
		mtx_lock(&kmem_items_mtx);
		LIST_INSERT_HEAD(&kmem_items, i, next);
		mtx_unlock(&kmem_items_mtx);
	}
#endif
	return (p);
}

void
zfs_kmem_free(void *buf, size_t size __unused)
{
    OSFree(buf, size, zfs_kmem_alloc_tag);
}

static uint64_t kmem_size_val;


void
spl_kmem_init(void)
{
    physmem = 0x20000000; // FIXME obviously

    zfs_kmem_alloc_tag = OSMalloc_Tagalloc("ZFS general purpose",
                                           OSMT_DEFAULT);
}

void
spl_kmem_fini(void)
{
    OSMalloc_Tagfree(zfs_kmem_alloc_tag);
}


#if 0
static void
kmem_size_init(void *unused __unused)
{
    zfs_kmem_alloc_tag = OSMalloc_Tagalloc("ZFS general purpose",
                                           OSMT_DEFAULT);
	kmem_size_val = max_mem;
}
SYSINIT(kmem_size_init, SI_SUB_KMEM, SI_ORDER_ANY, kmem_size_init, NULL);
#endif

uint64_t
kmem_size(void)
{

	return (kmem_size_val);
}

uint64_t
kmem_used(void)
{
    return 0x1234567890;
	//return (kmem_map->size);
}

static int
kmem_std_constructor(void *mem, int size __unused, void *private, int flags)
{
	struct kmem_cache *cache = private;

	return (cache->kc_constructor(mem, cache->kc_private, flags));
}

static void
kmem_std_destructor(void *mem, int size __unused, void *private)
{
	struct kmem_cache *cache = private;

	cache->kc_destructor(mem, cache->kc_private);
}

kmem_cache_t *
kmem_cache_create(char *name, size_t bufsize, size_t align,
    int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
    void (*reclaim)(void *) __unused, void *private, vmem_t *vmp, int cflags)
{
	kmem_cache_t *cache;

	ASSERT(vmp == NULL);

	cache = kmem_alloc(sizeof(*cache), KM_SLEEP);
	strlcpy(cache->kc_name, name, sizeof(cache->kc_name));
	cache->kc_constructor = constructor;
	cache->kc_destructor = destructor;
	cache->kc_private = private;
	cache->kc_size = bufsize;

	return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cache)
{
	kmem_free(cache, sizeof(*cache));
}

void *
kmem_cache_alloc(kmem_cache_t *cache, int flags)
{
	void *p;

	p = kmem_alloc(cache->kc_size, flags);
	if (p != NULL && cache->kc_constructor != NULL)
		kmem_std_constructor(p, cache->kc_size, cache, flags);
	return (p);
}

void
kmem_cache_free(kmem_cache_t *cache, void *buf)
{
	if (cache->kc_destructor != NULL)
		kmem_std_destructor(buf, cache->kc_size, cache);
	kmem_free(buf, cache->kc_size);
}

#ifdef _KERNEL
void
kmem_cache_reap_now(kmem_cache_t *cache)
{
}

void
kmem_reap(void)
{
}
#else
void
kmem_cache_reap_now(kmem_cache_t *cache __unused)
{
}

void
kmem_reap(void)
{
}
#endif

int
kmem_debugging(void)
{
	return (0);
}

void *
calloc(size_t n, size_t s)
{
	return (kmem_zalloc(n * s, KM_NOSLEEP));
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
    void *buf;

    buf = zfs_kmem_alloc(size, kmflags);
    if (buf != NULL)
        bzero(buf, size);
    return(buf);
}


#undef kmem_alloc
#undef kmem_free

extern kern_return_t    kmem_alloc(
                                   vm_map_t        map,
                                   vm_offset_t     *addrp,
                                   vm_size_t       size);

extern void             kmem_free(
                                  vm_map_t        map,
                                  vm_offset_t     addr,
                                  vm_size_t       size);
extern vm_map_t kernel_map;

void *
vmem_alloc(__unused vmem_t *vmp, size_t size, int vmflag)
{
    void *buf;

    /*
     * Only use kernel_map for sizes that are at least a page size
     */
    if (size < KERN_MAP_MIN_SIZE) {
        buf = zfs_kmem_alloc(size, vmflag);
    } else if (kmem_alloc(kernel_map, (vm_offset_t *)&buf, size) != KERN_SUCCESS) {
        buf = NULL;
    } else {
#if 0
        OSAddAtomic(size, (SInt32 *)&zfs_kernelmap_size);
        OSAddAtomic(size, (SInt32 *)&zfs_footprint.current);
        if (zfs_footprint.current > zfs_footprint.highest)
            zfs_footprint.highest = zfs_footprint.current;
#endif
    }

    if (buf == NULL) {
        if (vmflag & M_NOWAIT)
            return (NULL);
        else
            panic("zfs: vmem_alloc couldn't alloc %ld bytes\n", size);
    }

    /*
     * When were low on memory, call kmem_reap()
     */

    return (buf);
}

void
vmem_free(__unused vmem_t *vmp, void *vaddr, size_t size)
{
    /*
     * Only use kmem_alloc for sizes that are at least a page size
     */
    if (size < KERN_MAP_MIN_SIZE) {
        zfs_kmem_free(vaddr, size);
    } else {
        kmem_free(kernel_map, (vm_offset_t)vaddr, size);
#if 0
        OSAddAtomic(-size, (SInt32 *)&zfs_kernelmap_size);
        OSAddAtomic(-size, (SInt32 *)&zfs_footprint.current);
#endif
    }
}

void *
vmem_xalloc(vmem_t *vmp, size_t size, __unused size_t align_arg, __unused size_t phase,
            __unused size_t nocross, __unused void *minaddr, __unused void *maxaddr, int vmflag)
{
    return vmem_alloc(vmp, size, vmflag);
}

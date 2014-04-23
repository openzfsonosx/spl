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

/*
 *
 * Copyright (C) 2008 MacZFS
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <spl-debug.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include "spl-bmalloc.h"

uint64_t physmem = 0;
static uint64_t total_in_use = 0;

extern int vm_pool_low(void);

extern unsigned int vm_page_free_count;
extern unsigned int vm_page_speculative_count;

void spl_register_oids(void);
void spl_unregister_oids(void);

SYSCTL_DECL(_spl);
SYSCTL_NODE( , OID_AUTO, spl, CTLFLAG_RW, 0, "Solaris Porting Layer");
struct sysctl_oid_list sysctl__spl_children;

SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_total, CTLFLAG_RD,
            &total_in_use, "kmem.total bytes allocated");

extern uint32_t zfs_threads;
SYSCTL_INT(_spl, OID_AUTO, num_threads,
           CTLFLAG_RD, &zfs_threads, 0,
           "Num threads");

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
    ASSERT(size);

    void *p = bmalloc(size);

    if (p) {
        if (kmflags & KM_ZERO) {
            bzero(p, size);
        }
        atomic_add_64(&total_in_use, size);
    } else {
        printf("[spl] kmem_alloc(%lu) failed: \n", size);
    }

    return (p);
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
    return zfs_kmem_alloc(size, kmflags | KM_ZERO);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    ASSERT(buf && size);

    bfree(buf, size);
    atomic_sub_64(&total_in_use, size);
}

void
spl_kmem_init(uint64_t total_memory)
{
    printf("SPL: Total memory %llu\n", total_memory);
    spl_register_oids();
}

void
spl_kmem_fini(void)
{
    spl_unregister_oids();
}

uint64_t
kmem_size(void)
{
	return (physmem * PAGE_SIZE);
}

uint64_t
kmem_used(void)
{
    return total_in_use;
}

uint64_t
kmem_avail(void)
{
    return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
}

int spl_vm_pool_low(void)
{
    static int tick_counter = 0;

    int r = vm_pool_low();

    if(r) {
        bmalloc_release_memory();
    }

    // FIXME - this should be in its own thread
    // that calls garbage collect at least every
    // 5 seconds.
    tick_counter++;
    if(tick_counter % 5 == 0) {
        tick_counter = 0;
        bmalloc_garbage_collect();
    }

    return r;
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
                  void (*reclaim)(void *), void *private, vmem_t *vmp, int cflags)
{
	kmem_cache_t *cache;

	ASSERT(vmp == NULL);

	cache = zfs_kmem_alloc(sizeof(*cache), KM_SLEEP);
	strlcpy(cache->kc_name, name, sizeof(cache->kc_name));
	cache->kc_constructor = constructor;
	cache->kc_destructor = destructor;
	cache->kc_reclaim = reclaim;
	cache->kc_private = private;
	cache->kc_size = bufsize;

	return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cache)
{
	zfs_kmem_free(cache, sizeof(*cache));
}

void *
kmem_cache_alloc(kmem_cache_t *cache, int flags)
{
	void *p;

	p = zfs_kmem_alloc(cache->kc_size, flags);
	if (p != NULL && cache->kc_constructor != NULL)
		kmem_std_constructor(p, cache->kc_size, cache, flags);
	return (p);
}

void
kmem_cache_free(kmem_cache_t *cache, void *buf)
{
	if (cache->kc_destructor != NULL)
		kmem_std_destructor(buf, cache->kc_size, cache);
	zfs_kmem_free(buf, cache->kc_size);
}


/*
 * Call the registered reclaim function for a cache.  Depending on how
 * many and which objects are released it may simply repopulate the
 * local magazine which will then need to age-out.  Objects which cannot
 * fit in the magazine we will be released back to their slabs which will
 * also need to age out before being release.  This is all just best
 * effort and we do not want to thrash creating and destroying slabs.
 */
void
kmem_cache_reap_now(kmem_cache_t *skc)
{
}

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

void
strfree(char *str)
{
    bfree(str, strlen(str) + 1);
}

char *kvasprintf(const char *fmt, va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    p = bmalloc(len+1);
    if (!p)
        return NULL;

    vsnprintf(p, len+1, fmt, ap);

    return p;
}

char *
kmem_vasprintf(const char *fmt, va_list ap)
{
    va_list aq;
    char *ptr;

    do {
        va_copy(aq, ap);
        ptr = kvasprintf(fmt, aq);
        va_end(aq);
    } while (ptr == NULL);

    return ptr;
}

char *
kmem_asprintf(const char *fmt, ...)
{
    va_list ap;
    char *ptr;

    do {
        va_start(ap, fmt);
        ptr = kvasprintf(fmt, ap);
        va_end(ap);
    } while (ptr == NULL);

    return ptr;
}

void spl_register_oids(void)
{
    sysctl_register_oid(&sysctl__spl);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_register_oid(&sysctl__spl_num_threads);
}

void spl_unregister_oids(void)
{
    sysctl_unregister_oid(&sysctl__spl);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_unregister_oid(&sysctl__spl_num_threads);
}

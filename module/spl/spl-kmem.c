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


#include <sys/kmem.h>
#include <spl-debug.h>


#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kmem.h>
#include <sys/mutex.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>
#include <libkern/OSMalloc.h>
#include <sys/sysctl.h>

#ifdef _KERNEL

#else
#define	malloc(size, type, flags)	malloc(size)
#define	free(addr, type)		free(addr)
#endif

extern uint64_t    max_mem;
uint64_t    physmem = 0;

//extern uint64_t    max_mem;
static OSMallocTag zfs_kmem_alloc_tag = NULL;

vmem_t *zio_alloc_arena = NULL; /* arena for allocating zio memory */

static uint64_t total_in_use = 0;


extern unsigned int vm_page_free_count;
extern unsigned int vm_page_speculative_count;

typedef void * zone_t;
extern void *zinit( vm_size_t,  vm_size_t,  vm_size_t, char *);
extern void *zalloc( void *);
extern void zfree(void *, void *);

struct spl_kmem_zone_struct {
    unsigned int size;
    void *zone;
    char name[32];
    uint32_t num_allocated;
    uint64_t bytes_allocated;
};


/*
 * Allocate zones for common sizes we want to allocate into.
 * Anything larger will be allocated as kalloc.large.
 */
static struct spl_kmem_zone_struct spl_kmem_zones[] = {
    /* size   zone  name                 #  bytes */
    { 32,     NULL, "spl.kmem.32",       0, 0 },
    { 64,     NULL, "spl.kmem.64",       0, 0 },
    { 128,    NULL, "spl.kmem.128",      0, 0 },
    { 256,    NULL, "spl.kmem.256",      0, 0 },
    { 512,    NULL, "spl.kmem.512",      0, 0 },
    { 1024,   NULL, "spl.kmem.1024",     0, 0 },
    { 2048,   NULL, "spl.kmem.2048",     0, 0 },
    { 4096,   NULL, "spl.kmem.4096",     0, 0 },
    { 8192,   NULL, "spl.kmem.8192",     0, 0 },
    { 16384,  NULL, "spl.kmem.16384",    0, 0 },
    { 32768,  NULL, "spl.kmem.32768",    0, 0 },
    { 65536,  NULL, "spl.kmem.65536",    0, 0 },
    { 131072, NULL, "spl.kmem.131072",   0, 0 },
    { 262144, NULL, "spl.kmem.262144",   0, 0 },
};

#define SPL_KMEM_NUM_ZONES (sizeof(spl_kmem_zones) / sizeof(struct spl_kmem_zone_struct))

static uint32_t spl_large_num_allocated   = 0;
static uint64_t spl_large_bytes_allocated = 0;

void spl_register_oids(void);
void spl_unregister_oids(void);
SYSCTL_DECL(_spl);
SYSCTL_NODE( , OID_AUTO, spl, CTLFLAG_RW, 0, "Solaris Porting Layer");
struct sysctl_oid_list sysctl__spl_children;

SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_32, CTLFLAG_RD,
            &spl_kmem_zones[0].bytes_allocated, "kmem.32 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_64, CTLFLAG_RD,
            &spl_kmem_zones[1].bytes_allocated, "kmem.64 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_128, CTLFLAG_RD,
            &spl_kmem_zones[2].bytes_allocated, "kmem.128 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_256, CTLFLAG_RD,
            &spl_kmem_zones[3].bytes_allocated, "kmem.256 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_512, CTLFLAG_RD,
            &spl_kmem_zones[4].bytes_allocated, "kmem.512 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_1024, CTLFLAG_RD,
            &spl_kmem_zones[5].bytes_allocated, "kmem.1024 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_2048, CTLFLAG_RD,
            &spl_kmem_zones[6].bytes_allocated, "kmem.2048 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_4096, CTLFLAG_RD,
            &spl_kmem_zones[7].bytes_allocated, "kmem.4096 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_8192, CTLFLAG_RD,
            &spl_kmem_zones[8].bytes_allocated, "kmem.8192 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_16384, CTLFLAG_RD,
            &spl_kmem_zones[9].bytes_allocated, "kmem.16384 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_32768, CTLFLAG_RD,
            &spl_kmem_zones[10].bytes_allocated, "kmem.32768 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_65536, CTLFLAG_RD,
            &spl_kmem_zones[11].bytes_allocated, "kmem.65536 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_131072, CTLFLAG_RD,
           &spl_kmem_zones[12].bytes_allocated, "kmem.131072 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_262144, CTLFLAG_RD,
           &spl_kmem_zones[13].bytes_allocated, "kmem.262144 bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_large, CTLFLAG_RD,
           &spl_large_bytes_allocated, "kmem.large bytes allocated");
SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_total, CTLFLAG_RD,
           &total_in_use, "kmem.total bytes allocated");

SYSCTL_INT(_spl, OID_AUTO, kmem_count_32, CTLFLAG_RD,
      &spl_kmem_zones[0].num_allocated, 0, "kmem.32 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_64, CTLFLAG_RD,
      &spl_kmem_zones[1].num_allocated, 0, "kmem.64 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_128, CTLFLAG_RD,
      &spl_kmem_zones[2].num_allocated, 0, "kmem.128 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_256, CTLFLAG_RD,
      &spl_kmem_zones[3].num_allocated, 0, "kmem.256 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_512, CTLFLAG_RD,
      &spl_kmem_zones[4].num_allocated, 0, "kmem.512 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_1024, CTLFLAG_RD,
      &spl_kmem_zones[5].num_allocated, 0, "kmem.1024 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_2048, CTLFLAG_RD,
      &spl_kmem_zones[6].num_allocated, 0, "kmem.2048 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_4096, CTLFLAG_RD,
      &spl_kmem_zones[7].num_allocated, 0, "kmem.4096 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_8192, CTLFLAG_RD,
      &spl_kmem_zones[8].num_allocated, 0, "kmem.8192 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_16384, CTLFLAG_RD,
      &spl_kmem_zones[9].num_allocated, 0, "kmem.16384 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_32768, CTLFLAG_RD,
      &spl_kmem_zones[10].num_allocated, 0, "kmem.32768 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_65536, CTLFLAG_RD,
      &spl_kmem_zones[11].num_allocated, 0, "kmem.65536 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_131072, CTLFLAG_RD,
      &spl_kmem_zones[12].num_allocated, 0, "kmem.131072 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_262144, CTLFLAG_RD,
      &spl_kmem_zones[13].num_allocated, 0, "kmem.262144 active allocations");
SYSCTL_INT(_spl, OID_AUTO, kmem_count_large, CTLFLAG_RD,
      &spl_large_num_allocated, 0, "kmem.large active allocations");


void
strfree(char *str)
{
    OSFree(str, strlen(str) + 1, zfs_kmem_alloc_tag);
}

extern void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
                                 void * physicalAddress);
extern void IOFreeContiguous(void * _address, vm_size_t size);

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
	void *p = NULL;
    uint64_t times = 0;
    int i;

    do {

        times++;

        /* Find the correct zone */
        if (size > spl_kmem_zones[ SPL_KMEM_NUM_ZONES-1 ].size) {
            p = OSMalloc(size, zfs_kmem_alloc_tag);
        } else {

            for (i = 0; i < SPL_KMEM_NUM_ZONES; i++) {
                if (size <= spl_kmem_zones[i].size) {
                    p = zalloc(spl_kmem_zones[i].zone);
                    break;
                }
            }
        }

    } while(!p);


    if (p && (kmflags & KM_ZERO))
        bzero(p, size);

    if (times > 1)
        printf("[spl] kmem_alloc(%lu) took %llu retries\n",
               size, times);

    if (!p) {
        printf("[spl] kmem_alloc(%lu) failed: \n",size);
    } else {

        if (size > spl_kmem_zones[ SPL_KMEM_NUM_ZONES-1 ].size) {
            atomic_add_64(&spl_large_bytes_allocated, size);
            atomic_inc_32(&spl_large_num_allocated);
        } else {
            atomic_add_64(&spl_kmem_zones[i].bytes_allocated, size);
            atomic_inc_32(&spl_kmem_zones[i].num_allocated);
        }

        atomic_add_64(&total_in_use, size);
    }
	return (p);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    int i;
    /* Find the correct zone */
    if (size > spl_kmem_zones[ SPL_KMEM_NUM_ZONES-1 ].size) {
        OSFree(buf, size, zfs_kmem_alloc_tag);
        atomic_sub_64(&spl_large_bytes_allocated, size);
        atomic_dec_32(&spl_large_num_allocated);
    } else {

        for (i = 0; i < SPL_KMEM_NUM_ZONES; i++) {
            if (size <= spl_kmem_zones[i].size) {
                zfree(spl_kmem_zones[i].zone, buf);
                atomic_sub_64(&spl_kmem_zones[i].bytes_allocated, size);
                atomic_dec_32(&spl_kmem_zones[i].num_allocated);
                break;
            }
        }
    }

    atomic_sub_64(&total_in_use, size);
}

void spl_total_in_use(void)
{
    printf("SPL: memory in use %llu\n", total_in_use);
}


void
spl_kmem_init(uint64_t total_memory)
{
    int i;

    //OSMT_PAGEABLE
    zfs_kmem_alloc_tag = OSMalloc_Tagalloc("spl.kmem.large",
                                           //OSMT_PAGEABLE);
                                           OSMT_DEFAULT);

    printf("SPL: Total memory %llu\n", total_memory);
    for (i = 0; i < SPL_KMEM_NUM_ZONES; i++) {
        printf("SPL: Initialising zone %d: %u\n",
               i,
               spl_kmem_zones[i].size);
        spl_kmem_zones[i].zone = zinit(spl_kmem_zones[i].size,
                                       total_memory,
                                       spl_kmem_zones[i].size,
                                       spl_kmem_zones[i].name);
        if (spl_kmem_zones[i].zone == NULL)
            printf("SPL: Zone allocation %u failed.\n",
                   spl_kmem_zones[i].size);
    }

    spl_register_oids();

}

void
spl_kmem_fini(void)
{
    OSMalloc_Tagfree(zfs_kmem_alloc_tag);
    spl_unregister_oids();
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

	return (physmem * PAGE_SIZE);
}

uint64_t
kmem_used(void)
{
    return total_in_use;
    //return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
}

uint64_t
kmem_avail(void)
{
    return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
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

	cache = kmem_alloc(sizeof(*cache), KM_SLEEP);
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


/*
 * Call the registered reclaim function for a cache.  Depending on how
 * many and which objects are released it may simply repopulate the
 * local magazine which will then need to age-out.  Objects which cannot
 * fit in the magazine we will be released back to their slabs which will
 * also need to age out before being release.  This is all just best
 * effort and we do not want to thrash creating and destroying slabs.
 */
void
kmem_cache_reap_now(kmem_cache_t *skc)//, int count)
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

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
    void *buf;

    buf = zfs_kmem_alloc(size, kmflags);

    if (buf != NULL) {
        bzero(buf, size);
    }
    return(buf);
}


char *kvasprintf(const char *fmt, va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    p = OSMalloc(len+1, zfs_kmem_alloc_tag);
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
    sysctl_register_oid(&sysctl__spl_kmem_bytes_32);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_64);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_128);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_256);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_512);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_1024);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_2048);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_4096);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_8192);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_16384);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_32768);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_65536);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_131072);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_262144);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_large);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_register_oid(&sysctl__spl_kmem_count_32);
    sysctl_register_oid(&sysctl__spl_kmem_count_64);
    sysctl_register_oid(&sysctl__spl_kmem_count_128);
    sysctl_register_oid(&sysctl__spl_kmem_count_256);
    sysctl_register_oid(&sysctl__spl_kmem_count_512);
    sysctl_register_oid(&sysctl__spl_kmem_count_1024);
    sysctl_register_oid(&sysctl__spl_kmem_count_2048);
    sysctl_register_oid(&sysctl__spl_kmem_count_4096);
    sysctl_register_oid(&sysctl__spl_kmem_count_8192);
    sysctl_register_oid(&sysctl__spl_kmem_count_16384);
    sysctl_register_oid(&sysctl__spl_kmem_count_32768);
    sysctl_register_oid(&sysctl__spl_kmem_count_65536);
    sysctl_register_oid(&sysctl__spl_kmem_count_131072);
    sysctl_register_oid(&sysctl__spl_kmem_count_262144);
    sysctl_register_oid(&sysctl__spl_kmem_count_large);
}

void spl_unregister_oids(void)
{
    sysctl_unregister_oid(&sysctl__spl);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_32);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_64);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_128);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_256);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_512);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_1024);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_2048);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_4096);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_8192);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_16384);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_32768);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_65536);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_131072);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_262144);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_large);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_32);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_64);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_128);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_256);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_512);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_1024);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_2048);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_4096);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_8192);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_16384);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_32768);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_65536);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_131072);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_262144);
    sysctl_unregister_oid(&sysctl__spl_kmem_count_large);
}


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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/atomic.h>

#include <sys/vmem.h>
#include <sys/vmem_impl.h>
// ugly: smd
#ifdef kmem_free
#undef kmem_free
#endif
#include <vm/seg_kmem.h>

#include <sys/time.h>
#include <sys/timer.h>
#include <osx/condvar.h>

#include <stdbool.h>

/*
 * seg_kmem is the primary kernel memory segment driver.  It
 * maps the kernel heap [kernelheap, ekernelheap), module text,
 * and all memory which was allocated before the VM was initialized
 * into kas.
 *
 * Pages which belong to seg_kmem are hashed into &kvp vnode at
 * an offset equal to (u_offset_t)virt_addr, and have p_lckcnt >= 1.
 * They must never be paged out since segkmem_fault() is a no-op to
 * prevent recursive faults.
 *
 * Currently, seg_kmem pages are sharelocked (p_sharelock == 1) on
 * __x86 and are unlocked (p_sharelock == 0) on __sparc.  Once __x86
 * supports relocation the #ifdef kludges can be removed.
 *
 * seg_kmem pages may be subject to relocation by page_relocate(),
 * provided that the HAT supports it; if this is so, segkmem_reloc
 * will be set to a nonzero value. All boot time allocated memory as
 * well as static memory is considered off limits to relocation.
 * Pages are "relocatable" if p_state does not have P_NORELOC set, so
 * we request P_NORELOC pages for memory that isn't safe to relocate.
 *
 * The kernel heap is logically divided up into four pieces:
 *
 *   heap32_arena is for allocations that require 32-bit absolute
 *   virtual addresses (e.g. code that uses 32-bit pointers/offsets).
 *
 *   heap_core is for allocations that require 2GB *relative*
 *   offsets; in other words all memory from heap_core is within
 *   2GB of all other memory from the same arena. This is a requirement
 *   of the addressing modes of some processors in supervisor code.
 *
 *   heap_arena is the general heap arena.
 *
 *   static_arena is the static memory arena.  Allocations from it
 *   are not subject to relocation so it is safe to use the memory
 *   physical address as well as the virtual address (e.g. the VA to
 *   PA translations are static).  Caches may import from static_arena;
 *   all other static memory allocations should use static_alloc_arena.
 *
 * On some platforms which have limited virtual address space, seg_kmem
 * may share [kernelheap, ekernelheap) with seg_kp; if this is so,
 * segkp_bitmap is non-NULL, and each bit represents a page of virtual
 * address space which is actually seg_kp mapped.
 */

/*
 * Rough stubbed Port for XNU.
 *
 * Copyright (c) 2014 Brendon Humphrey (brendon.humphrey@mac.com)
 */


#ifdef _KERNEL
#define XNU_KERNEL_PRIVATE
#include <mach/vm_types.h>
extern vm_map_t kernel_map;

/*
 * These extern prototypes has to be carefully checked against XNU source
 * in case Apple changes them. They are not defined in the "allowed" parts
 * of the kernel.framework
 */
typedef uint8_t vm_tag_t;

/*
 * Tag we use to identify memory we have allocated
 *
 * (VM_KERN_MEMORY_KEXT - mach_vm_statistics.h)
 */
#define SPL_TAG 6

/*
 * In kernel lowlevel form of malloc.
 */
extern kern_return_t kernel_memory_allocate(vm_map_t map, void **addrp,
                                            vm_size_t size, vm_offset_t mask,
											int flags, vm_tag_t tag);

/*
 * Free memory
 */
extern void kmem_free(vm_map_t map, void *addr, vm_size_t size);

#endif /* _KERNEL */

typedef int page_t;

void *segkmem_alloc(vmem_t *vmp, size_t size, int vmflag);
void segkmem_free(vmem_t *vmp, void *inaddr, size_t size);


uint64_t segkmem_total_mem_allocated = 0;	/* Total memory held allocated */
vmem_t *heap_arena;							/* primary kernel heap arena */
vmem_t *zio_arena_parent_parent = NULL;
vmem_t *zio_arena_parent = NULL;
vmem_t *zio_arena;							/* arena for allocating zio memory */
vmem_t *zio_alloc_arena;					/* arena for allocating zio memory */

#ifdef _KERNEL
extern uint64_t total_memory;
uint64_t tunable_osif_memory_cap = 0;
uint64_t tunable_osif_memory_reserve = 0;
uint64_t tunable_osif_pushpage_waitlimit = hz*10ULL;
#endif
uint64_t stat_osif_malloc_denied = 0;
uint64_t stat_osif_malloc_success = 0;
uint64_t stat_osif_malloc_fail = 0;
uint64_t stat_osif_free = 0;
uint64_t stat_osif_cum_reserve_allocs = 0;
uint64_t stat_osif_cum_reserve_bytes = 0;
uint64_t stat_osif_uncapped_calls = 0;
uint64_t stat_osif_capped_calls = 0;
uint64_t stat_osif_default_calls = 0;


#define OSIF_RESERVE_PERCENT_ULL 10ULL // percent above cap we can allocate

// slowpath: segkmem_total_mem_allocated + size > total_memory
inline static void *
osif_malloc_reserve_cap(uint64_t size)
{
#ifdef _KERNEL
	void *tr;
	kern_return_t kr;

	if (tunable_osif_memory_cap == 0 && total_memory > 0) {
		tunable_osif_memory_cap = total_memory + (1024ULL * 1024ULL * 1024ULL);
	}

	if (tunable_osif_memory_reserve <=
	    (tunable_osif_memory_cap + (1024ULL * 1024ULL * 1024ULL))
	    && total_memory > 0) {
		extern uint64_t real_total_memory;
		tunable_osif_memory_reserve =
		    MIN((real_total_memory / 80ULL * 100ULL),
			(tunable_osif_memory_cap + (2ULL * 1024ULL * 1024ULL * 1024ULL)));
	}

	atomic_inc_64(&stat_osif_cum_reserve_allocs);

	if (segkmem_total_mem_allocated + size <= tunable_osif_memory_reserve) {
		kr = kernel_memory_allocate(kernel_map, &tr, size, PAGESIZE, 0,
					    SPL_TAG);

		if (kr == KERN_SUCCESS) {
			stat_osif_malloc_success++;
			atomic_add_64(&segkmem_total_mem_allocated, size);
			if (segkmem_total_mem_allocated > total_memory) {	// close enough, logically
				// rather than burn a variable to determine what fraction
				// of this allocation is above total_memory threshold
				// and anyway, that's maybe less interesting than this count for now
				atomic_add_64(&stat_osif_cum_reserve_bytes,
					      size);
			}
			return (tr);
		} else {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
	} else {
		atomic_inc_64(&stat_osif_malloc_denied);
		return (NULL);
	}
#else
	return ((void *) malloc(size));
#endif
}

inline static void *
osif_malloc_uncapped(uint64_t size)
{
#ifdef _KERNEL
	void *tr;
	kern_return_t kr;

	atomic_inc_64(&stat_osif_uncapped_calls);

	kr = kernel_memory_allocate(kernel_map, &tr, size, PAGESIZE, 0,
				    SPL_TAG);

	if (kr == KERN_SUCCESS) {
		stat_osif_malloc_success++;
		atomic_add_64(&segkmem_total_mem_allocated, size);
		return (tr);
	} else {
		atomic_inc_64(&stat_osif_malloc_fail);
		return (NULL);
	}
#else
	return ((void *) malloc(size));
#endif				/* _KERNEL */
}

inline static void *
osif_malloc_capped(uint64_t size)
{
#ifdef _KERNEL
	void *tr;
	kern_return_t kr;

	atomic_inc_64(&stat_osif_capped_calls);

	if (tunable_osif_memory_cap == 0 && total_memory > 0) {
		tunable_osif_memory_cap = total_memory + (1024ULL * 1024ULL * 1024ULL);
	}

	if ((segkmem_total_mem_allocated + size) > tunable_osif_memory_cap &&
	    (tunable_osif_memory_cap > 0) &&
	    (segkmem_total_mem_allocated > 0)) {
		atomic_inc_64(&stat_osif_malloc_denied);
		return (NULL);
	}

	kr = kernel_memory_allocate(kernel_map, &tr, size, PAGESIZE, 0,
				    SPL_TAG);

	if (kr == KERN_SUCCESS) {
		stat_osif_malloc_success++;
		atomic_add_64(&segkmem_total_mem_allocated, size);
		return (tr);
	} else {
		atomic_inc_64(&stat_osif_malloc_fail);
		return (NULL);
	}
#else
	return ((void *) malloc(size));
#endif				/* _KERNEL */
}

static inline void *
osif_malloc_pushpage(size_t size, const char *caller)
{
	static uint64_t lastsuccess = 0;

	void *ret = osif_malloc_reserve_cap(size);

	if (ret != NULL) {
		lastsuccess = zfs_lbolt();
		return (ret);
	}

	uint64_t now = zfs_lbolt();
	uint64_t elapsed = now - lastsuccess;

	volatile extern unsigned int vm_page_free_wanted;
	volatile extern unsigned int vm_page_free_count;

	if (elapsed > tunable_osif_pushpage_waitlimit) {
		if (vm_page_free_wanted == 0
		    && vm_page_free_count > (size / PAGESIZE)) {
			printf("SPL: %s stuck for %llu ticks, force allocating %lu.\n",
			    caller, elapsed, size);
			lastsuccess = now;
			return osif_malloc_uncapped(size);
		} else if (vm_page_free_wanted == 0) {
			printf("SPL: %s stuck for %llu ticks, vm_page_free_count is only %u, "
			    "force allocating %lu anyway.\n",
			    caller, elapsed, vm_page_free_count, size);
			lastsuccess = now;
			return osif_malloc_uncapped(size);
		} else if (elapsed > (6*tunable_osif_pushpage_waitlimit)
		    || (now % (hz*60))==0) {
			printf("SPL: %s stuck for %llu seconds, vm_page_free_wanted = %u, "
			    "vm_page_free_count = %u, force_allocating %lu nevertheless.\n",
			    caller, (elapsed / hz),
			    vm_page_free_wanted, vm_page_free_count,
			    size);
			lastsuccess = now;
			return osif_malloc_uncapped(size);
		} else if ((now % (10*hz))==0) {
			printf("SPL: %s stuck badly, been %llu seconds, "
			    "vm_page_free_wanted = %u, vm_page_free_count = %u, still waiting for %lu.\n",
			    caller, (elapsed/hz),
			    vm_page_free_wanted, vm_page_free_count,
			    size);
			return (NULL);
		}
	}

	return (NULL);
}

inline static void
osif_free(void* buf, uint64_t size)
{
#ifdef _KERNEL
    kmem_free(kernel_map, buf, size);
    stat_osif_free++;
    atomic_sub_64(&segkmem_total_mem_allocated, size);
#else
    free(buf);
#endif /* _KERNEL */
}

/*
 * Configure vmem, such that the heap arena is fed,
 * and drains to the kernel low level allocator.
 */
void
kernelheap_init()
{
	heap_arena = vmem_init("heap", NULL, 0, PAGESIZE, segkmem_alloc, segkmem_free);
}


void kernelheap_fini(void)
{
	vmem_fini(heap_arena);
}

void *
segkmem_alloc(vmem_t * vmp, size_t size, int vmflag)
{
	void *ret = NULL;
	bool called = false;

	volatile extern unsigned int vm_page_free_wanted;
	volatile extern unsigned int vm_page_free_count;

	if (vmflag == VM_SLEEP) {
		if (vm_page_free_wanted > 0) {
			return (NULL);
			atomic_inc_64(&stat_osif_malloc_fail);
		}
		ret = osif_malloc_capped(size);
		called = true;
	}

	uint8_t vmflags = vmflag & 0xff;

	if (vmflags & VM_PANIC) {
		ret = osif_malloc_uncapped(size);
		called = true;
	}

	if (vmflags & VM_PUSHPAGE) {
		ret = osif_malloc_pushpage(size, __func__);
		called = true;
	}

	if (vmflags & VM_NORMALPRI && vmflags & VM_NOSLEEP) {
		if (vm_page_free_wanted > 0) {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
		if (vm_page_free_count < 8 * (size / PAGESIZE)) {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
		ret = osif_malloc_capped(size);
		called = true;
	}

	if (vmflags & VM_NORMALPRI) {
		ret = osif_malloc_capped(size);
		called = true;
	}

	if (vmflags & VM_NOSLEEP) {
		return (osif_malloc_capped(size));
	}

	if (ret != NULL) {
		cv_signal(&vmp->vm_cv);
		return (ret);
	} else if (called == true) {
		// should we or not signal?
		// since adjusting vmem_update(), probably not
		//cv_signal(&vmp->vm_cv);
		return (NULL);
	}

	printf("SPL: %s default alloc, size = %lu, vmflag = %x.\n",
	       __func__, size, vmflag);
	atomic_inc_64(&stat_osif_default_calls);
	return (osif_malloc_capped(size));
}


void *
segkmem_zio_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	void *ret = NULL;
	bool called = false;

	volatile extern unsigned int vm_page_free_count;
	volatile extern unsigned int vm_page_free_wanted;

	if (vm_page_free_wanted >  0 ||
	    vm_page_free_count < 8 * (size / PAGESIZE)) {
		kpreempt(KPREEMPT_SYNC);
	}

	if (vmflag == VM_SLEEP) {
		if (vm_page_free_wanted > 0) {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
		ret = osif_malloc_capped(size);
		called = true;
	}

	uint8_t vmflags = vmflag & 0xff;

	if (vmflags & VM_PANIC) {
		ret = osif_malloc_uncapped(size);
		called = true;
	}

	if (vmflags & VM_PUSHPAGE) {
		ret = osif_malloc_pushpage(size, __func__);
		called = true;
	}

	if (vmflags & VM_NORMALPRI && vmflags & VM_NOSLEEP) {
		if (vm_page_free_wanted > 0) {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
		if (vm_page_free_count < 8 * (size / PAGESIZE)) {
			atomic_inc_64(&stat_osif_malloc_fail);
			return (NULL);
		}
		ret = osif_malloc_capped(size);
		called = true;
	}

	if (vmflags & VM_NORMALPRI) {
		ret = osif_malloc_capped(size);
		called = true;
	}

	if (vmflags & VM_NOSLEEP) {
		return (osif_malloc_capped(size));
	}

	if (ret != NULL) {
		cv_signal(&vmp->vm_cv);
		return (ret);
	} else if (called == true) {
		// should we or not signal?
		// since adjusting vmem_update(), probably not
		//cv_signal(&vmp->vm_cv);
		return (NULL);
	}

	printf("SPL: %s default alloc, size = %lu, vmflag = %x.\n",
	       __func__, size, vmflag);
	atomic_inc_64(&stat_osif_default_calls);
	return (osif_malloc_capped(size));
}

void
segkmem_free(vmem_t *vmp, void *inaddr, size_t size)
{
	osif_free(inaddr, size);
	cv_signal(&vmp->vm_cv);
}

void
segkmem_zio_free(vmem_t *vmp, void *inaddr, size_t size)
{
	osif_free(inaddr, size);
	cv_signal(&vmp->vm_cv);
}

/*
 * OSX does not use separate heaps for the ZIO buffers,
 * the ZFS code is structured such that the zio caches will
 * fallback to using the kmem_default arena same 
 * as all the other caches.
 */
// smd: we nevertheless plumb in an arena with heap as parent, so that
//      we can track stats and maintain the VM_ / qc settings differently
void
segkmem_zio_init()
{

	// note:  from startup.c and vm_machparam: SEGZIOMINSIZE = 512M.
	// and SEGZSIOMAXSIZE = 512G; if physmem is between the two, then
	// segziosize is (physmem - SEGZIOMAXSIZE) / 2.

	// for now we duke it out on size using segkmem_zio_alloc

	zio_arena_parent_parent = vmem_create("zfs_file_data_p_p", NULL, 0,
	    4*1024*1024, NULL, NULL, NULL, 0, VM_SLEEP | VM_NEXTFIT);

	zio_arena_parent = vmem_create("zfs_file_data_p", NULL, 0,
	    PAGESIZE, segkmem_zio_alloc, segkmem_zio_free, zio_arena_parent_parent,
	    4*1024*1024, VM_SLEEP | VMC_NO_QCACHE | VM_NEXTFIT);

	zio_arena = vmem_create("zfs_file_data", NULL, 0,
	    PAGESIZE, vmem_alloc, vmem_free, zio_arena_parent,
	    /* 32 * 1024 */ 0, VM_SLEEP | VM_NEXTFIT);

	zio_alloc_arena = vmem_create("zfs_file_data_buf", NULL, 0,
	    PAGESIZE, vmem_alloc, vmem_free, zio_arena, 0, VM_SLEEP | VM_NEXTFIT);

	ASSERT(zio_arena != NULL);
	ASSERT(zio_alloc_arena != NULL);
}

void
segkmem_zio_fini(void)
{
	if (zio_alloc_arena) {
		vmem_destroy(zio_alloc_arena);
	}
	
	if (zio_arena) {
		vmem_destroy(zio_arena);
	}
}



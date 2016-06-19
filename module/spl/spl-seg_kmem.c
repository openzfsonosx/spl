
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
#include <vm/seg_kmem.h>



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

/*
 * Create virtual address map from a parent map.
 */
extern kern_return_t	kmem_suballoc(vm_map_t	parent,
									  vm_offset_t	*addr,
									  vm_size_t	size,
									  boolean_t	pageable,
									  int		flags,
									  vm_map_t	*new_map);

#endif /* _KERNEL */

typedef int page_t;

void *segkmem_alloc(vmem_t *vmp, size_t size, int vmflag);
void segkmem_free(vmem_t *vmp, void *inaddr, size_t size);

/* Total memory held allocated */
uint64_t segkmem_total_mem_allocated = 0;

//extern ulong_t *segkp_bitmap;   /* Is set if segkp is from the kernel heap */

char *kernelheap;		/* start of primary kernel heap */
char *ekernelheap;		/* end of primary kernel heap */
//struct seg kvseg;		/* primary kernel heap segment */
//struct seg kvseg_core;		/* "core" kernel heap segment */
//struct seg kzioseg;		/* Segment for zio mappings */
vmem_t *heap_arena;		/* primary kernel heap arena */
//vmem_t *heap_core_arena;	/* core kernel heap arena */
//char *heap_core_base;		/* start of core kernel heap arena */
//char *heap_lp_base;		/* start of kernel large page heap arena */
//char *heap_lp_end;		/* end of kernel large page heap arena */
//vmem_t *hat_memload_arena;	/* HAT translation data */
//struct seg kvseg32;		/* 32-bit kernel heap segment */
//vmem_t *heap32_arena;		/* 32-bit kernel heap arena */
//vmem_t *heaptext_arena;		/* heaptext arena */
//struct as kas;			/* kernel address space */
//int segkmem_reloc;		/* enable/disable relocatable segkmem pages */
//vmem_t *static_arena;		/* arena for caches to import static memory */
//vmem_t *static_alloc_arena;	/* arena for allocating static memory */
vmem_t *zio_arena_parent = NULL;
vmem_t *zio_arena = NULL;	/* arena for allocating zio memory */
vmem_t *zio_alloc_arena = NULL;	/* arena for allocating zio memory */

/*
 * seg_kmem driver can map part of the kernel heap with large pages.
 * Currently this functionality is implemented for sparc platforms only.
 *
 * The large page size "segkmem_lpsize" for kernel heap is selected in the
 * platform specific code. It can also be modified via /etc/system file.
 * Setting segkmem_lpsize to PAGESIZE in /etc/system disables usage of large
 * pages for kernel heap. "segkmem_lpshift" is adjusted appropriately to
 * match segkmem_lpsize.
 *
 * At boot time we carve from kernel heap arena a range of virtual addresses
 * that will be used for large page mappings. This range [heap_lp_base,
 * heap_lp_end) is set up as a separate vmem arena - "heap_lp_arena". We also
 * create "kmem_lp_arena" that caches memory already backed up by large
 * pages. kmem_lp_arena imports virtual segments from heap_lp_arena.
 */

//size_t	segkmem_lpsize;
//static  uint_t	segkmem_lpshift = PAGESHIFT;
//int	segkmem_lpszc = 0;

//size_t  segkmem_kmemlp_quantum = 0x400000;	/* 4MB */
//size_t  segkmem_heaplp_quantum;
//vmem_t *heap_lp_arena;
//static  vmem_t *kmem_lp_arena;
//static  vmem_t *segkmem_ppa_arena;
//static	segkmem_lpcb_t segkmem_lpcb;

/*
 * We use "segkmem_kmemlp_max" to limit the total amount of physical memory
 * consumed by the large page heap. By default this parameter is set to 1/8 of
 * physmem but can be adjusted through /etc/system either directly or
 * indirectly by setting "segkmem_kmemlp_pcnt" to the percent of physmem
 * we allow for large page heap.
 */
//size_t  segkmem_kmemlp_max;
//static  uint_t  segkmem_kmemlp_pcnt;


static void *
osif_malloc(uint64_t size)
{
#ifdef _KERNEL
    void *tr;
    kern_return_t kr;

	printf("osif_malloc: %llu\n", size);
	
    kr = kernel_memory_allocate(kernel_map, &tr, size, PAGESIZE, 0, SPL_TAG);

    if (kr == KERN_SUCCESS) {
        atomic_add_64(&segkmem_total_mem_allocated, size);
        return (tr);
    } else {
        return (NULL);
    }
#else
    return ((void*)malloc(size));
#endif /* _KERNEL */
}

static void
osif_free(void* buf, uint64_t size)
{
#ifdef _KERNEL
	printf("osif_free: %llu\n", size);
    kmem_free(kernel_map, buf, size);
    atomic_sub_64(&segkmem_total_mem_allocated, size);
#else
    free(buf);
#endif /* _KERNEL */
}

/*
 * Initialize kernel heap boundaries.
 */
void
kernelheap_init(
				void *heap_start,
				void *heap_end,
				char *first_avail,
				void *core_start,
				void *core_end)
{
	heap_arena = vmem_init("heap", NULL, 0, PAGESIZE,
						   segkmem_alloc, segkmem_free);

	// FIXME - do we need to do this (below)?
	
	/*
	 * Remove the already-spoken-for memory range [kernelheap, first_avail).
	 */
//	(void) vmem_xalloc(heap_arena, first_avail - kernelheap, PAGESIZE,
//					   0, 0, kernelheap, first_avail, VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
}


void kernelheap_fini(void)
{
	vmem_fini(heap_arena);
}

static void *
segkmem_alloc_vn(vmem_t *vmp, size_t size, int vmflag, struct vnode *vp)
{
	return osif_malloc(size);
}

void *
segkmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_alloc_vn(vmp, size, vmflag, 0 /*&kvp*/));
}

void *
segkmem_zio_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_alloc_vn(vmp, size, vmflag, 0 /*&zvp*/));
}

/*
 * Any changes to this routine must also be carried over to
 * devmap_free_pages() in the seg_dev driver. This is because
 * we currently don't have a special kernel segment for non-paged
 * kernel memory that is exported by drivers to user space.
 */
static void
segkmem_free_vn(vmem_t *vmp, void *inaddr, size_t size, struct vnode *vp,
				void (*func)(page_t *))
{
	osif_free(inaddr, size);
}

void
segkmem_free(vmem_t *vmp, void *inaddr, size_t size)
{
	segkmem_free_vn(vmp, inaddr, size, 0 /*&kvp*/, NULL);
}

void
segkmem_zio_free(vmem_t *vmp, void *inaddr, size_t size)
{
	segkmem_free_vn(vmp, inaddr, size, 0 /*&zvp*/, NULL);
}


void
segkmem_zio_init(void *zio_mem_base, void *zio_mem_end)
{
	size_t heap_size;

	ASSERT(zio_mem_base != NULL);
	ASSERT(zio_mem_end  != NULL);

	/*
	 * To reduce VA space fragmentation, we set up quantum caches for the
	 * smaller sizes;  we chose 32k because that translates to 128k VA
	 * slabs, which matches nicely with the common 128k zio_data bufs.
	 */
	heap_size = (uintptr_t)zio_mem_end - (uintptr_t)zio_mem_base;
	
	zio_arena_parent = vmem_create("zfs_file_data_p", NULL, 0,
							PAGESIZE, NULL, NULL, NULL, 0, VM_SLEEP);
	
	zio_arena = vmem_create("zfs_file_data", NULL, 0,
							PAGESIZE, segkmem_zio_alloc, segkmem_zio_free, zio_arena_parent, 32 * 1024, VM_SLEEP);

	zio_alloc_arena = vmem_create("zfs_file_data_buf", NULL, 0, PAGESIZE,
								  vmem_alloc, vmem_free, zio_arena, 0, VM_SLEEP);

	ASSERT(zio_arena != NULL);
	ASSERT(zio_alloc_arena != NULL);
}

void
segkmem_zio_fini(void)
{
	vmem_destroy(zio_alloc_arena);
	vmem_destroy(zio_arena);
}




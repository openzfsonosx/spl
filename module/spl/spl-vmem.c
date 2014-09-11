#include <sys/vmem_impl.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <spl-bmalloc.h>
//#include <sys/panic.h>

#define	VMEM_INITIAL		10	/* early vmem arenas */
#define	VMEM_SEG_INITIAL	200	/* early segments */

/*
 * Adding a new span to an arena requires two segment structures: one to
 * represent the span, and one to represent the free segment it contains.
 */
#define	VMEM_SEGS_PER_SPAN_CREATE	2

/*
 * Allocating a piece of an existing segment requires 0-2 segment structures
 * depending on how much of the segment we're allocating.
 *
 * To allocate the entire segment, no new segment structures are needed; we
 * simply move the existing segment structure from the freelist to the
 * allocation hash table.
 *
 * To allocate a piece from the left or right end of the segment, we must
 * split the segment into two pieces (allocated part and remainder), so we
 * need one new segment structure to represent the remainder.
 *
 * To allocate from the middle of a segment, we need two new segment strucures
 * to represent the remainders on either side of the allocated part.
 */
#define	VMEM_SEGS_PER_EXACT_ALLOC	0
#define	VMEM_SEGS_PER_LEFT_ALLOC	1
#define	VMEM_SEGS_PER_RIGHT_ALLOC	1
#define	VMEM_SEGS_PER_MIDDLE_ALLOC	2

/*
 * vmem_populate() preallocates segment structures for vmem to do its work.
 * It must preallocate enough for the worst case, which is when we must import
 * a new span and then allocate from the middle of it.
 */
#define	VMEM_SEGS_PER_ALLOC_MAX		\
(VMEM_SEGS_PER_SPAN_CREATE + VMEM_SEGS_PER_MIDDLE_ALLOC)

/*
 * The segment structures themselves are allocated from vmem_seg_arena, so
 * we have a recursion problem when vmem_seg_arena needs to populate itself.
 * We address this by working out the maximum number of segment structures
 * this act will require, and multiplying by the maximum number of threads
 * that we'll allow to do it simultaneously.
 *
 * The worst-case segment consumption to populate vmem_seg_arena is as
 * follows (depicted as a stack trace to indicate why events are occurring):
 *
 * (In order to lower the fragmentation in the heap_arena, we specify a
 * minimum import size for the vmem_metadata_arena which is the same size
 * as the kmem_va quantum cache allocations.  This causes the worst-case
 * allocation from the vmem_metadata_arena to be 3 segments.)
 *
 * vmem_alloc(vmem_seg_arena)		-> 2 segs (span create + exact alloc)
 *  segkmem_alloc(vmem_metadata_arena)
 *   vmem_alloc(vmem_metadata_arena)	-> 3 segs (span create + left alloc)
 *    vmem_alloc(heap_arena)		-> 1 seg (left alloc)
 *   page_create()
 *   hat_memload()
 *    kmem_cache_alloc()
 *     kmem_slab_create()
 *	vmem_alloc(hat_memload_arena)	-> 2 segs (span create + exact alloc)
 *	 segkmem_alloc(heap_arena)
 *	  vmem_alloc(heap_arena)	-> 1 seg (left alloc)
 *	  page_create()
 *	  hat_memload()		-> (hat layer won't recurse further)
 *
 * The worst-case consumption for each arena is 3 segment structures.
 * Of course, a 3-seg reserve could easily be blown by multiple threads.
 * Therefore, we serialize all allocations from vmem_seg_arena (which is OK
 * because they're rare).  We cannot allow a non-blocking allocation to get
 * tied up behind a blocking allocation, however, so we use separate locks
 * for VM_SLEEP and VM_NOSLEEP allocations.  Similarly, VM_PUSHPAGE allocations
 * must not block behind ordinary VM_SLEEPs.  In addition, if the system is
 * panicking then we must keep enough resources for panic_thread to do its
 * work.  Thus we have at most four threads trying to allocate from
 * vmem_seg_arena, and each thread consumes at most three segment structures,
 * so we must maintain a 12-seg reserve.
 */
#define	VMEM_POPULATE_RESERVE	12

/*
 * vmem_populate() ensures that each arena has VMEM_MINFREE seg structures
 * so that it can satisfy the worst-case allocation *and* participate in
 * worst-case allocation from vmem_seg_arena.
 */
#define	VMEM_MINFREE	(VMEM_POPULATE_RESERVE + VMEM_SEGS_PER_ALLOC_MAX)

static vmem_t vmem0[VMEM_INITIAL];
static uint32_t vmem_id;
#if 0
static vmem_t *vmem_populator[VMEM_INITIAL];
static uint32_t vmem_populators;
static vmem_seg_t vmem_seg0[VMEM_SEG_INITIAL];
static vmem_seg_t *vmem_segfree;
static kmutex_t vmem_list_lock;
static kmutex_t vmem_segfree_lock;
static kmutex_t vmem_sleep_lock;
static kmutex_t vmem_nosleep_lock;
static kmutex_t vmem_pushpage_lock;
static kmutex_t vmem_panic_lock;
static vmem_t *vmem_list;
static vmem_t *vmem_metadata_arena;
static vmem_t *vmem_seg_arena;
static vmem_t *vmem_hash_arena;
static long vmem_update_interval = 15;	/* vmem_update() every 15 seconds */
#endif
static vmem_t *vmem_vmem_arena;
uint32_t vmem_mtbf;		/* mean time between failures [default: off] */
size_t vmem_seg_size = sizeof (vmem_seg_t);

static vmem_kstat_t vmem_kstat_template = {
	{ "mem_inuse",		KSTAT_DATA_UINT64 },
	{ "mem_import",		KSTAT_DATA_UINT64 },
	{ "mem_total",		KSTAT_DATA_UINT64 },
	{ "vmem_source",	KSTAT_DATA_UINT32 },
	{ "alloc",		KSTAT_DATA_UINT64 },
	{ "free",		KSTAT_DATA_UINT64 },
	{ "wait",		KSTAT_DATA_UINT64 },
	{ "fail",		KSTAT_DATA_UINT64 },
	{ "lookup",		KSTAT_DATA_UINT64 },
	{ "search",		KSTAT_DATA_UINT64 },
	{ "populate_wait",	KSTAT_DATA_UINT64 },
	{ "populate_fail",	KSTAT_DATA_UINT64 },
	{ "contains",		KSTAT_DATA_UINT64 },
	{ "contains_search",	KSTAT_DATA_UINT64 },
};

/*
 * Insert/delete from arena list (type 'a') or next-of-kin list (type 'k').
 */
#define	VMEM_INSERT(vprev, vsp, type)					\
{									\
vmem_seg_t *vnext = (vprev)->vs_##type##next;			\
(vsp)->vs_##type##next = (vnext);				\
(vsp)->vs_##type##prev = (vprev);				\
(vprev)->vs_##type##next = (vsp);				\
(vnext)->vs_##type##prev = (vsp);				\
}

#define	VMEM_DELETE(vsp, type)						\
{									\
vmem_seg_t *vprev = (vsp)->vs_##type##prev;			\
vmem_seg_t *vnext = (vsp)->vs_##type##next;			\
(vprev)->vs_##type##next = (vnext);				\
(vnext)->vs_##type##prev = (vprev);				\
}

/*
 * Allocate size bytes from arena vmp.  Returns the allocated address
 * on success, NULL on failure.  vmflag specifies VM_SLEEP or VM_NOSLEEP,
 * and may also specify best-fit, first-fit, or next-fit allocation policy
 * instead of the default instant-fit policy.  VM_SLEEP allocations are
 * guaranteed to succeed.
 */
void *
vmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return bmalloc(size, vmflag);
}

/*
 * Free the segment [vaddr, vaddr + size).
 */
void
vmem_free(vmem_t *vmp, void *vaddr, size_t size)
{
	bfree(vaddr, size);
}

/*
 * Create an arena called name whose initial span is [base, base + size).
 * The arena's natural unit of currency is quantum, so vmem_alloc()
 * guarantees quantum-aligned results.  The arena may import new spans
 * by invoking afunc() on source, and may return those spans by invoking
 * ffunc() on source.  To make small allocations fast and scalable,
 * the arena offers high-performance caching for each integer multiple
 * of quantum up to qcache_max.
 */
static vmem_t *
vmem_create_common(const char *name, void *base, size_t size, size_t quantum,
				   void *(*afunc)(vmem_t *, size_t, int),
				   void (*ffunc)(vmem_t *, void *, size_t),
				   vmem_t *source, size_t qcache_max, int vmflag)
{
	size_t nqcache;
	vmem_t *vmp;
	uint32_t id = atomic_inc_32_nv(&vmem_id);

	if (vmem_vmem_arena != NULL) {
		vmp = vmem_alloc(vmem_vmem_arena, sizeof (vmem_t),
						 vmflag & VM_KMFLAGS);
	} else {
		ASSERT(id <= VMEM_INITIAL);
		vmp = &vmem0[id - 1];
	}

	/* An identifier arena must inherit from another identifier arena */
	ASSERT(source == NULL || ((source->vm_cflags & VMC_IDENTIFIER) ==
							  (vmflag & VMC_IDENTIFIER)));

	if (vmp == NULL)
		return (NULL);
	bzero(vmp, sizeof (vmem_t));

	(void) snprintf(vmp->vm_name, VMEM_NAMELEN, "%s", name);
	vmp->vm_cflags = vmflag;
	vmflag &= VM_KMFLAGS;

	vmp->vm_quantum = quantum;
	vmp->vm_qshift = highbit(quantum) - 1;
	nqcache = MIN(qcache_max >> vmp->vm_qshift, VMEM_NQCACHE_MAX);


	bcopy(&vmem_kstat_template, &vmp->vm_kstat, sizeof (vmem_kstat_t));

	vmp->vm_id = id;
	if (source != NULL)
		vmp->vm_kstat.vk_source_id.value.ui32 = source->vm_id;
	vmp->vm_source = source;
	vmp->vm_source_alloc = afunc;
	vmp->vm_source_free = ffunc;

	return (vmp);
}

vmem_t *
vmem_create(const char *name, void *base, size_t size, size_t quantum,
			vmem_alloc_t *afunc, vmem_free_t *ffunc, vmem_t *source,
			size_t qcache_max, int vmflag)
{
	ASSERT(!(vmflag & (VMC_XALLOC | VMC_XALIGN)));
	vmflag &= ~(VMC_XALLOC | VMC_XALIGN);

	return (vmem_create_common(name, base, size, quantum,
							   afunc, ffunc, source, qcache_max, vmflag));
}

/*
 * Destroy arena vmp.
 */
void
vmem_destroy(vmem_t *vmp)
{
	bfree(vmp, sizeof(vmem_t));
}


/*
 * Prepare vmem for use.
 */
vmem_t *
vmem_init(const char *heap_name,
		  void *heap_start, size_t heap_size, size_t heap_quantum,
		  void *(*heap_alloc)(vmem_t *, size_t, int),
		  void (*heap_free)(vmem_t *, void *, size_t))
{
	vmem_t *heap;

	//while (--nseg >= 0)
	//	vmem_putseg_global(&vmem_seg0[nseg]);

	heap = vmem_create(heap_name,
					   heap_start, heap_size, heap_quantum,
					   NULL, NULL, NULL, 0,
					   VM_SLEEP | VMC_POPULATOR);

	return (heap);
}

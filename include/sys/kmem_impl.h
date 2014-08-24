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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_KMEM_IMPL_H
#define	_SYS_KMEM_IMPL_H

#include <sys/kmem.h>
//#include <sys/vmem.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/time.h>
#include <sys/kstat.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
//#include <vm/page.h>
//#include <sys/avl.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
    /*
     * kernel memory allocator: implementation-private data structures
     *
     * Lock order:
     * 1. cache_lock
     * 2. cc_lock in order by CPU ID
     * 3. cache_depot_lock
     *
     * Do not call kmem_cache_alloc() or taskq_dispatch() while holding any of the
     * above locks.
     */
    
#define	KMF_AUDIT	0x00000001	/* transaction auditing */
#define	KMF_DEADBEEF	0x00000002	/* deadbeef checking */
#define	KMF_REDZONE	0x00000004	/* redzone checking */
#define	KMF_CONTENTS	0x00000008	/* freed-buffer content logging */
#define	KMF_STICKY	0x00000010	/* if set, override /etc/system */
#define	KMF_NOMAGAZINE	0x00000020	/* disable per-cpu magazines */
#define	KMF_FIREWALL	0x00000040	/* put all bufs before unmapped pages */
#define	KMF_LITE	0x00000100	/* lightweight debugging */
    
#define	KMF_HASH	0x00000200	/* cache has hash table */
#define	KMF_RANDOMIZE	0x00000400	/* randomize other kmem_flags */
    
#define	KMF_DUMPDIVERT	0x00001000	/* use alternate memory at dump time */
#define	KMF_DUMPUNSAFE	0x00002000	/* flag caches used at dump time */
#define	KMF_PREFILL	0x00004000	/* Prefill the slab when created. */
    
#define	KMF_BUFTAG	(KMF_DEADBEEF | KMF_REDZONE)
#define	KMF_TOUCH	(KMF_BUFTAG | KMF_LITE | KMF_CONTENTS)
#define	KMF_RANDOM	(KMF_TOUCH | KMF_AUDIT | KMF_NOMAGAZINE)
#define	KMF_DEBUG	(KMF_RANDOM | KMF_FIREWALL)
    
#define	KMEM_STACK_DEPTH	15
    
#define	KMEM_FREE_PATTERN		0xdeadbeefdeadbeefULL
#define	KMEM_UNINITIALIZED_PATTERN	0xbaddcafebaddcafeULL
#define	KMEM_REDZONE_PATTERN		0xfeedfacefeedfaceULL
#define	KMEM_REDZONE_BYTE		0xbb
    
    /*
     * Redzone size encodings for kmem_alloc() / kmem_free().  We encode the
     * allocation size, rather than storing it directly, so that kmem_free()
     * can distinguish frees of the wrong size from redzone violations.
     *
     * A size of zero is never valid.
     */
#define	KMEM_SIZE_ENCODE(x)	(251 * (x) + 1)
#define	KMEM_SIZE_DECODE(x)	((x) / 251)
#define	KMEM_SIZE_VALID(x)	((x) % 251 == 1 && (x) != 1)
    
    
#define	KMEM_ALIGN		8	/* min guaranteed alignment */
#define	KMEM_ALIGN_SHIFT	3	/* log2(KMEM_ALIGN) */
#define	KMEM_VOID_FRACTION	8	/* never waste more than 1/8 of slab */
    
#define	KMEM_SLAB_IS_PARTIAL(sp)		\
((sp)->slab_refcnt > 0 && (sp)->slab_refcnt < (sp)->slab_chunks)
#define	KMEM_SLAB_IS_ALL_USED(sp)		\
((sp)->slab_refcnt == (sp)->slab_chunks)
    
    /*
     * The bufctl (buffer control) structure keeps some minimal information
     * about each buffer: its address, its slab, and its current linkage,
     * which is either on the slab's freelist (if the buffer is free), or
     * on the cache's buf-to-bufctl hash table (if the buffer is allocated).
     * In the case of non-hashed, or "raw", caches (the common case), only
     * the freelist linkage is necessary: the buffer address is at a fixed
     * offset from the bufctl address, and the slab is at the end of the page.
     *
     * NOTE: bc_next must be the first field; raw buffers have linkage only.
     */
    typedef struct kmem_bufctl {
        struct kmem_bufctl	*bc_next;	/* next bufctl struct */
        void			*bc_addr;	/* address of buffer */
        struct kmem_slab	*bc_slab;	/* controlling slab */
    } kmem_bufctl_t;
    
    /*
     * The KMF_AUDIT version of the bufctl structure.  The beginning of this
     * structure must be identical to the normal bufctl structure so that
     * pointers are interchangeable.
     */
    typedef struct kmem_bufctl_audit {
        struct kmem_bufctl	*bc_next;	/* next bufctl struct */
        void			*bc_addr;	/* address of buffer */
        struct kmem_slab	*bc_slab;	/* controlling slab */
        kmem_cache_t		*bc_cache;	/* controlling cache */
        hrtime_t		bc_timestamp;	/* transaction time */
        kthread_t		*bc_thread;	/* thread doing transaction */
        struct kmem_bufctl	*bc_lastlog;	/* last log entry */
        void			*bc_contents;	/* contents at last free */
        int			bc_depth;	/* stack depth */
        pc_t			bc_stack[KMEM_STACK_DEPTH];	/* pc stack */
    } kmem_bufctl_audit_t;
    
    /*
     * A kmem_buftag structure is appended to each buffer whenever any of the
     * KMF_BUFTAG flags (KMF_DEADBEEF, KMF_REDZONE, KMF_VERIFY) are set.
     */
    typedef struct kmem_buftag {
        uint64_t		bt_redzone;	/* 64-bit redzone pattern */
        kmem_bufctl_t		*bt_bufctl;	/* bufctl */
        intptr_t		bt_bxstat;	/* bufctl ^ (alloc/free) */
    } kmem_buftag_t;
    
    /*
     * A variant of the kmem_buftag structure used for KMF_LITE caches.
     * Previous callers are stored in reverse chronological order. (i.e. most
     * recent first)
     */
    typedef struct kmem_buftag_lite {
        kmem_buftag_t		bt_buftag;	/* a normal buftag */
        pc_t			bt_history[1];	/* zero or more callers */
    } kmem_buftag_lite_t;
    
#define	KMEM_BUFTAG_LITE_SIZE(f)	\
(offsetof(kmem_buftag_lite_t, bt_history[f]))
    
#define	KMEM_BUFTAG(cp, buf)		\
((kmem_buftag_t *)((char *)(buf) + (cp)->cache_buftag))
    
#define	KMEM_BUFCTL(cp, buf)		\
((kmem_bufctl_t *)((char *)(buf) + (cp)->cache_bufctl))
    
#define	KMEM_BUF(cp, bcp)		\
((void *)((char *)(bcp) - (cp)->cache_bufctl))
    
#define	KMEM_SLAB(cp, buf)		\
((kmem_slab_t *)P2END((uintptr_t)(buf), (cp)->cache_slabsize) - 1)
    
    /*
     * Test for using alternate memory at dump time.
     */
#define	KMEM_DUMP(cp)		((cp)->cache_flags & KMF_DUMPDIVERT)
#define	KMEM_DUMPCC(ccp)	((ccp)->cc_flags & KMF_DUMPDIVERT)
    
    /*
     * The "CPU" macro loads a cpu_t that refers to the cpu that the current
     * thread is running on at the time the macro is executed.  A context switch
     * may occur immediately after loading this data structure, leaving this
     * thread pointing at the cpu_t for the previous cpu.  This is not a problem;
     * we'd just end up checking the previous cpu's per-cpu cache, and then check
     * the other layers of the kmem cache if need be.
     *
     * It's not even a problem if the old cpu gets DR'ed out during the context
     * switch.  The cpu-remove DR operation bzero()s the cpu_t, but doesn't free
     * it.  So the cpu_t's cpu_cache_offset would read as 0, causing us to use
     * cpu 0's per-cpu cache.
     *
     * So, there is no need to disable kernel preemption while using the CPU macro
     * below since if we have been context switched, there will not be any
     * correctness problem, just a momentary use of a different per-cpu cache.
     */
    
#define	KMEM_CPU_CACHE(cp)						\
((kmem_cpu_cache_t *)((char *)(&cp->cache_cpu) + CPU->cpu_cache_offset))
    
#define	KMEM_MAGAZINE_VALID(cp, mp)	\
(((kmem_slab_t *)P2END((uintptr_t)(mp), PAGESIZE) - 1)->slab_cache == \
(cp)->cache_magtype->mt_cache)
    
#define	KMEM_SLAB_OFFSET(sp, buf)	\
((size_t)((uintptr_t)(buf) - (uintptr_t)((sp)->slab_base)))
    
#define	KMEM_SLAB_MEMBER(sp, buf)	\
(KMEM_SLAB_OFFSET(sp, buf) < (sp)->slab_cache->cache_slabsize)
    
#define	KMEM_BUFTAG_ALLOC	0xa110c8edUL
#define	KMEM_BUFTAG_FREE	0xf4eef4eeUL
    
    /* slab_later_count thresholds */
#define	KMEM_DISBELIEF		3
    
    /* slab_flags */
#define	KMEM_SLAB_NOMOVE	0x1
#define	KMEM_SLAB_MOVE_PENDING	0x2
   
#define KMEM_CACHE_NAMELEN 31


#endif
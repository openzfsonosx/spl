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
 *  Solaris Porting Layer (SPL) Atomic Implementation.
\*****************************************************************************/

#include <sys/atomic.h>
#include <sys/kernel.h>
#include <libkern/OSAtomic.h>


#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
//#include <sys/atomic.h>

/*
 * *******************************************************
 *
 * KERNEL
 *
 * *******************************************************
 */

#ifdef _KERNEL


#include <sys/kernel.h>

#include <libkern/OSAtomic.h>

//struct mutex_t atomic_mtx;
//MTX_SYSINIT(atomic, &atomic_mtx, "atomic", MTX_DEF);



/* NOTE:
 * Mac OSX atomic operations return value is the number
 * BEFORE it is atomically incremented or decremented.
 * This is opposite that of Solaris.
 * We need a real KPI for this functionality!
 */
SInt64
OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address)
{
	SInt64 value = OSAddAtomic64(theAmount, address);
	/* the store to "*address" will be atomic, but we need to recalculate what it would be here */
	return value + theAmount;
}


#if !defined(__i386__) && !defined(__x86_64__)
/*
 * Emulated for architectures that don't have this primitive. Do an atomic
 * add for the low order bytes, try to detect overflow/underflow, and
 * update the high order bytes. The second update is definitely not
 * atomic, but it's better than nothing.
 */
SInt64
OSAddAtomic64(SInt64 theAmount, volatile SInt64 *address)
{
	volatile SInt32 *lowaddr;
	volatile SInt32 *highaddr;
	SInt32 highword;
	SInt32 lowword;

#ifdef __BIG_ENDIAN__
	highaddr = (volatile SInt32 *)address;
	lowaddr = highaddr + 1;
#else
	lowaddr = (volatile SInt32 *)address;
	highaddr = lowaddr + 1;
#endif

	highword = *highaddr;
	lowword = OSAddAtomic((SInt32)theAmount, lowaddr); // lowword is the old value
	if ((theAmount < 0) && (lowword < -theAmount)) {
		// underflow, decrement the high word
		(void)OSAddAtomic(-1, highaddr);
	} else if ((theAmount > 0) && ((UInt32)lowword > 0xFFFFFFFF-theAmount)) {
		// overflow, increment the high word
		(void)OSAddAtomic(1, highaddr);
	}
	return ((SInt64)highword << 32) | ((UInt32)lowword);
}

SInt64
OSIncrementAtomic64(volatile SInt64 *address)
{
	return OSAddAtomic64(1, address);
}
#endif  /* !__i386__ && !__x86_64__ */



uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t new)
{
	uint32_t old = *target;

	OSCompareAndSwap( cmp, new, (volatile UInt32 *)target );
	return old;
}

/*
 * This operation is not thread-safe and the user must
 * protect it my some other means.  The only known caller
 * is zfs_vnop_write() and the value is protected by the
 * znode's mutex.
 */
uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t new)
{
	uint64_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

void *
atomic_cas_ptr(volatile void *target, void *cmp, void *new)
{
	void *old = *(void **)target;

#ifdef __LP64__
	OSCompareAndSwapPtr(cmp, new, target);
#else
	OSCompareAndSwap( (uint32_t)cmp, (uint32_t)new, (unsigned long *)target );
#endif
	return old;
}



SInt32 atomic_inc_32_nv(volatile SInt32 *addr)
{
	SInt64 value = OSIncrementAtomic(addr);
    return value+1;
}

SInt32 atomic_dec_32_nv(volatile SInt32 *addr)
{
	SInt64 value = OSDecrementAtomic(addr);
    return value-1;
}



void
membar_producer(void)
{
	/* nothing */
}


/*
 * *******************************************************
 *
 * USERLAND / pthread
 *
 * *******************************************************
 */


#else

#include <pthread.h>

#define	mtx_lock(lock)		pthread_mutex_lock(lock)
#define	mtx_unlock(lock)	pthread_mutex_unlock(lock)

static pthread_mutex_t atomic_mtx;

static __attribute__((constructor)) void
atomic_init(void)
{
	pthread_mutex_init(&atomic_mtx, NULL);
}

#if !defined(__LP64__) && !defined(__mips_n32)
void
atomic_add_64(volatile uint64_t *target, int64_t delta)
{

	mtx_lock(&atomic_mtx);
	*target += delta;
	mtx_unlock(&atomic_mtx);
}

void
atomic_dec_64(volatile uint64_t *target)
{

	mtx_lock(&atomic_mtx);
	*target -= 1;
	mtx_unlock(&atomic_mtx);
}
#endif

uint64_t
atomic_add_64_nv(volatile uint64_t *target, int64_t delta)
{
	uint64_t newval;

	mtx_lock(&atomic_mtx);
	newval = (*target += delta);
	mtx_unlock(&atomic_mtx);
	return (newval);
}

#if defined(__powerpc__) || defined(__arm__) || defined(__mips__)
void
atomic_or_8(volatile uint8_t *target, uint8_t value)
{
	mtx_lock(&atomic_mtx);
	*target |= value;
	mtx_unlock(&atomic_mtx);
}
#endif

uint8_t
atomic_or_8_nv(volatile uint8_t *target, uint8_t value)
{
	uint8_t newval;

	mtx_lock(&atomic_mtx);
	newval = (*target |= value);
	mtx_unlock(&atomic_mtx);
	return (newval);
}

uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t newval)
{
	uint64_t oldval;

	mtx_lock(&atomic_mtx);
	oldval = *target;
	if (oldval == cmp)
		*target = newval;
	mtx_unlock(&atomic_mtx);
	return (oldval);
}

uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t newval)
{
	uint32_t oldval;

	mtx_lock(&atomic_mtx);
	oldval = *target;
	if (oldval == cmp)
		*target = newval;
	mtx_unlock(&atomic_mtx);
	return (oldval);
}

void
membar_producer(void)
{
	/* nothing */
}


#endif

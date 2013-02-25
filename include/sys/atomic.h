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
\*****************************************************************************/

#ifndef _SPL_ATOMIC_H
#define _SPL_ATOMIC_H

//#include <linux/module.h>
//#include <linux/spinlock.h>
#include <libkern/OSAtomic.h>
#include <sys/types.h>
#include <osx/atomic.h>

#ifndef HAVE_ATOMIC64_CMPXCHG
#define atomic64_cmpxchg(v, o, n)       (cmpxchg(&((v)->counter), (o), (n)))
#endif

#ifndef HAVE_ATOMIC64_XCHG
#define atomic64_xchg(v, n)             (xchg(&((v)->counter), n))
#endif



/*
 * Increment target.
 */
#define atomic_inc_8(addr)  (void)OSIncrementAtomic8((volatile SInt8 *)addr)
#define atomic_inc_16(addr) (void)OSIncrementAtomic16((volatile SInt16 *)addr)
#define atomic_inc_32(addr) (void)OSIncrementAtomic((volatile SInt32 *)addr)
#define atomic_inc_64(addr) (void)OSIncrementAtomic64((volatile SInt64 *)addr)

extern SInt32 atomic_inc_32_nv(volatile SInt32 *);


/*
 * Decrement target
 */
#define atomic_dec_8(addr)  (void)OSDecrementAtomic8((volatile SInt8 *)addr)
#define atomic_dec_16(addr) (void)OSDecrementAtomic16((volatile SInt16 *)addr)
#define atomic_dec_32(addr) (void)OSDecrementAtomic((volatile SInt32 *)addr)
#define atomic_dec_64(addr) (void)OSDecrementAtomic64((volatile SInt64 *)addr)

extern SInt32 atomic_dec_32_nv(volatile SInt32 *);

/*
 * Add delta to target
 */
#define atomic_add_8(addr,amt)  (void)OSAddAtomic8(amt, (volatile SInt8 *)addr)
#define atomic_add_16(addr,amt) (void)OSAddAtomic16(amt, (volatile SInt16 *)addr)
#define atomic_add_32(addr,amt) (void)OSAddAtomic(amt, (volatile SInt32 *)addr)
#define atomic_add_64(addr,amt) (void)OSAddAtomic64(amt, (volatile SInt64 *)addr)

extern SInt64 OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address);
#define atomic_add_64_nv(addr, amt)     (uint64_t)OSAddAtomic64_NV(amt, (volatile SInt64 *)addr)

#define atomic_sub_64(addr,amt) (void)OSAddAtomic64(-(amt), (volatile SInt64 *)addr)

/*
 * logical OR bits with target
 */
#define atomic_or_8(addr, mask)  (void)OSBitOrAtomic8((UInt32)mask, (volatile UInt8 *)addr)
#define atomic_or_16(addr, mask) (void)OSBitOrAtomic16((UInt32)mask, (volatile UInt16 *)addr)
#define atomic_or_32(addr, mask) (void)OSBitOrAtomic((UInt32)mask, (volatile UInt32 *)addr)

/*
 * logical AND bits with target
 */
#define atomic_and_8(addr, mask)  (void)OSBitAndAtomic8((UInt32)mask, (volatile UInt8 *)addr)
#define atomic_and_16(addr, mask) (void)OSBitAndAtomic16((UInt32)mask, (volatile UInt16 *)addr)
#define atomic_and_32(addr, mask) (void)OSBitAndAtomic((UInt32)mask, (volatile UInt32 *)addr)

/*
 * *arg1 == arg2, set *arg1 = arg3; return old value
 */
extern uint8_t  atomic_cas_8(  volatile uint8_t *, uint8_t, uint8_t);
extern uint16_t atomic_cas_16( volatile uint16_t *, uint16_t, uint16_t);
extern uint32_t atomic_cas_32( volatile uint32_t *, uint32_t, uint32_t);
extern uint64_t atomic_cas_64( volatile uint64_t *, uint64_t, uint64_t);
extern void    *atomic_cas_ptr(volatile void *, void *, void *);





#endif  /* _SPL_ATOMIC_H */

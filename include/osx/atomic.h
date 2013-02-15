#ifndef OSX_ATOMIC_H
#define OSX_ATOMIC_H

#include <sys/types.h>
//#include <machine/atomic.h>
#include <sys/kernel.h>
#include <libkern/OSAtomic.h>

#define casptr(_a, _b, _c)      \
    atomic_cmpset_ptr((volatile uintptr_t *)(_a), (uintptr_t)(_b), (uintptr_t) (_c))
#define cas32   atomic_cmpset_32

#if !defined(__LP64__) && !defined(__mips_n32)
extern void atomic_add_64(volatile uint64_t *target, int64_t delta);
extern void atomic_dec_64(volatile uint64_t *target);
#endif
#ifndef __sparc64__
extern uint32_t atomic_cas_32(volatile uint32_t *target, uint32_t cmp,
    uint32_t newval);
extern uint64_t atomic_cas_64(volatile uint64_t *target, uint64_t cmp,
    uint64_t newval);
#endif
extern uint64_t atomic_add_64_nv(volatile uint64_t *target, int64_t delta);
extern uint8_t atomic_or_8_nv(volatile uint8_t *target, uint8_t value);
extern void membar_producer(void);


#endif

/*****************************************************************************\
 *
 * OSX Atomic functions using GCC builtins.
 *
 * Jorgen Lundman <lundman@lundman.net>
 *
\*****************************************************************************/

#ifndef _SPL_ATOMIC_H
#define _SPL_ATOMIC_H

#include <libkern/OSAtomic.h>
#include <sys/types.h>
#include <osx/atomic.h>



/*
 *
 * GCC atomic versions. These are preferrable once we sort out compatibility
 * issues with GCC versions?
 */

/* The _nv variants return the NewValue */

/*
 * Increment target
 */
static inline void atomic_inc_8(volatile uint8_t *target)
{
    __sync_fetch_and_add(target, 1);
}
static inline void atomic_inc_16(volatile uint16_t *target)
{
    __sync_fetch_and_add(target, 1);
}
static inline void atomic_inc_32(volatile uint32_t *target)
{
    __sync_fetch_and_add(target, 1);
}
static inline void atomic_inc_64(volatile uint64_t *target)
{
    __sync_fetch_and_add(target, 1);
}
static inline int32_t atomic_inc_32_nv(volatile uint32_t *target)
{
    return __sync_add_and_fetch(target, 1);
}
static inline int64_t atomic_inc_64_nv(volatile uint64_t *target)
{
    return __sync_add_and_fetch(target, 1);
}



/*
 * Decrement target
 */
static inline void atomic_dec_8(volatile uint8_t *target)
{
    __sync_fetch_and_sub(target, 1);
}
static inline void atomic_dec_16(volatile uint16_t *target)
{
    __sync_fetch_and_sub(target, 1);
}
static inline void atomic_dec_32(volatile uint32_t *target)
{
    __sync_fetch_and_sub(target, 1);
}
static inline void atomic_dec_64(volatile uint64_t *target)
{
    __sync_fetch_and_sub(target, 1);
}
static inline int32_t atomic_dec_32_nv(volatile uint32_t *target)
{
    return __sync_sub_and_fetch(target, 1);
}
static inline int64_t atomic_dec_64_nv(volatile uint64_t *target)
{
    return __sync_sub_and_fetch(target, 1);
}




/*
 * Add delta to target
 */
static inline void
atomic_add_8(volatile uint8_t *target, int8_t delta)
{
    __sync_add_and_fetch(target, delta);
}
static inline void
atomic_add_16(volatile uint16_t *target, int16_t delta)
{
    __sync_add_and_fetch(target, delta);
}
static inline void
atomic_add_32(volatile uint32_t *target, int32_t delta)
{
    __sync_add_and_fetch(target, delta);
}
static inline void
atomic_add_64(volatile uint64_t *target, int64_t delta)
{
    __sync_add_and_fetch(target, delta);
}
static inline uint64_t
atomic_add_64_nv(volatile uint64_t *target, int64_t delta)
{
    return  __sync_add_and_fetch(target, delta);
}


/*
 * Subtract delta to target
 */
static inline void
atomic_sub_8(volatile uint8_t *target, int8_t delta)
{
    __sync_sub_and_fetch(target, delta);
}
static inline void
atomic_sub_16(volatile uint16_t *target, int16_t delta)
{
    __sync_sub_and_fetch(target, delta);
}
static inline void
atomic_sub_32(volatile uint32_t *target, int32_t delta)
{
    __sync_sub_and_fetch(target, delta);
}
static inline void
atomic_sub_64(volatile uint64_t *target, int64_t delta)
{
    __sync_sub_and_fetch(target, delta);
}
static inline uint64_t
atomic_sub_64_nv(volatile uint64_t *target, int64_t delta)
{
    return  __sync_sub_and_fetch(target, delta);
}


/*
 * logical OR bits with target
 */
static inline void
atomic_or_8(volatile uint8_t *target, uint8_t mask)
{
    __sync_or_and_fetch(target, mask);
}
static inline void
atomic_or_16(volatile uint16_t *target, uint16_t mask)
{
    __sync_or_and_fetch(target, mask);
}
static inline void
atomic_or_32(volatile uint32_t *target, uint32_t mask)
{
    __sync_or_and_fetch(target, mask);
}


/*
 * logical AND bits with target
 */
static inline void
atomic_and_8(volatile uint8_t *target, uint8_t mask)
{
    __sync_and_and_fetch(target, mask);
}
static inline void
atomic_and_16(volatile uint16_t *target, uint16_t mask)
{
    __sync_and_and_fetch(target, mask);
}
static inline void
atomic_and_32(volatile uint32_t *target, uint32_t mask)
{
    __sync_and_and_fetch(target, mask);
}


/*
 * Compare And Set
 * if *arg1 == arg2, then set *arg1 = arg3; return old value.
 */

static inline uint8_t
atomic_cas_8(volatile uint8_t *target, uint8_t cmp, uint8_t new)
{
    return __sync_val_compare_and_swap(target, cmp, new);
}
static inline uint16_t
atomic_cas_16(volatile uint16_t *target, uint16_t cmp, uint16_t new)
{
    return __sync_val_compare_and_swap(target, cmp, new);
}
static inline uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t new)
{
    return __sync_val_compare_and_swap(target, cmp, new);
}
static inline uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t new)
{
    return __sync_val_compare_and_swap(target, cmp, new);
}

extern void *atomic_cas_ptr(volatile void *target, void *cmp, void *new);

static inline void membar_producer(void) { /* nothing */ }


#endif  /* _SPL_ATOMIC_H */

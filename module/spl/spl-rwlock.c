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

#include <sys/rwlock.h>
#include <kern/debug.h>
#include <sys/atomic.h>
#include <sys/mutex.h>

static lck_attr_t       *zfs_rwlock_attr = NULL;
static lck_grp_attr_t   *zfs_rwlock_group_attr = NULL;
static lck_grp_t  *zfs_rwlock_group = NULL;

void
rw_init(krwlock_t *rwlp, char *name, krw_type_t type, __unused void *arg)
{
    ASSERT(type != RW_DRIVER);

    lck_rw_init((lck_rw_t *)&rwlp->rw_lock[0],
                zfs_rwlock_group, zfs_rwlock_attr);
    rwlp->rw_owner = NULL;
    rwlp->rw_readers = 0;
#ifdef SPL_DEBUG
	rwlp->rw_pad = 0x012345678;
#endif
}

void
rw_destroy(krwlock_t *rwlp)
{
    lck_rw_destroy((lck_rw_t *)&rwlp->rw_lock[0], zfs_rwlock_group);
#ifdef SPL_DEBUG
	rwlp->rw_pad = 0x99;
#endif
}

void
rw_enter(krwlock_t *rwlp, krw_t rw)
{
#ifdef SPL_DEBUG
	if (rwlp->rw_pad != 0x012345678)
		panic("rwlock %p not initialised\n", rwlp);
#endif

    if (rw == RW_READER) {
        lck_rw_lock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
        atomic_inc_32((volatile uint32_t *)&rwlp->rw_readers);
        ASSERT(rwlp->rw_owner == 0);
    } else {
        if (rwlp->rw_owner == current_thread())
            panic("rw_enter: locking against myself!");
        lck_rw_lock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
        ASSERT(rwlp->rw_owner == 0);
        ASSERT(rwlp->rw_readers == 0);
        rwlp->rw_owner = current_thread();
    }
}

/*
 * kernel private from osfmk/kern/locks.h
 */
extern boolean_t lck_rw_try_lock(lck_rw_t *lck, lck_rw_type_t lck_rw_type);

int
rw_tryenter(krwlock_t *rwlp, krw_t rw)
{
    int held = 0;

#ifdef SPL_DEBUG
	if (rwlp->rw_pad != 0x012345678)
		panic("rwlock %p not initialised\n", rwlp);
#endif

    if (rw == RW_READER) {
        held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
                               LCK_RW_TYPE_SHARED);
        if (held)
            atomic_inc_32((volatile uint32_t *)&rwlp->rw_readers);
    } else {
        if (rwlp->rw_owner == current_thread())
            panic("rw_tryenter: locking against myself!");
        held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
                               LCK_RW_TYPE_EXCLUSIVE);
        if (held)
            rwlp->rw_owner = current_thread();
    }

    return (held);
}


int
rw_tryupgrade(krwlock_t *rwlp)
{

    atomic_dec_32((volatile uint32_t *)&rwlp->rw_readers);

	if (lck_rw_lock_shared_to_exclusive(
			(lck_rw_t *)&rwlp->rw_lock[0]) == FALSE) {
		return 0;
	}

	rwlp->rw_owner = current_thread();
    return (1);
}

void
rw_exit(krwlock_t *rwlp)
{
    if (rwlp->rw_owner == current_thread()) {
        rwlp->rw_owner = NULL;
        ASSERT(rwlp->rw_readers == 0);
        lck_rw_unlock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
    } else {
        atomic_dec_32((volatile uint32_t *)&rwlp->rw_readers);
        ASSERT(rwlp->rw_owner == 0);
        lck_rw_unlock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
    }
}


int
rw_lock_held(krwlock_t *rwlp)
{
    /*
     * ### not sure about this one ###
     */
    return (rwlp->rw_owner == current_thread() || rwlp->rw_readers > 0);
}

int
rw_write_held(krwlock_t *rwlp)
{
    return (rwlp->rw_owner == current_thread());
}

void
rw_downgrade(krwlock_t *rwlp)
{
    rwlp->rw_owner = NULL;
    lck_rw_lock_exclusive_to_shared((lck_rw_t *)&rwlp->rw_lock[0]);
    atomic_inc_32((volatile uint32_t *)&rwlp->rw_readers);
}

int spl_rwlock_init(void)
{
    zfs_rwlock_attr = lck_attr_alloc_init();
    zfs_rwlock_group_attr = lck_grp_attr_alloc_init();
    zfs_rwlock_group = lck_grp_alloc_init("zfs-rwlock", zfs_rwlock_group_attr);
    return 0;
}

void spl_rwlock_fini(void)
{
    lck_grp_free(zfs_rwlock_group);
    zfs_rwlock_group = NULL;

    lck_grp_attr_free(zfs_rwlock_group_attr);
    zfs_rwlock_group_attr = NULL;

    lck_attr_free(zfs_rwlock_attr);
    zfs_rwlock_attr = NULL;
}

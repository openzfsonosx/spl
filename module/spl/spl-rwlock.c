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
 *  Solaris Porting Layer (SPL) Reader/Writer Lock Implementation.
\*****************************************************************************/

#include <sys/rwlock.h>
#include <kern/debug.h>
#include <sys/atomic.h>

extern lck_attr_t *zfs_lock_attr;
static lck_grp_t  *zfs_rwlock_group = NULL;


void
rw_init(krwlock_t *rwlp, char *name, krw_type_t type, __unused void *arg)
{
    ASSERT(type != RW_DRIVER);

    lck_rw_init((lck_rw_t *)&rwlp->rw_lock[0],
                zfs_rwlock_group, zfs_lock_attr);
    rwlp->rw_owner = NULL;
    rwlp->rw_readers = 0;
}

void
rw_destroy(krwlock_t *rwlp)
{
    lck_rw_destroy((lck_rw_t *)&rwlp->rw_lock[0], zfs_rwlock_group);
}

void
rw_enter(krwlock_t *rwlp, krw_t rw)
{
    if (rw == RW_READER) {
        lck_rw_lock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
        atomic_inc_32((volatile uint32_t *)&rwlp->rw_readers);
    } else {
        if (rwlp->rw_owner == current_thread())
            panic("rw_enter: locking against myself!");
        lck_rw_lock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
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


/*
 * Not supported in Mac OS X kernel.
 */
int
rw_tryupgrade(krwlock_t *rwlp)
{
    return (0);
}

void
rw_exit(krwlock_t *rwlp)
{
    if (rwlp->rw_owner == current_thread()) {
        rwlp->rw_owner = NULL;
        lck_rw_unlock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
    } else {
        atomic_dec_32((volatile uint32_t *)&rwlp->rw_readers);
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
    zfs_rwlock_group = lck_grp_alloc_init("zfs-rwlock", zfs_group_attr);
    return 0;
}

void spl_rwlock_fini(void)
{
    lck_grp_free(zfs_rwlock_group);
    zfs_rwlock_group = NULL;
}


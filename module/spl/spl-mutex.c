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
 *  Solaris Porting Layer (SPL) Mutex Implementation.
\*****************************************************************************/

#include <sys/mutex.h>


#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <sys/mutex.h>
#include <string.h>
#include <sys/debug.h>
#include <kern/debug.h>
#include <sys/thread.h>

// Not defined in headers
extern boolean_t lck_mtx_try_lock(lck_mtx_t *lck);


lck_attr_t       *zfs_lock_attr = NULL;
lck_grp_attr_t   *zfs_group_attr = NULL;

static lck_grp_t *zfs_mutex_group = NULL;


#define MUTEX_INIT_VAL 0x0123456789abcdef


int spl_mutex_subsystem_init(void)
{
    zfs_lock_attr = lck_attr_alloc_init();
    zfs_group_attr = lck_grp_attr_alloc_init();
    zfs_mutex_group  = lck_grp_alloc_init("zfs-mutex", zfs_group_attr);
    return 0;
}



void spl_mutex_subsystem_fini(void)
{
    lck_attr_free(zfs_lock_attr);
    zfs_lock_attr = NULL;

    lck_grp_attr_free(zfs_group_attr);
    zfs_group_attr = NULL;

    lck_grp_free(zfs_mutex_group);
    zfs_mutex_group = NULL;
}


void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
{
    ASSERT(type != MUTEX_SPIN);
    ASSERT(ibc == NULL);

    if (mp->initialized == MUTEX_INIT_VAL)  // Already initialized, leave it.
        return;

    //lck_mtx_init((lck_mtx_t *)&mp->m_lock[0],
    //           zfs_mutex_group, zfs_lock_attr);
    mp->m_lock = lck_mtx_alloc_init(zfs_mutex_group, zfs_lock_attr);
    mp->m_owner = NULL;
    mp->initialized = MUTEX_INIT_VAL;
}

void spl_mutex_destroy(kmutex_t *mp)
{
    if (!mp) return;
    if (mp->initialized==MUTEX_INIT_VAL)
        lck_mtx_free(mp->m_lock, zfs_mutex_group);
    mp->initialized = 0;
    //lck_mtx_destroy((lck_mtx_t *)&mp->m_lock[0], zfs_mutex_group);
}

void mutex_enter(kmutex_t *mp)
{
    if (mp->initialized!=MUTEX_INIT_VAL) {
        printf("mutex_enter: not initialized %p, I'll do it now.\n",
               mp);
        spl_mutex_init(mp, "AutoInit", 0, NULL);
    }

    if (mp->m_owner == current_thread())
        panic("mutex_enter: locking against myself!");

    //lck_mtx_lock((lck_mtx_t *)&mp->m_lock[0]);
    lck_mtx_lock(mp->m_lock);
    mp->m_owner = current_thread();
}

void spl_mutex_exit(kmutex_t *mp)
{
    mp->m_owner = NULL;
    //lck_mtx_unlock((lck_mtx_t *)&mp->m_lock[0]);
    lck_mtx_unlock(mp->m_lock);
}


int spl_mutex_tryenter(kmutex_t *mp)
{
    int held;

    if (mp->initialized!=MUTEX_INIT_VAL) {
        printf("mutex_enter: not initialized %p, I'll do it now.\n",
               mp);
        spl_mutex_init(mp, "AutoInit", 0, NULL);
    }

    if (mp->m_owner == current_thread())
        panic("mutex_tryenter: locking against myself!");

    //held = lck_mtx_try_lock((lck_mtx_t *)&mp->m_lock[0]);
    held = lck_mtx_try_lock(mp->m_lock);
    if (held)
        mp->m_owner = current_thread();
    return (held);
}

int spl_mutex_owned(kmutex_t *mp)
{
    return (mp->m_owner == current_thread());
}

struct thread *spl_mutex_owner(kmutex_t *mp)
{
    return (mp->m_owner);
}

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
 *  Solaris Porting Layer (SPL) Credential Implementation.
\*****************************************************************************/

#include <sys/condvar.h>
#include <spl-debug.h>
#include <sys/errno.h>


void
spl_cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg)
{
    cvp->cv_waiters = 0;
}

void
spl_cv_destroy(kcondvar_t *cvp)
{
}

void
spl_cv_signal(kcondvar_t *cvp)
{
    if (cvp->cv_waiters > 0) {
        wakeup_one((caddr_t)cvp);
        --cvp->cv_waiters;
    }
}

void
spl_cv_broadcast(kcondvar_t *cvp)
{
    if (cvp->cv_waiters > 0) {
        wakeup((caddr_t)cvp);
        cvp->cv_waiters = 0;
    }
}


/*
 * Block on the indicated condition variable and
 * release the associated mutex while blocked.
 */
void
spl_cv_wait(kcondvar_t *cvp, kmutex_t *mp, const char *msg)
{
    if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */

    ++cvp->cv_waiters;

    mp->m_owner = NULL;
    (void) msleep(cvp, (lck_mtx_t *)mp->m_lock, PRIBIO, msg, 0);
    //(void) msleep(cvp, (lck_mtx_t *)&mp->m_lock[0], PRIBIO, msg, 0);
    mp->m_owner = current_thread();
}

/*
 * Same as cv_wait except the thread will unblock at 'tim'
 * (an absolute time) if it hasn't already unblocked.
 *
 * Returns the amount of time left from the original 'tim' value
 * when it was unblocked.
 */
int
spl_cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, const char *msg)
{
    struct timespec ts;
    int result;

    if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */

    ts.tv_sec = MAX(1, (tim - zfs_lbolt()) / hz);
    ts.tv_nsec = 0;
#if 1
    if (ts.tv_sec < 1)
        ts.tv_sec = 1;
#endif
    if (ts.tv_sec > 1000)
        printf("cv_timedwait: will wait %ds\n", ts.tv_sec);

    ++cvp->cv_waiters;

    mp->m_owner = NULL;
    //result = msleep(cvp, (lck_mtx_t *)&mp->m_lock[0], PRIBIO, msg, &ts);
    result = msleep(cvp, mp->m_lock, PRIBIO, msg, &ts);
    mp->m_owner = current_thread();

    return (result == EWOULDBLOCK ? -1 : 0);

}

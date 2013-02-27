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

#ifndef _SPL_THREAD_H
#define _SPL_THREAD_H

//#include <linux/module.h>
//#include <linux/mm.h>
//#include <linux/spinlock.h>
//#include <linux/kthread.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/tsd.h>
#include <sys/condvar.h>


typedef struct kthread kthread_t;

/*
 * Thread interfaces
 */
#define TP_MAGIC			0x53535353

#define TS_FREE         0x00    /* Thread at loose ends */
#define TS_SLEEP        0x01    /* Awaiting an event */
#define TS_RUN          0x02    /* Runnable, but not yet on a processor */
#define TS_ONPROC       0x04    /* Thread is being run on a processor */
#define TS_ZOMB         0x08    /* Thread has died but hasn't been reaped */
#define TS_STOPPED      0x10    /* Stopped, initial state */
#define TS_WAIT         0x20    /* Waiting to become runnable */


typedef void (*thread_func_t)(void *);


//#define curthread       ((void *)(uintptr_t)thr_self())
#define       curthread       (current_thread())    /* current thread pointer */
#define       curproj         (ttoproj(curthread))    /* current project pointer */

#define thread_join(t)			VERIFY(0)

extern kthread_t *thread_create(
                                caddr_t         stk,
                                size_t          stksize,
                                void            (*proc)(),
                                void            *arg,
                                size_t          len,
                                proc_t          *pp,
                                int             state,
                                pri_t           pri);
extern void thread_exit(void);

#endif  /* _SPL_THREAD_H */

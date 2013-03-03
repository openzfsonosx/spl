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
 *  Solaris Porting Layer (SPL) Thread Implementation.
\*****************************************************************************/

#include <sys/thread.h>
#include <mach/thread_act.h>
#include <sys/kmem.h>
#include <sys/tsd.h>
#include <spl-debug.h>

static uint32_t zfs_threads = 0;

kthread_t *
spl_thread_create(
        caddr_t         stk,
        size_t          stksize,
        void            (*proc)(),
        void            *arg,
        size_t          len,
        proc_t          *pp,
        int             state,
        pri_t           pri)
{
        kern_return_t   result;
        thread_t        thread;

        result = kernel_thread_start((thread_continue_t)proc, arg, &thread);
        if (result != KERN_SUCCESS)
                return (NULL);

        thread_deallocate(thread);

        OSIncrementAtomic((SInt32 *)&zfs_threads);

        return ((kthread_t *)thread);
}


void spl_thread_exit(void)
{
        OSDecrementAtomic((SInt32 *)&zfs_threads);

        (void) thread_terminate(current_thread());
}

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

#include <sys/thread.h>
#include <mach/thread_act.h>
#include <sys/kmem.h>
#include <sys/tsd.h>
#include <spl-debug.h>

uint32_t zfs_threads = 0;

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

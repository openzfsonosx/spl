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

#ifndef _SPL_SIGNAL_H
#define _SPL_SIGNAL_H

#include <osx/sched.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include_next <sys/signal.h>
//#include <sys/signalvar.h>

#define	FORREAL		0	/* Usual side-effects */
#define	JUSTLOOKING	1	/* Don't stop the process */

struct proc;

extern int
thread_issignal(struct proc *, thread_t, sigset_t);

/* The "why" argument indicates the allowable side-effects of the call:
 *
 * FORREAL:  Extract the next pending signal from p_sig into p_cursig;
 * stop the process if a stop has been requested or if a traced signal
 * is pending.
 *
 * JUSTLOOKING:  Don't stop the process, just indicate whether or not
 * a signal might be pending (FORREAL is needed to tell for sure).
 */
#define threadmask (sigmask(SIGILL)|sigmask(SIGTRAP)|\
                    sigmask(SIGIOT)|sigmask(SIGEMT)|\
                    sigmask(SIGFPE)|sigmask(SIGBUS)|\
                    sigmask(SIGSEGV)|sigmask(SIGSYS)|\
                    sigmask(SIGPIPE)|sigmask(SIGKILL)|\
                    sigmask(SIGTERM)|sigmask(SIGINT))

static __inline__ int
issig(int why)
{
    if (why == JUSTLOOKING)
        return (1);
    else
        return (thread_issignal(current_proc(), current_thread(),
                                threadmask));
}

#endif /* SPL_SIGNAL_H */

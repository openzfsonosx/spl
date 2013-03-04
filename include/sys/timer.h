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

#ifndef _SPL_TIMER_H
#define _SPL_TIMER_H

//#include <linux/module.h>
#include <osx/sched.h>
//#include <linux/timer.h>

//#define ddi_get_lbolt()			((clock_t)jiffies)
//#define ddi_get_lbolt64()		((int64_t)get_jiffies_64())

//#define delay(ticks)			schedule_timeout((long)(ticks))


#define USEC_PER_SEC    1000000         /* microseconds per second */

/* Open Solaris lbolt is in hz */
static inline uint64_t
zfs_lbolt(void)
{
    struct timeval tv;
    uint64_t lbolt_hz;
    microuptime(&tv);
    lbolt_hz = ((uint64_t)tv.tv_sec * USEC_PER_SEC + tv.tv_usec) / 10000;
    return (lbolt_hz);
}


#define lbolt zfs_lbolt()
#define lbolt64 zfs_lbolt()

#define        ddi_get_lbolt()         (gethrtime() >> 23)
#define        ddi_get_lbolt64()       (gethrtime() >> 23)

extern void delay(clock_t ticks);


#endif  /* _SPL_TIMER_H */


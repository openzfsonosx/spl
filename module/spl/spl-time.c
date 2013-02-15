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
 *  Solaris Porting Layer (SPL) Time Implementation.
\*****************************************************************************/

#include <sys/sysmacros.h>
#include <sys/time.h>
#include <kern/clock.h>



/*
 * gethrtime() provides high-resolution timestamps with machine-dependent origin
.
 * Hence its primary use is to specify intervals.
 */

static hrtime_t
zfs_abs_to_nano(uint64_t elapsed)
{
    static mach_timebase_info_data_t    sTimebaseInfo = { 0, 0 };

    /*
     * If this is the first time we've run, get the timebase.
     * We can use denom == 0 to indicate that sTimebaseInfo is
     * uninitialised because it makes no sense to have a zero
     * denominator in a fraction.
     */

    if ( sTimebaseInfo.denom == 0 ) {
        (void) clock_timebase_info(&sTimebaseInfo);
    }

    /*
     * Convert to nanoseconds.
     * return (elapsed * (uint64_t)sTimebaseInfo.numer)/(uint64_t)sTimebaseInfo.denom;
     *
     * Provided the final result is representable in 64 bits the following maneuver will
     * deliver that result without intermediate overflow.
     */
    if (sTimebaseInfo.denom == sTimebaseInfo.numer)
        return elapsed;
    else if (sTimebaseInfo.denom == 1)
        return elapsed * (uint64_t)sTimebaseInfo.numer;
    else {
        /* Decompose elapsed = eta32 * 2^32 + eps32: */
        uint64_t eta32 = elapsed >> 32;
        uint64_t eps32 = elapsed & 0x00000000ffffffffLL;

        uint32_t numer = sTimebaseInfo.numer, denom = sTimebaseInfo.denom;

        /* Form product of elapsed64 (decomposed) and numer: */
        uint64_t mu64 = numer * eta32;
        uint64_t lambda64 = numer * eps32;

        /* Divide the constituents by denom: */
        uint64_t q32 = mu64/denom;
        uint64_t r32 = mu64 - (q32 * denom); /* mu64 % denom */

        return (q32 << 32) + ((r32 << 32) + lambda64)/denom;
    }
}


hrtime_t gethrtime(void)
{
    static uint64_t start = 0;
    if (start == 0)
        start = mach_absolute_time();
    return zfs_abs_to_nano(mach_absolute_time() - start);
}


void
gethrestime(struct timespec *ts)
{
    nanotime(ts);
}

time_t
gethrestime_sec(void)
{
    struct timeval tv;

    microtime(&tv);
    return (tv.tv_sec);
}


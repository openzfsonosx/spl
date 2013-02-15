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

#ifndef _SPL_CMN_ERR_H
#define _SPL_CMN_ERR_H

#include <stdarg.h>
#include <sys/varargs.h>

#define CE_CONT         0       /* continuation         */
#define CE_NOTE         1       /* notice               */
#define CE_WARN         2       /* warning              */
#define CE_PANIC        3       /* panic                */
#define CE_IGNORE       4       /* print nothing        */

#ifdef _KERNEL

void kprintf(const char *fmt, ...);

# define cmn_err(ce, fmt, args...)       \
        do {                                 \
                if (ce == CE_PANIC)              \
                        panic(fmt, ##args);          \
                else                             \
                        kprintf(fmt, ##args);        \
        } while(0)

#endif /* _KERNEL */

#define fm_panic	panic

#endif /* SPL_CMN_ERR_H */

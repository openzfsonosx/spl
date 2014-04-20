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
 * Copyright 2010 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


/*
 * Available Solaris debug functions.  All of the ASSERT() macros will be
 * compiled out when NDEBUG is defined, this is the default behavior for
 * the SPL.  To enable assertions use the --enable-debug with configure.
 * The VERIFY() functions are never compiled out and cannot be disabled.
 *
 * PANIC()	- Panic the node and print message.
 * ASSERT()	- Assert X is true, if not panic.
 * ASSERTF()	- Assert X is true, if not panic and print message.
 * ASSERTV()	- Wraps a variable declaration which is only used by ASSERT().
 * ASSERT3S()	- Assert signed X OP Y is true, if not panic.
 * ASSERT3U()	- Assert unsigned X OP Y is true, if not panic.
 * ASSERT3P()	- Assert pointer X OP Y is true, if not panic.
 * VERIFY()	- Verify X is true, if not panic.
 * VERIFY3S()	- Verify signed X OP Y is true, if not panic.
 * VERIFY3U()	- Verify unsigned X OP Y is true, if not panic.
 * VERIFY3P()	- Verify pointer X OP Y is true, if not panic.
 */

#ifndef _SPL_DEBUG_H
#define _SPL_DEBUG_H

#include <spl-debug.h>

#ifndef DEBUG /* Debugging Disabled */

/* Define SPL_DEBUG_STR to make clear which ASSERT definitions are used */
#define SPL_DEBUG_STR	""

#if 0
#define PANIC(fmt, a...)						\
do {									\
	printk(KERN_EMERG fmt, ## a);					\
	spl_debug_bug(__FILE__, __FUNCTION__, __LINE__, 0);		\
} while (0)
#endif
#define	PANIC panic

#define __ASSERT(x)			((void)0)
#define ASSERT(x)			((void)0)
#define ASSERT0(x)			((void)0)
#define ASSERTF(x, y, z...)		((void)0)
#define ASSERTV(x)
#define VERIFY(cond)							\
do {									\
	if (unlikely(!(cond)))						\
		PANIC("VERIFY(" #cond ") failed\n");			\
} while (0)

#define VERIFY0(cond)							\
do {									\
	if (unlikely((cond)!=0))						\
		PANIC("VERIFY0(" #cond ") failed\n");			\
} while (0)

#define VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE, FMT, CAST)			\
do {									\
	if (!((TYPE)(LEFT) OP (TYPE)(RIGHT)))				\
		PANIC("VERIFY3(" #LEFT " " #OP " " #RIGHT ") "		\
		    "failed (" FMT " " #OP " " FMT ")\n",		\
		    CAST (LEFT), CAST (RIGHT));				\
} while (0)

#define VERIFY3S(x,y,z)	VERIFY3_IMPL(x, y, z, int64_t, "%lld", (long long))
#define VERIFY3U(x,y,z)	VERIFY3_IMPL(x, y, z, uint64_t, "%llu",		\
				    (unsigned long long))
#define VERIFY3P(x,y,z)	VERIFY3_IMPL(x, y, z, uintptr_t, "%p", (void *))

#define ASSERT3S(x,y,z)	((void)0)
#define ASSERT3U(x,y,z)	((void)0)
#define ASSERT3P(x,y,z)	((void)0)

#else /* Debugging Enabled */

/* Define SPL_DEBUG_STR to make clear which ASSERT definitions are used */
#define SPL_DEBUG_STR	" (DEBUG mode)"

#define PANIC(fmt, a...)						\
do {									\
	spl_debug_msg(NULL, 0, 0,					\
	     __FILE__, __FUNCTION__, __LINE__,	fmt, ## a);		\
	spl_debug_bug(__FILE__, __FUNCTION__, __LINE__, 0);		\
} while (0)

/* ASSERTION that is safe to use within the debug system */
#define __ASSERT(cond)							\
do {									\
	if (unlikely(!(cond))) {					\
	    printk(KERN_EMERG "ASSERTION(" #cond ") failed\n");		\
	    BUG();							\
	}								\
} while (0)

/* ASSERTION that will debug log used outside the debug sysytem */
#define ASSERT(cond)							\
do {									\
	if (unlikely(!(cond)))						\
		PANIC("ASSERTION(" #cond ") failed\n");			\
} while (0)

#define ASSERT0(cond)	ASSERT((cond)==0)

#define ASSERTF(cond, fmt, a...)					\
do {									\
	if (unlikely(!(cond)))						\
		PANIC("ASSERTION(" #cond ") failed: " fmt, ## a);	\
} while (0)

#define VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE, FMT, CAST)			\
do {									\
	if (!((TYPE)(LEFT) OP (TYPE)(RIGHT)))				\
		PANIC("VERIFY3(" #LEFT " " #OP " " #RIGHT ") "		\
		    "failed (" FMT " " #OP " " FMT ")\n",		\
		    CAST (LEFT), CAST (RIGHT));				\
} while (0)

#define VERIFY3S(x,y,z)	VERIFY3_IMPL(x, y, z, int64_t, "%lld", (long long))
#define VERIFY3U(x,y,z)	VERIFY3_IMPL(x, y, z, uint64_t, "%llu",		\
				    (unsigned long long))
#define VERIFY3P(x,y,z)	VERIFY3_IMPL(x, y, z, uintptr_t, "%p", (void *))

#define ASSERT3S(x,y,z)	VERIFY3S(x, y, z)
#define ASSERT3U(x,y,z)	VERIFY3U(x, y, z)
#define ASSERT3P(x,y,z)	VERIFY3P(x, y, z)

#define ASSERTV(x)	x
#define VERIFY(x)	ASSERT(x)
#define VERIFY0(x)	ASSERT((x)==0)

#endif /* NDEBUG */
#endif /* SPL_DEBUG_H */

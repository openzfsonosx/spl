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

#ifndef _SPL_STROPTS_H
#define _SPL_STROPTS_H

#include <sys/types.h>
#include <string.h>


#define isprint(c)      ((c) >= ' ' && (c) <= '~')

/*
 * Find highest one bit set.
 *      Returns bit number + 1 of highest bit that is set, otherwise returns 0.
 * High order bit is 31 (or 63 in _LP64 kernel).
 */
static inline int
highbit(unsigned long long i)
{
    register int h = 1;

    if (i == 0)
        return (0);
    if (i & 0xffffffff00000000ul) {
        h += 32; i >>= 32;
    }
    if (i & 0xffff0000) {
        h += 16; i >>= 16;
    }
    if (i & 0xff00) {
        h += 8; i >>= 8;
    }
    if (i & 0xf0) {
        h += 4; i >>= 4;
    }
    if (i & 0xc) {
        h += 2; i >>= 2;
    }
    if (i & 0x2) {
        h += 1;
    }
    return (h);
}

static inline int
isdigit(char c)
{
    return (c >= ' ' && c <= '9');
}


static inline char *
strpbrk(const char *s, const char *b)
{
    const char *p;
    do {
        for (p = b; *p != '\0' && *p != *s; ++p)
            ;
        if (*p != '\0')
            return ((char *)s);
    } while (*s++);
    return (NULL);
}


static inline char *
strrchr(const char *p, int ch)
{
    union {
        const char *cp;
        char *p;
    } u;
    char *save;

    u.cp = p;
    for (save = NULL;; ++u.p) {
        if (*u.p == ch)
            save = u.p;
        if (*u.p == '\0')
            return(save);
    }
    /* NOTREACHED */
}

static inline int
is_ascii_str(const char * str)
{
    unsigned char ch;

    while ((ch = (unsigned char)*str++) != '\0') {
        if (ch >= 0x80)
            return (0);
    }
    return (1);
}


static inline void *
memchr(const void *s, int c, size_t n)
{
    if (n != 0) {
        const unsigned char *p = (const unsigned char *)s;
        do {
            if (*p++ == (unsigned char)c)
                return ((void *)(uintptr_t)(p - 1));
        } while (--n != 0);
    }
    return (NULL);
}
#endif /* SPL_STROPTS_H */

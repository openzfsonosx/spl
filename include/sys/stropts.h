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

extern void kmem_free(void *, size_t );

static inline void
strfree(char *str)
{
    kmem_free(str, strlen(str) + 1);
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
strrchr(p, ch)
     const char *p;
     int ch;
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


#endif /* SPL_STROPTS_H */

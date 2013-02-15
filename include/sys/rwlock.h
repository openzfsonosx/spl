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

#ifndef _SPL_RWLOCK_H
#define _SPL_RWLOCK_H

#include <sys/types.h>
#include <kern/locks.h>
//#include <linux/rwsem.h>
//#include <linux/rwsem_compat.h>


typedef enum {
        RW_DRIVER  = 2,
        RW_DEFAULT = 4
} krw_type_t;

typedef enum {
        RW_NONE   = 0,
        RW_WRITER = 1,
        RW_READER = 2
} krw_t;

struct krwlock {
    uint32_t   rw_lock[4];   /* opaque lck_rw_t data */
    void       *rw_owner;    /* writer (exclusive) lock only */
    int        rw_readers;   /* reader lock only */
};
typedef struct krwlock  krwlock_t;

#define RW_WRITE_HELD(x)        (rw_write_held((x)))
#define RW_LOCK_HELD(x)         (rw_lock_held((x)))

extern  void  rw_init(krwlock_t *, char *, krw_type_t, void *);
extern  void  rw_destroy(krwlock_t *);
extern  void  rw_enter(krwlock_t *, krw_t);
extern  int   rw_tryenter(krwlock_t *, krw_t);
extern  void  rw_exit(krwlock_t *);
extern  void  rw_downgrade(krwlock_t *);
extern  int   rw_tryupgrade(krwlock_t *);
extern  int   rw_write_held(krwlock_t *);
extern  int   rw_lock_held(krwlock_t *);

int  spl_rwlock_init(void);
void spl_rwlock_fini(void);

#endif /* _SPL_RWLOCK_H */

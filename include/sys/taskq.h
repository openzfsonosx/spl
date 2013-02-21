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

#ifndef _SPL_TASKQ_H
#define _SPL_TASKQ_H

//#include <linux/module.h>
//#include <linux/gfp.h>
//#include <linux/slab.h>
//#include <linux/interrupt.h>
//#include <linux/kthread.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/rwlock.h>

#define TASKQ_NAMELEN           31

#define TASKQ_PREPOPULATE       0x00000001
#define TASKQ_CPR_SAFE          0x00000002
#define TASKQ_DYNAMIC           0x00000004
#define TASKQ_THREADS_CPU_PCT   0x00000008
#define TASKQ_DC_BATCH          0x00000010

typedef struct taskq taskq_t;

typedef unsigned long taskqid_t;
typedef void (task_func_t)(void *);

#define TQENT_FLAG_PREALLOC     0x1

/*
 * Flags for taskq_dispatch. TQ_SLEEP/TQ_NOSLEEP should be same as
 * KM_SLEEP/KM_NOSLEEP.  TQ_NOQUEUE/TQ_NOALLOC are set particularly
 * large so as not to conflict with already used GFP_* defines.
 */
#define TQ_SLEEP                0x00000000
#define TQ_NOSLEEP              0x00000001
#define TQ_PUSHPAGE             0x00000002
#define TQ_NOQUEUE              0x01000000
#define TQ_NOALLOC              0x02000000
#define TQ_NEW                  0x04000000
#define TQ_FRONT                0x08000000
#define TQ_ACTIVE               0x80000000

int spl_taskq_init(void);
void spl_taskq_fini(void);

typedef struct taskq_bucket taskq_bucket_t;

typedef struct taskq_ent {
        struct taskq_ent        *tqent_next;
        struct taskq_ent        *tqent_prev;
        task_func_t             *tqent_func;
        void                    *tqent_arg;
        taskq_bucket_t          *tqent_bucket;
        kthread_t               *tqent_thread;
        kcondvar_t              tqent_cv;
        kmutex_t                tqent_thread_lock;
        kcondvar_t              tqent_thread_cv;
} taskq_ent_t;

/*
 * Per-CPU hash bucket manages taskq_bent_t structures using freelist.
 */
struct taskq_bucket {
        kmutex_t        tqbucket_lock;
        taskq_t         *tqbucket_taskq;        /* Enclosing taskq */
        taskq_ent_t     tqbucket_freelist;
        uint_t          tqbucket_nalloc;        /* # of allocated entries */
        uint_t          tqbucket_nfree;         /* # of free entries */
        kcondvar_t      tqbucket_cv;
        ushort_t        tqbucket_flags;
        hrtime_t        tqbucket_totaltime;
};

/*
 * Bucket flags.
 */
#define TQBUCKET_CLOSE          0x01
#define TQBUCKET_SUSPEND        0x02

/*
 * taskq implementation flags: bit range 16-31
 */
#define TASKQ_ACTIVE            0x00010000
#define TASKQ_SUSPENDED         0x00020000
#define TASKQ_NOINSTANCE        0x00040000

struct taskq {
        char            tq_name[TASKQ_NAMELEN + 1];
        kmutex_t        tq_lock;
        krwlock_t       tq_threadlock;
        kcondvar_t      tq_dispatch_cv;
        kcondvar_t      tq_wait_cv;
        uint_t          tq_flags;
        int             tq_active;
        int             tq_nthreads;
        int             tq_nalloc;
        int             tq_minalloc;
        int             tq_maxalloc;
        taskq_ent_t     *tq_freelist;
        taskq_ent_t     tq_task;
        int             tq_maxsize;
        pri_t           tq_pri;         /* Scheduling priority      */
        taskq_bucket_t  *tq_buckets;    /* Per-cpu array of buckets */
#ifndef __APPLE__
        int             tq_instance;
#endif /*!__APPLE__*/
        uint_t          tq_nbuckets;    /* # of buckets (2^n)       */
        union {
                kthread_t *_tq_thread;
                kthread_t **_tq_threadlist;
        }               tq_thr;
        /*
         * Statistics.
         */
        hrtime_t        tq_totaltime;   /* Time spent processing tasks */
        int             tq_tasks;       /* Total # of tasks posted */
        int             tq_executed;    /* Total # of tasks executed */
        int             tq_maxtasks;    /* Max number of tasks in the queue */
        int             tq_tcreates;
        int             tq_tdeaths;
};

#define tq_thread tq_thr._tq_thread
#define tq_threadlist tq_thr._tq_threadlist

extern taskq_t *system_taskq;

extern taskq_t  *taskq_create(const char *, int, pri_t, int, int, uint_t);
extern taskqid_t taskq_dispatch(taskq_t *, task_func_t, void *, uint_t);
extern void     nulltask(void *); // Maybe we don't need this?
extern void     taskq_destroy(taskq_t *);
extern void     taskq_wait(taskq_t *);
extern void     taskq_suspend(taskq_t *);
extern int      taskq_suspended(taskq_t *);
extern void     taskq_resume(taskq_t *);
extern int      taskq_member(taskq_t *, kthread_t *);

#define	taskq_create_proc(a, b, c, d, e, p, f) \
	    (taskq_create(a, b, c, d, e, f))
#define	taskq_create_sysdc(a, b, d, e, p, dc, f) \
	    (taskq_create(a, b, maxclsyspri, d, e, f))
extern void	taskq_dispatch_ent(taskq_t *, task_func_t, void *, uint_t,
    taskq_ent_t *);
extern int	taskq_empty_ent(taskq_ent_t *);
extern void	taskq_init_ent(taskq_ent_t *);


#endif  /* _SPL_TASKQ_H */

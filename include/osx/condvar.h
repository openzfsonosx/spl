#ifndef OSX_CONDVAR_H
#define OSX_CONDVAR_H

#include <sys/time.h>

#define    hz   119  /* frequency when using gethrtime() >> 23 for lbolt */

typedef enum {
        CV_DEFAULT,
        CV_DRIVER
} kcv_type_t;


struct cv {
    uint32_t   cv_waiters;
    uint32_t   pad;
};

typedef struct cv  kcondvar_t;




void spl_cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg);
void spl_cv_destroy(kcondvar_t *cvp);
void spl_cv_signal(kcondvar_t *cvp);
void spl_cv_broadcast(kcondvar_t *cvp);
void spl_cv_wait(kcondvar_t *cvp, kmutex_t *mp, const char *msg);
int  spl_cv_timedwait(kcondvar_t *cvp,kmutex_t *mp, clock_t tim, const char *msg);


/*
 * Use these wrapper macros to obtain the CV variable
 * name to make ZFS more gdb debugging friendly!
 * This name shows up as a thread's wait_event string.
 */
#define cv_wait(cvp, mp)        \
        spl_cv_wait((cvp), (mp), #cvp)

/* Linux provides a cv_wait_io so the schedular will know why we block.
 * find OSX equivalent?
 */
#define cv_wait_io(cvp, mp)                     \
    spl_cv_wait((cvp), (mp), #cvp)

#define cv_timedwait(cvp, mp, tim)      \
        spl_cv_timedwait((cvp), (mp), (tim), #cvp)

#define cv_wait_interruptible(cv, mp)  cv_wait(cv, mp)

#define cv_timedwait_interruptible(cvp, mp, tim)  \
        spl_cv_timedwait((cvp), (mp), (tim), #cvp)

#define cv_init spl_cv_init
#define cv_destroy spl_cv_destroy
#define cv_broadcast spl_cv_broadcast
#define cv_signal spl_cv_signal


#endif

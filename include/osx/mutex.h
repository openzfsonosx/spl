

#ifndef OSX_MUTEX_H
#define OSX_MUTEX_H

#ifdef _KERNEL
#include <libkern/locks.h>

#include <libkern/OSAtomic.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <sys/proc.h>

typedef enum {
    MUTEX_ADAPTIVE = 0,     /* spin if owner is running, otherwise block */
    MUTEX_SPIN = 1,         /* block interrupts and spin */
    MUTEX_DRIVER = 4,       /* driver (DDI) mutex */
    MUTEX_DEFAULT = 6       /* kernel default mutex */
} kmutex_type_t;

// Does anyone know where lck_mtx_t; is actually defined? Not just the opaque
// typedef in i386/locks.h ?
typedef struct {
        unsigned long           opaque[3];
} mutex_t;


typedef struct kmutex {
    void           *m_owner;
    boolean_t       initialized;
    mutex_t         m_lock[1];  // should be lck_mtx_t ?
} kmutex_t;

extern lck_attr_t     *zfs_lock_attr;
extern lck_grp_attr_t *zfs_group_attr;


#define MUTEX_HELD(x)           (mutex_owned(x))
#define MUTEX_NOT_HELD(x)       (!mutex_owned(x))

void mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc);
void mutex_destroy(kmutex_t *mp);
void mutex_enter(kmutex_t *mp);
void mutex_exit(kmutex_t *mp);
int  mutex_tryenter(kmutex_t *mp);
int  mutex_owned(kmutex_t *mp);
struct thread *mutex_owner(kmutex_t *mp);

int  spl_mutex_init(void);
void spl_mutex_fini(void);

#endif


#endif

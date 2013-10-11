

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
        uint32_t  opaque[3];
} mutex_t;

/*
 * Solaris kmutex defined.
 *
 * and is embedded into ZFS structures (see dbuf) so we need to match the
 * size carefully. It appears to be 32 bytes. Or rather, it needs to be
 * aligned.
 */
typedef struct kmutex {
    void           *m_owner;
    lck_mtx_t *m_lock;
    uint8_t m_padding[14];
} kmutex_t;


#define MUTEX_HELD(x)           (mutex_owned(x))
#define MUTEX_NOT_HELD(x)       (!mutex_owned(x))

/*
 * On OS X, CoreStorage provides these symbols, so we have to redefine them,
 * preferably without having to modify SPL users.
 */
#define mutex_init spl_mutex_init
#define	mutex_destroy spl_mutex_destroy
#define mutex_enter spl_mutex_enter
#define	mutex_exit spl_mutex_exit
#define	mutex_tryenter spl_mutex_tryenter
#define	mutex_owned spl_mutex_owned
#define	mutex_owner spl_mutex_owner

void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc);
void spl_mutex_destroy(kmutex_t *mp);
void spl_mutex_enter(kmutex_t *mp);
void spl_mutex_exit(kmutex_t *mp);
int  spl_mutex_tryenter(kmutex_t *mp);
int  spl_mutex_owned(kmutex_t *mp);
struct thread *spl_mutex_owner(kmutex_t *mp);

int  spl_mutex_subsystem_init(void);
void spl_mutex_subsystem_fini(void);

#endif


#endif

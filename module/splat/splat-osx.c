
/*
 * OSX Port by Jorgen Lundman <lundman@lundman.net>
 */


#include <sys/debug.h>
#include <sys/kmem.h>

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/atomic.h>
#include <kern/locks.h>
#include <sys/thread.h>

typedef struct thread_priv {
        unsigned long tp_magic;
        struct file *tp_file;
        spinlock_t tp_lock;
    //wait_queue_head_t tp_waitq;
	//uint_t tp_keys[SPLAT_THREAD_TEST_KEYS];
	int tp_rc;
	int tp_count;
	int tp_dtor_count;
} thread_priv_t;


static void
splat_thread_work1(void *priv)
{
	thread_priv_t *tp = (thread_priv_t *)priv;
    printf("* thread!\n");
	//spin_lock(&tp->tp_lock);
	//ASSERT(tp->tp_magic == SPLAT_THREAD_TEST_MAGIC);
	tp->tp_rc = 1;
	//wake_up(&tp->tp_waitq);
	//spin_unlock(&tp->tp_lock);

	thread_exit();
}

static int
splat_thread_test1(struct file *file, void *arg)
{
	thread_priv_t tp;
	kthread_t *thr;

	tp.tp_magic = 01123;
	tp.tp_file = file;
    //spin_lock_init(&tp.tp_lock);
	//init_waitqueue_head(&tp.tp_waitq);
	tp.tp_rc = 0;

	thr = (kthread_t *)thread_create(NULL, 0, splat_thread_work1, &tp, 0,
			                 &p0, TS_RUN, 0);
	/* Must never fail under Solaris, but we check anyway since this
	 * can happen in the linux SPL, we may want to change this behavior */
	if (thr == NULL)
		return  -ESRCH;

	/* Sleep until the thread sets tp.tp_rc == 1 */
	//wait_event(tp.tp_waitq, splat_thread_rc(&tp, 1));

    printf("Thread successfully started properly\n");
	return 0;
}







kern_return_t splat_start (kmod_info_t * ki, void * d)
{
    printf("SPLAT: Loaded module v0.01\n");
    splat_thread_test1(NULL, NULL);

    return KERN_SUCCESS;
}


kern_return_t splat_stop (kmod_info_t * ki, void * d)
{
    printf("SPLAT: Unloaded module\n");
    return KERN_SUCCESS;
}


extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t splat_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t splat_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.splat, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = splat_start;
__private_extern__ kmod_stop_func_t *_antimain = splat_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;

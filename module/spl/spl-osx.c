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
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */


#include <spl-debug.h>
#include <sys/kmem.h>

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/taskq.h>
//#define MACH_KERNEL_PRIVATE

#include <kern/processor.h>

struct utsname utsname = { { 0 } };

//extern struct machine_info      machine_info;

unsigned int max_ncpus = 0;
static uint64_t  total_memory = 0;


#include <sys/types.h>
#include <sys/sysctl.h>
/* protect against:
 * /System/Library/Frameworks/Kernel.framework/Headers/mach/task.h:197: error: conflicting types for ‘spl_thread_create’
 * ../../include/sys/thread.h:72: error: previous declaration of ‘spl_thread_create’ was here
 */
#define	_task_user_
#include <IOKit/IOLib.h>


/* SMAP */
#include <i386/proc_reg.h>
#include <i386/cpuid.h>
#include <Availability.h>
static int spl_cpufeature_smap = 0;

// Size in bytes of the memory allocated in seg_kmem
extern uint64_t		segkmem_total_mem_allocated;

extern char hostname[MAXHOSTNAMELEN];

/*
 * Solaris delay is in ticks (hz) and Darwin uses microsecs
 * 1 HZ is 10 milliseconds
 */
void
osx_delay(int ticks)
{
	IODelay(ticks * 10000);
}


uint32_t zone_get_hostid(void *zone)
{
    size_t len;
    uint32_t myhostid = 0;

    len = sizeof(myhostid);
    sysctlbyname("kern.hostid", &myhostid, &len, NULL, 0);
    return myhostid;
}

extern void *(*__ihook_malloc)(size_t size);
extern void (*__ihook_free)(void *);

#include <sys/systeminfo.h>


extern const char              *panicstr;
extern int system_inshutdown;

const char *spl_panicstr(void)
{
    return panicstr;
}

int spl_system_inshutdown(void)
{
    return system_inshutdown;
}

int
ddi_copyin(const void *from, void *to, size_t len, int flags)
{
	int ret = 0;

	/* stac/clac defined from 10.10, but only enforced from 10.10.3 */
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) stac();
#endif

    /* Fake ioctl() issued by kernel, 'from' is a kernel address */
    if (flags & FKIOCTL)
		bcopy(from, to, len);
	else
		ret = copyin((user_addr_t)from, (void *)to, len);

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) clac();
#endif
	return ret;
}

int
ddi_copyout(const void *from, void *to, size_t len, int flags)
{
	int ret = 0;

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) stac();
#endif

    /* Fake ioctl() issued by kernel, 'from' is a kernel address */
    if (flags & FKIOCTL)
		bcopy(from, to, len);
	else
		ret = copyout(from, (user_addr_t)to, len);

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) clac();
#endif
	return ret;
}

/* Technically, this call does not exist in IllumOS, but we use it for
 * consistency, and SMAP wrappers.
 */
int ddi_copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	int ret;

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) stac();
#endif
	ret = copyinstr((user_addr_t)uaddr, kaddr, len, done);
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (spl_cpufeature_smap) clac();
#endif
	return ret;
}



kern_return_t spl_start (kmod_info_t * ki, void * d)
{
    //max_ncpus = processor_avail_count;
    int ncpus;
    size_t len = sizeof(ncpus);

	/* We need to check if cpuid SMAP is enabled */
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000 // __MAC_10_10 and up
	if (get_cr4() & CR4_SMAP)
		spl_cpufeature_smap = 1;
#endif


    sysctlbyname("hw.logicalcpu_max", &max_ncpus, &len, NULL, 0);
    len = sizeof(total_memory);
    sysctlbyname("hw.memsize", &total_memory, &len, NULL, 0);

    physmem = total_memory / PAGE_SIZE;

    len = sizeof(utsname.sysname);
    sysctlbyname("kern.ostype", &utsname.sysname, &len, NULL, 0);

    /*
     * For some reason, (CTLFLAG_KERN is not set) looking up hostname
     * returns 1. So we set it to uuid just to give it *something*.
     * As it happens, ZFS sets the nodename on init.
     */
    len = sizeof(utsname.nodename);
    sysctlbyname("kern.uuid", &utsname.nodename, &len, NULL, 0);

    len = sizeof(utsname.release);
    sysctlbyname("kern.osrelease", &utsname.release, &len, NULL, 0);

    len = sizeof(utsname.version);
    sysctlbyname("kern.version", &utsname.version, &len, NULL, 0);

    strlcpy(utsname.nodename, hostname, sizeof(utsname.nodename));

    spl_mutex_subsystem_init();
    spl_kmem_init(total_memory);
    spl_vnode_init();
	spl_kmem_thread_init();
	spl_kmem_mp_init();

    IOLog("SPL: Loaded module v%s-%s%s, "
          "(ncpu %d, memsize %llu, pages %llu) %s\n",
          SPL_META_VERSION, SPL_META_RELEASE, SPL_DEBUG_STR,
		max_ncpus, total_memory, physmem,
		spl_cpufeature_smap ? "SMAP" : "");

	return KERN_SUCCESS;
}


kern_return_t spl_stop (kmod_info_t * ki, void * d)
{
	spl_kmem_thread_fini();
    spl_vnode_fini();
    spl_taskq_fini();
    spl_rwlock_fini();
	spl_tsd_fini();
    spl_kmem_fini();
	spl_kstat_fini();
    spl_mutex_subsystem_fini();
    IOLog("SPL: Unloaded module. (os_mem_alloc: %llu)\n",
		segkmem_total_mem_allocated);
    return KERN_SUCCESS;
}


extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t spl_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t spl_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.spl, "1.0.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = spl_start;
__private_extern__ kmod_stop_func_t *_antimain = spl_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;

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

struct utsname utsname = { 0 };

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

/*
 * Solaris delay is in ticks (hz) and Darwin uses microsecs
 * 1 HZ is 10 milliseconds
 */
void
osx_delay(int ticks)
{
	IODelay(ticks * 10000);
}

/*
 * fnv_32a_str - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a string
 *
 * input:
 *	str	- string to hash
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
 *  	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
 */
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)
uint32_t
fnv_32a_str(char *str, uint32_t hval)
{
    unsigned char *s = (unsigned char *)str;	/* unsigned string */

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*s) {

	/* xor the bottom with the current octet */
	hval ^= (uint32_t)*s++;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}

uint32_t zone_get_hostid(void *zone)
{
    size_t len;
    uint32_t myhostid = 0;

    len = sizeof(myhostid);
    sysctlbyname("kern.hostid", &myhostid, &len, NULL, 0);
    return myhostid;
}


kern_return_t spl_start (kmod_info_t * ki, void * d)
{
    //max_ncpus = processor_avail_count;
    int ncpus;
    size_t len = sizeof(ncpus);
    uint32_t myhostid = 0;
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


    /*
     * hostid is left as 0 on OSX, and left to be set if developers wish to
     * use it. If it is 0, we will hash the kern.uuid into a 32bit value and
     * set the hostid.
     */
    len = sizeof(myhostid);
    sysctlbyname("kern.hostid", &myhostid, &len, NULL, 0);
    if (myhostid == 0) {
        myhostid = fnv_32a_str(utsname.nodename, FNV1_32A_INIT);
        sysctlbyname("kern.hostid", NULL, NULL, &myhostid, sizeof(myhostid));
        printf("SPL: hostid set to %08x from UUID '%s'\n",
               myhostid, utsname.nodename);
    }

    spl_kmem_init();
    spl_mutex_subsystem_init();
    spl_rwlock_init();
    spl_taskq_init();

    IOLog("SPL: Loaded module v0.01 (ncpu %d, memsize %llu, pages %llu)\n",
          max_ncpus, total_memory, physmem);
    return KERN_SUCCESS;
}


kern_return_t spl_stop (kmod_info_t * ki, void * d)
{
    spl_taskq_fini();
    spl_rwlock_fini();
    spl_mutex_subsystem_fini();
    spl_kmem_fini();
    IOLog("SPL: Unloaded module\n");
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

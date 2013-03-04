/*-
 * Copyright 2007 John Birrell <jb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

/*
 * OSX Port by Jorgen Lundman <lundman@lundman.net>
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

struct utsname utsname = {
        "OS-X", "", "1.0", "1.0", "i386"
};

//extern struct machine_info      machine_info;

unsigned int max_ncpus;
uint64_t  total_memory;


#include <sys/types.h>
#include <sys/sysctl.h>
/* protect against:
 * /System/Library/Frameworks/Kernel.framework/Headers/mach/task.h:197: error: conflicting types for ‘spl_thread_create’
 * ../../include/sys/thread.h:72: error: previous declaration of ‘spl_thread_create’ was here
 */
#define	_task_user_
#include <IOKit/IOLib.h>


void
osx_delay(int ticks)
{
	IODelay(ticks);
}

kern_return_t spl_start (kmod_info_t * ki, void * d)
{
    //max_ncpus = processor_avail_count;
    int ncpus;
    size_t len = sizeof(ncpus);
    sysctlbyname("hw.logicalcpu_max", &max_ncpus, &len, NULL, 0);
    len = sizeof(total_memory);
    sysctlbyname("hw.memsize", &total_memory, &len, NULL, 0);

    physmem = total_memory; // FIXME obviously

    spl_kmem_init();
    spl_mutex_init();
    spl_rwlock_init();
    spl_taskq_init();

    IOLog("SPL: Loaded module v0.01 (ncpu %d, memsize %llu)\n",
          max_ncpus, total_memory);
    return KERN_SUCCESS;
}


kern_return_t spl_stop (kmod_info_t * ki, void * d)
{
    spl_taskq_fini();
    spl_rwlock_fini();
    spl_mutex_fini();
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

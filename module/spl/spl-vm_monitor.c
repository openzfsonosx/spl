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
 * Copyright (c) 2019, Brendon Humphrey (brendon.humphrey@mac.com)
 */

#include "vm/vm_monitor.h"
#include "sys/kmem.h"

// Kernel calls for register/dregister into the fs buffer cache pressure callback mechanism
// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/vfs/vfs_bio.c#L4542
extern int fs_buffer_cache_gc_register(void (* callout)(int, void *), void *context);
extern int fs_buffer_cache_gc_unregister(void (* callout)(int, void *), void *context);

typedef struct {
	void (* callout)(int, void *);
	void *context;
} monitor_pressure_callout_t;

static kmutex_t	pressure_callout_lock;
static monitor_pressure_callout_t pressure_callouts[VM_MONITOR_CALLOUTS_MAX_SIZE] = { {NULL, NULL} };


int
vm_monitor_pressure_register(void (* callout)(int, void *), void *context)
{
	mutex_enter(&pressure_callout_lock);
	for (int i = 0; i < VM_MONITOR_CALLOUTS_MAX_SIZE; i++) {
		if (pressure_callouts[i].callout == NULL) {
			pressure_callouts[i].callout = callout;
			pressure_callouts[i].context = context;
			mutex_exit(&pressure_callout_lock);
			return 0;
		}
	}

	mutex_exit(&pressure_callout_lock);
	return ENOMEM;
}

int
vm_monitor_pressure_unregister(void (* callout)(int, void *), void *context)
{
	mutex_enter(&pressure_callout_lock);
	for (int i = 0; i < VM_MONITOR_CALLOUTS_MAX_SIZE; i++) {
		if (pressure_callouts[i].callout == callout &&
		    pressure_callouts[i].context == context) {
			pressure_callouts[i].callout = NULL;
			pressure_callouts[i].context = NULL;
		}
	}
	mutex_exit(&pressure_callout_lock);
	return 0;
}

static void
vm_monitor_dispatch_callouts(int all)
{
	mutex_enter(&pressure_callout_lock);
	for(int i = 0; i < VM_MONITOR_CALLOUTS_MAX_SIZE; i++) {
		if (pressure_callouts[i].callout != NULL) {
			pressure_callouts[i].callout(all, pressure_callouts[i].context);
		}
	}
	mutex_exit(&pressure_callout_lock);
}

static void 
vm_monitor_pressure_cb(int all, void *context)
{
	// Take a look at the state of the vm
	extern void kmem_manage_memory(void);
	kmem_manage_memory();
	
	// Notify application layer of need to memory to be released
	vm_monitor_dispatch_callouts(all);

	// Reap all memory caches
	kmem_reap();
}

void
vm_monitor_init()
{
	mutex_init(&pressure_callout_lock, "pressure_callout_lock", MUTEX_DEFAULT, NULL);
	int r = fs_buffer_cache_gc_register(vm_monitor_pressure_cb, NULL);

	if(r == ENOMEM) 
		printf("SPL: unable to register fs_buffer_cache_gc callback\n");
	else
		printf("SPL: Pressure monitor registered with OS\n");
}

void
vm_monitor_fini()
{
	fs_buffer_cache_gc_unregister(vm_monitor_pressure_cb, NULL);
	mutex_destroy(&pressure_callout_lock);
}



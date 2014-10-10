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
 * Copyright (C) 2008 MacZFS
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/mutex.h>


#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <sys/mutex.h>
#include <string.h>
#include <sys/debug.h>
#include <kern/debug.h>
#include <sys/thread.h>

// Not defined in headers
extern boolean_t lck_mtx_try_lock(lck_mtx_t *lck);


static lck_attr_t       *zfs_lock_attr = NULL;
static lck_grp_attr_t   *zfs_group_attr = NULL;

static lck_grp_t *zfs_mutex_group = NULL;

uint64_t zfs_active_mutex = 0;

#define MUTEX_LEAK
#ifdef MUTEX_LEAK
#include <sys/list.h>
static list_t mutex_list;
static kmutex_t mutex_list_mutex;


struct leak {
    list_node_t     mutex_leak_node;

#define MUTEX_LEAK_MAXCHAR 32
	char location_file[MUTEX_LEAK_MAXCHAR];
	char location_function[MUTEX_LEAK_MAXCHAR];
	uint64_t location_line;
	void *mp;
};

#endif


int spl_mutex_subsystem_init(void)
{
    zfs_lock_attr = lck_attr_alloc_init();
    zfs_group_attr = lck_grp_attr_alloc_init();
    zfs_mutex_group  = lck_grp_alloc_init("zfs-mutex", zfs_group_attr);


#ifdef MUTEX_LEAK
	list_create(&mutex_list, sizeof (struct leak),
				offsetof(struct leak, mutex_leak_node));
	mutex_list_mutex.m_lock = lck_mtx_alloc_init(zfs_mutex_group, zfs_lock_attr);
#endif

    return 0;
}



void spl_mutex_subsystem_fini(void)
{
#ifdef MUTEX_LEAK
	uint64_t total = 0;
	printf("Dumping leaked mutex allocations...\n");

	mutex_enter(&mutex_list_mutex);
	while(1) {
		struct leak *leak, *runner;
		uint32_t found;

		leak = list_head(&mutex_list);

		if (leak) {
			list_remove(&mutex_list, leak);
		}
		if (!leak) break;

		// Run through list and count up how many times this leak is
		// found, removing entries as we go.
		for (found = 1, runner = list_head(&mutex_list);
			 runner;
			 runner = runner ? list_next(&mutex_list, runner) :
				 list_head(&mutex_list)) {

			if (!strcmp(leak->location_file, runner->location_file) &&
				!strcmp(leak->location_function, runner->location_function) &&
				leak->location_line == runner->location_line) {
				// Same place
				found++;
				list_remove(&mutex_list, runner);
				FREE(runner, M_TEMP);
				runner = NULL;
			} // if same

		} // for all nodes

		printf("  mutex %p : %s %s %llu : # leaks: %u\n",
			   leak->mp,
			   leak->location_file,
			   leak->location_function,
			   leak->location_line,
			   found);

		FREE(leak, M_TEMP);
		total+=found;

	}
	mutex_exit(&mutex_list_mutex);
	printf("Dumped %llu leaked allocations\n", total);

	lck_mtx_free(mutex_list_mutex.m_lock, zfs_mutex_group);
	list_destroy(&mutex_list);
#endif

    lck_attr_free(zfs_lock_attr);
    zfs_lock_attr = NULL;

    lck_grp_attr_free(zfs_group_attr);
    zfs_group_attr = NULL;

    lck_grp_free(zfs_mutex_group);
    zfs_mutex_group = NULL;
}


#ifdef MUTEX_LEAK
void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc,
					const char *file, const char *fn, int line)
#else
void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
#endif
{
    ASSERT(type != MUTEX_SPIN);
    ASSERT(ibc == NULL);
    mp->m_lock = lck_mtx_alloc_init(zfs_mutex_group, zfs_lock_attr);
    mp->m_owner = NULL;

	atomic_inc_64(&zfs_active_mutex);

#ifdef MUTEX_LEAK
	if (!mp->m_lock) panic("[SPL] Unable to allocate MUTEX\n");

	struct leak *leak;

	MALLOC(leak, struct leak *,
		   sizeof(struct leak),  M_TEMP, M_WAITOK);

	if (leak) {
		bzero(leak, sizeof(struct leak));
		strlcpy(leak->location_file, file, MUTEX_LEAK_MAXCHAR);
		strlcpy(leak->location_function, fn, MUTEX_LEAK_MAXCHAR);
		leak->location_line = line;
		leak->mp = mp;

		mutex_enter(&mutex_list_mutex);
		list_link_init(&leak->mutex_leak_node);
		list_insert_tail(&mutex_list, leak);
		mp->leak = leak;
		mutex_exit(&mutex_list_mutex);
	}
#endif
}

void spl_mutex_destroy(kmutex_t *mp)
{
    if (!mp) return;
    lck_mtx_free(mp->m_lock, zfs_mutex_group);

	atomic_dec_64(&zfs_active_mutex);

#ifdef MUTEX_LEAK
	if (mp->leak) {
		struct leak *leak = (struct leak *)mp->leak;
		mutex_enter(&mutex_list_mutex);
		list_remove(&mutex_list, leak);
		mp->leak = NULL;
		mutex_exit(&mutex_list_mutex);
		FREE(leak, M_TEMP);
	}
#endif
}

void mutex_enter(kmutex_t *mp)
{
    if (mp->m_owner == current_thread())
        panic("mutex_enter: locking against myself!");

    lck_mtx_lock(mp->m_lock);
    mp->m_owner = current_thread();
}

void spl_mutex_exit(kmutex_t *mp)
{
    mp->m_owner = NULL;
    lck_mtx_unlock(mp->m_lock);
}


int spl_mutex_tryenter(kmutex_t *mp)
{
    int held;

    if (mp->m_owner == current_thread())
        panic("mutex_tryenter: locking against myself!");

    held = lck_mtx_try_lock(mp->m_lock);
    if (held)
        mp->m_owner = current_thread();
    return (held);
}

int spl_mutex_owned(kmutex_t *mp)
{
    return (mp->m_owner == current_thread());
}

struct thread *spl_mutex_owner(kmutex_t *mp)
{
    return (mp->m_owner);
}

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

uint64_t spl_mutex_total = 0;

#ifdef MUTEX_LEAK
#include <sys/list.h>
static list_t mutex_list;
static kmutex_t mutex_list_mutex;
#endif


int spl_mutex_subsystem_init(void)
{
    zfs_lock_attr = lck_attr_alloc_init();
    zfs_group_attr = lck_grp_attr_alloc_init();
    zfs_mutex_group  = lck_grp_alloc_init("zfs-mutex", zfs_group_attr);


#ifdef MUTEX_LEAK
	list_create(&mutex_list, sizeof (kmutex_t),
				offsetof(kmutex_t, mutex_leak_node));
	mutex_init(&mutex_list_mutex, NULL, MUTEX_DEFAULT, NULL);
#endif

    return 0;
}



void spl_mutex_subsystem_fini(void)
{
#ifdef MUTEX_LEAK
	printf("Dumping leaked mutex allocations...\n");

	while(1) {
		kmutex_t *mp;

		mutex_enter(&mutex_list_mutex);
		mp = list_head(&mutex_list);
		if (mp) {
			list_remove(&mutex_list, mp);
		}
		mutex_exit(&mutex_list_mutex);
		if (!mp) break;

		printf("  mutex %p : %s %s %d\n",
			   mp,
			   mp->location_file,
			   mp->location_function,
			   mp->location_line);
	}

	mutex_destroy(&mutex_list_mutex);
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

	if (!mp->m_lock) panic("[SPL] Unable to allocate MUTEX\n");

#ifdef MUTEX_LEAK
	if (mp != &mutex_list_mutex) {
		strlcpy(mp->location_file, file, MUTEX_LEAK_MAXCHAR);
		strlcpy(mp->location_function, fn, MUTEX_LEAK_MAXCHAR);
		mp->location_line = line;

		mutex_enter(&mutex_list_mutex);
		list_link_init(&mp->mutex_leak_node);
		list_insert_tail(&mutex_list, mp);
		mutex_exit(&mutex_list_mutex);
	}
#endif

	atomic_inc_64(&spl_mutex_total);
}

void spl_mutex_destroy(kmutex_t *mp)
{
    if (!mp) return;
    lck_mtx_free(mp->m_lock, zfs_mutex_group);
	atomic_dec_64(&spl_mutex_total);
#ifdef MUTEX_LEAK
	if (mp != &mutex_list_mutex) {
		mutex_enter(&mutex_list_mutex);
		list_remove(&mutex_list, mp);
		mutex_exit(&mutex_list_mutex);
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

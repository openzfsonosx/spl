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
 * Copyright (C) 2014 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/tsd.h>
#include <sys/list.h>
#include <spl-debug.h>


struct spl_tsd_node_s
{
	pid_t       tsd_pid;
	uint_t      tsd_key;
	void       *tsd_value;
	dtor_func_t tsd_dtor;
	list_node_t tsd_link_node;
};
typedef struct spl_tsd_node_s spl_tsd_node_t;

static kmutex_t spl_tsd_mutex;
static list_t   spl_tsd_list;
static uint64_t spl_tsd_incr = 0;


/*
 * tsd_set - set thread specific data
 * @key: lookup key
 * @value: value to set
 *
 * Caller must prevent racing tsd_create() or tsd_destroy(), protected
 * from racing tsd_get() or tsd_set() because it is thread specific.
 * This function has been optimized to be fast for the update case.
 * When setting the tsd initially it will be slower due to additional
 * required locking and potential memory allocations.
 */
int
tsd_set(uint_t key, void *value)
{
	spl_tsd_node_t *entry = NULL;
	pid_t pid;

	pid = proc_pid(current_proc());

	//printf("tsd_set(pid %u, key %08x, value %p)\n", pid, key, value);

	mutex_enter(&spl_tsd_mutex);
	for (entry = list_head(&spl_tsd_list);
		 entry != NULL;
		 entry = list_next(&spl_tsd_list, entry)) {

		if ((pid == entry->tsd_pid) &&
			(key == entry->tsd_key)) break;
	} // for
	mutex_exit(&spl_tsd_mutex);

	if (entry) { // Update entry
		entry->tsd_value = value;
		return 0;
	}

	// Create new entry.
	entry = kmem_zalloc(sizeof (spl_tsd_node_t), KM_SLEEP | KM_NODEBUG);
	list_link_init(&entry->tsd_link_node);

	entry->tsd_pid   = pid;
	entry->tsd_key   = key;
	entry->tsd_value = value;

	mutex_enter(&spl_tsd_mutex);
	list_insert_head(&spl_tsd_list, entry);
	mutex_exit(&spl_tsd_mutex);
	return 0;
}

/*
 * tsd_get - get thread specific data
 * @key: lookup key
 *
 * Caller must prevent racing tsd_create() or tsd_destroy().  This
 * implementation is designed to be fast and scalable, it does not
 * lock the entire table only a single hash bin.
 */
void *
tsd_get(uint_t key)
{
	spl_tsd_node_t *entry = NULL;
	pid_t pid;

	pid = proc_pid(current_proc());

	mutex_enter(&spl_tsd_mutex);
	for (entry = list_head(&spl_tsd_list);
		 entry != NULL;
		 entry = list_next(&spl_tsd_list, entry)) {

		if ((pid == entry->tsd_pid) &&
			(key == entry->tsd_key)) break;
	} // for
	mutex_exit(&spl_tsd_mutex);

	//printf("tsd_get(pid %u, key %08x, value %p)\n", pid, key,
	//	   entry ? entry->tsd_value : NULL);

	return entry ? entry->tsd_value : NULL;
}

/*
 * Create TSD for a pid and fill in key with unique value, remember the dtor
 *
 * We cheat and create an entry with pid=0, to keep the dtor.
 */


void
tsd_create(uint_t *keyp, dtor_func_t dtor)
{
	spl_tsd_node_t *entry;

	if (*keyp) return; // Should be 0

	// Create new entry.
	entry = kmem_zalloc(sizeof (spl_tsd_node_t), KM_SLEEP | KM_NODEBUG);
	list_link_init(&entry->tsd_link_node);

	entry->tsd_pid   = 0;
	entry->tsd_dtor  = dtor;

	mutex_enter(&spl_tsd_mutex);
	*keyp = ++spl_tsd_incr;
	entry->tsd_key   = *keyp;
	list_insert_head(&spl_tsd_list, entry);
	mutex_exit(&spl_tsd_mutex);

	//printf("tsd_create: %08x\n", *keyp);
}

void
tsd_destroy(uint_t *keyp)
{
	spl_tsd_node_t *entry = NULL;

	/*
	 * Find all nodes that match keyp, and all pids.
	 * Remove them all.
	 */

	mutex_enter(&spl_tsd_mutex);

 restart:
	for (entry = list_head(&spl_tsd_list);
		 entry != NULL;
		 entry = list_next(&spl_tsd_list, entry)) {

		if ((*keyp == entry->tsd_key)) {

			list_remove(&spl_tsd_list, entry);

			kmem_free(entry, sizeof(spl_tsd_node_t));
			entry = NULL;

			goto restart;

		} // match node

	} // for
	mutex_exit(&spl_tsd_mutex);

	if (!entry) return;

	//printf("tsd_destroy: %08x\n", *keyp);

	mutex_enter(&spl_tsd_mutex);
	list_remove(&spl_tsd_list, entry);
	mutex_exit(&spl_tsd_mutex);

	if (entry->tsd_dtor && entry->tsd_value)
		entry->tsd_dtor(entry->tsd_value);

	kmem_free(entry, sizeof(spl_tsd_node_t));
	entry = NULL;

	// Technically, run through and remove all nodes with "key"

}


int
spl_tsd_init(void)
{
	mutex_init(&spl_tsd_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&spl_tsd_list, sizeof(spl_tsd_node_t),
				offsetof(spl_tsd_node_t, tsd_link_node));
	return 0;
}

void
spl_tsd_fini(void)
{
	spl_tsd_node_t *entry = NULL;

	mutex_enter(&spl_tsd_mutex);
	while ((entry = list_head(&spl_tsd_list))) {
		list_remove(&spl_tsd_list, entry);
		kmem_free(entry, sizeof(spl_tsd_node_t));
	} // while
	mutex_exit(&spl_tsd_mutex);

	list_destroy(&spl_tsd_list);
	mutex_destroy(&spl_tsd_mutex);
}

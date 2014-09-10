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
 * Copyright (C) 2014 Brendon Humphrey <brendon.humphrey@mac.com>
 *
 */

/*
 * Provides an implementation of kstat that is backed by OSX sysctls.
 */

#include <sys/kstat.h>
#include <spl-debug.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <spl-bmalloc.h>

/*
 * Statically declared toplevel OID that all kstats
 * will hang off.
 */
struct sysctl_oid_list sysctl__kstat_children;
SYSCTL_DECL(_kstat);
SYSCTL_NODE( , OID_AUTO, kstat, CTLFLAG_RW, 0, "kstat tree");

/*
 * Sysctl node tree structure.
 *
 * These are wired into the OSX sysctl structure
 * and also stored a list/tree/whatever for easy
 * location and destruction at shutdown time.
 */
typedef struct sysctl_tree_node {
	char					tn_kstat_name[KSTAT_STRLEN+1];
	struct sysctl_oid_list 	tn_children;
	struct sysctl_oid		tn_oid;
	struct sysctl_tree_node	*tn_next;
} sysctl_tree_node_t;

/*
 * Extended kstat structure -- for internal use only.
 */
typedef struct ekstat {
	kstat_t         		e_ks;		/* the kstat itself */
	size_t          		e_size;		/* total allocation size */
	kthread_t       		*e_owner;	/* thread holding this kstat */
	kcondvar_t				e_cv;		/* wait for owner == NULL */
	struct sysctl_oid_list	e_children;
	struct sysctl_oid		e_oid;
} ekstat_t;

struct sysctl_tree_node		*tree_nodes = 0;
struct sysctl_oid 			*e_sysctl = 0;

static void kstat_set_string(char *dst, const char *src)
{
    bzero(dst, KSTAT_STRLEN);
    (void) strlcpy(dst, src, KSTAT_STRLEN + 1);
}

static struct sysctl_oid*
get_oid_with_name(struct sysctl_oid_list* list, char *name)
{
	struct sysctl_oid *oidp;
	
	SLIST_FOREACH(oidp, list, oid_link) {
		if (strcmp(name, oidp->oid_name) == 0) {
			return oidp;
		}
	}
	
	return 0;
}

static void
init_oid_tree_node(struct sysctl_oid_list* parent, char *name, sysctl_tree_node_t* node)
{
	strlcpy(node->tn_kstat_name, name, KSTAT_STRLEN + 1);
	
	node->tn_oid.oid_parent = parent;
	node->tn_oid.oid_link.sle_next = 0;
	node->tn_oid.oid_number = OID_AUTO;
	node->tn_oid.oid_arg2 = 0;
	node->tn_oid.oid_name = &node->tn_kstat_name[0];
	node->tn_oid.oid_descr = "";
	node->tn_oid.oid_version = SYSCTL_OID_VERSION;
	node->tn_oid.oid_refcnt = 0;
	node->tn_oid.oid_handler = 0;
	node->tn_oid.oid_kind = CTLTYPE_NODE|CTLFLAG_RW|CTLFLAG_OID2;
	node->tn_oid.oid_fmt = "N";
	node->tn_oid.oid_arg1 = (void*)(&node->tn_children);
	
	sysctl_register_oid(&node->tn_oid);
			
	node->tn_next = tree_nodes;
	tree_nodes = node;
}

static struct sysctl_oid_list*
get_kstat_parent(struct sysctl_oid_list* root, char *module_name, char* class_name)
{
	struct sysctl_oid *the_module = 0;
	struct sysctl_oid *the_class = 0;
	sysctl_tree_node_t *new_node = 0;
	struct sysctl_oid_list *container = root;
	
	/*
	 * Locate/create the module
	 */
	the_module = get_oid_with_name(root, module_name);
	
	if (!the_module) {
		new_node = bzmalloc(sizeof(sysctl_tree_node_t), KM_SLEEP);
		init_oid_tree_node(root, module_name, new_node);
		the_module = &new_node->tn_oid;
	}
	
	/*
	 * Locate/create the class
	 */
	container = the_module->oid_arg1;
	the_class = get_oid_with_name(container, class_name);
	
	if (!the_class) {
		new_node = bzmalloc(sizeof(sysctl_tree_node_t), KM_SLEEP);
		init_oid_tree_node(container, class_name, new_node);
		the_class = &new_node->tn_oid;
	}
	
	container = the_class->oid_arg1;
	return container;
}

static int kstat_handle_i64 SYSCTL_HANDLER_ARGS
{
    int error = 0;
    
    kstat_named_t *named = (kstat_named_t*)(arg1);
    kstat_t *ksp  = named->s_parent;
	kmutex_t *lock = ksp->ks_lock;
	int lock_needs_release = 0;
    
	if (lock && !MUTEX_NOT_HELD(lock)) {
		mutex_enter(lock);
		lock_needs_release = 1;
	}
	
    if(!error && req->newptr) {
        /*
         * Write request - first read add current values for the kstat
         * (remember that is sysctl is likely only one of many
         *  values that make up the kstat).
         */
        if (ksp->ks_update) {
            ksp->ks_update(ksp, KSTAT_READ);
        }
        
        /* Copy the new value from user space */
        named->value.i64 = (*(int64_t*)(req->newptr));
        
        /* and invoke the update operation */
        if (ksp->ks_update) {
            error = ksp->ks_update(ksp, KSTAT_WRITE);
        }
    } else {
        /*
         * Read request
         */
        if (ksp->ks_update) {
            ksp->ks_update(ksp, KSTAT_READ);
        }
        error = SYSCTL_OUT(req, &named->value.i64, sizeof(int64_t));
    }
    
	if (lock_needs_release) {
		mutex_exit(lock);
	}
	
    return error;
}

static int kstat_handle_ui64 SYSCTL_HANDLER_ARGS
{
    int error = 0;
    
    kstat_named_t *named = (kstat_named_t*)(arg1);
    kstat_t *ksp  = named->s_parent;
	kmutex_t *lock = ksp->ks_lock;
	int lock_needs_release = 0;
	
	if (lock && !MUTEX_NOT_HELD(lock)) {
		mutex_enter(lock);
		lock_needs_release = 1;
	}
    if(!error && req->newptr) {
        /*
         * Write request - first read add current values for the kstat
         * (remember that is sysctl is likely only one of many
         *  values that make up the kstat).
         */
        if (ksp->ks_update) {
            ksp->ks_update(ksp, KSTAT_READ);
        }
        
        /* Copy the new value from user space */
        named->value.ui64 = (*(uint64_t*)(req->newptr));
        
        /* and invoke the update operation */
        if (ksp->ks_update) {
            error = ksp->ks_update(ksp, KSTAT_WRITE);
        }
    } else {
        /*
         * Read request
         */
        if (ksp->ks_update) {
            ksp->ks_update(ksp, KSTAT_READ);
        }
        error = SYSCTL_OUT(req, &named->value.ui64, sizeof(uint64_t));
    }
	
	if (lock_needs_release) {
		mutex_exit(lock);
	}
    
    return error;
}

kstat_t *
kstat_create(char *ks_module, int ks_instance, char *ks_name, char *ks_class,
             uchar_t ks_type,
             ulong_t ks_ndata, uchar_t ks_flags)
{
    kstat_t *ksp = 0;
    ekstat_t *e = 0;
    size_t size = 0;
	
    /*
     * Allocate memory for the new kstat header.
     */
    size = sizeof (ekstat_t);
    e = (ekstat_t *)bzmalloc(size, KM_SLEEP);
    if (e == NULL) {
        cmn_err(CE_NOTE, "kstat_create('%s', %d, '%s'): "
                "insufficient kernel memory",
                ks_module, ks_instance, ks_name);
        return (NULL);
    }
    bzero(e, size);
    e->e_size = size;
    
    cv_init(&e->e_cv, NULL, CV_DEFAULT, NULL);
    
    /*
     * Initialize as many fields as we can.  The caller may reset
     * ks_lock, ks_update, ks_private, and ks_snapshot as necessary.
     * Creators of virtual kstats may also reset ks_data.  It is
     * also up to the caller to initialize the kstat data section,
     * if necessary.  All initialization must be complete before
     * calling kstat_install().
     */
    ksp = &e->e_ks;
	
    ksp->ks_crtime          = gethrtime();
    kstat_set_string(ksp->ks_module, ks_module);
    ksp->ks_instance        = ks_instance;
    kstat_set_string(ksp->ks_name, ks_name);
    ksp->ks_type            = ks_type;
    kstat_set_string(ksp->ks_class, ks_class);
    ksp->ks_flags           = ks_flags | KSTAT_FLAG_INVALID;
    ksp->ks_ndata           = ks_ndata;
    ksp->ks_snaptime        = ksp->ks_crtime;
	ksp->ks_lock            = 0;
	
	/*
	 * Initialise the sysctl that represents this kstat
	 */
	e->e_children.slh_first = 0;
	
	e->e_oid.oid_parent = get_kstat_parent(&sysctl__kstat_children,
											  ksp->ks_module, ksp->ks_class);
	e->e_oid.oid_link.sle_next = 0;
	e->e_oid.oid_number = OID_AUTO;
	e->e_oid.oid_arg2 = 0;
	e->e_oid.oid_name = ksp->ks_name;
	e->e_oid.oid_descr = "";
	e->e_oid.oid_version = SYSCTL_OID_VERSION;
	e->e_oid.oid_refcnt = 0;
	e->e_oid.oid_handler = 0;
	e->e_oid.oid_kind = CTLTYPE_NODE|CTLFLAG_RW|CTLFLAG_OID2;
	e->e_oid.oid_fmt = "N";
	e->e_oid.oid_arg1 = (void*)(&e->e_children);
	
	sysctl_register_oid(&e->e_oid);
	
    return (ksp);
}

void
kstat_install(kstat_t *ksp)
{
	ekstat_t *e = (ekstat_t*)ksp;
	kstat_named_t *named_base = 0;
	int oid_permissions = CTLFLAG_RD;
	
    if (ksp->ks_type == KSTAT_TYPE_NAMED) {
        
		if (ksp->ks_flags & KSTAT_FLAG_WRITABLE) {
			oid_permissions |= CTLFLAG_RW;
		}
		
        named_base = (kstat_named_t*)(ksp->ks_data);
        
        for (int i=0; i < ksp->ks_ndata; i++) {
            
            int oid_valid = 1;
            
            kstat_named_t *named = &named_base[i];
            
            // Need to be able to navigate back to the
            // owning kstats for update callback
            named->s_parent = ksp;
            
            // Perform basic initialisation of the sysctl.
            //
            // The sysctl will be kstat.<module>.<class>.<name>.<data name>
            snprintf(named->s_name, KSTAT_STRLEN, "%s", named->name);
            
            named->s_oid.oid_parent = &e->e_children;
            named->s_oid.oid_link.sle_next = 0;
            named->s_oid.oid_number = OID_AUTO;
            named->s_oid.oid_arg2 = 0;
            named->s_oid.oid_name = named->s_name;
            named->s_oid.oid_descr = "";
            named->s_oid.oid_version = SYSCTL_OID_VERSION;
            named->s_oid.oid_refcnt = 0;
            
            // Based on the kstat type flags, provide location
            // of data item and associated type and handler
            // flags to the sysctl.
            switch (named->data_type) {
                case KSTAT_DATA_INT64:
                    named->s_oid.oid_handler = kstat_handle_i64;
                    named->s_oid.oid_kind = CTLTYPE_QUAD|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "Q";
                    named->s_oid.oid_arg1 = named;
                    break;
                case KSTAT_DATA_UINT64:
                    named->s_oid.oid_handler = kstat_handle_ui64;
                    named->s_oid.oid_kind = CTLTYPE_QUAD|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "Q";
                    named->s_oid.oid_arg1 = named;
                    break;
                case KSTAT_DATA_INT32:
                    named->s_oid.oid_handler = sysctl_handle_int;
                    named->s_oid.oid_kind = CTLTYPE_INT|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "I";
                    named->s_oid.oid_arg1 = &named->value.i32;
                    break;
                case KSTAT_DATA_UINT32:
                    named->s_oid.oid_handler = sysctl_handle_int;
                    named->s_oid.oid_kind = CTLTYPE_INT|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "IU";
                    named->s_oid.oid_arg1 = &named->value.ui32;
                    break;
                case KSTAT_DATA_LONG:
                    named->s_oid.oid_handler = sysctl_handle_long;
                    named->s_oid.oid_kind = CTLTYPE_INT|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "L";
                    named->s_oid.oid_arg1 = &named->value.l;
                    break;
                case KSTAT_DATA_ULONG:
                    named->s_oid.oid_handler = sysctl_handle_long;
                    named->s_oid.oid_kind = CTLTYPE_INT|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "L";
                    named->s_oid.oid_arg1 = &named->value.ul;
                    break;
                case KSTAT_DATA_STRING:
                    named->s_oid.oid_handler = sysctl_handle_string;
                    named->s_oid.oid_kind = CTLTYPE_STRING|oid_permissions|CTLFLAG_OID2;
                    named->s_oid.oid_fmt = "S";
                    named->s_oid.oid_arg1 = &named->value.string;
                    break;
                    
                case KSTAT_DATA_CHAR:
                default:
                    oid_valid = 0;
                    break;
            }
            
            // Finally publish the OID, provided that there were no issues initialising it.
            if (oid_valid) {
                sysctl_register_oid(&named->s_oid);
                named->s_oid_registered = 1;
            } else {
                named->s_oid_registered = 0;
            }
        }
    }
    
    ksp->ks_flags &= ~KSTAT_FLAG_INVALID;
}

static void
remove_child_sysctls(ekstat_t *e)
{
	kstat_t *ksp = &e->e_ks;
	kstat_named_t *named_base = (kstat_named_t*)(ksp->ks_data);
	
	for (int i=0; i < ksp->ks_ndata; i++) {
		if (named_base[i].s_oid_registered) {
			sysctl_unregister_oid(&named_base[i].s_oid);
			named_base[i].s_oid_registered = 0;
		}
	}
}

void
kstat_delete(kstat_t *ksp)
{
    ekstat_t *e = (ekstat_t *)ksp;
	kmutex_t *lock = ksp->ks_lock;
	
    // destroy the sysctl
    if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		
		if (lock && MUTEX_NOT_HELD(lock)) {
			mutex_enter(lock);
	        remove_child_sysctls(e);
			mutex_exit(lock);
		} else {
			remove_child_sysctls(e);
		}
    }
    
    cv_destroy(&e->e_cv);
	sysctl_unregister_oid(&e->e_oid);
    bfree(e, e->e_size);
}


void
kstat_waitq_enter(kstat_io_t *kiop)
{
}

void
kstat_waitq_exit(kstat_io_t *kiop)
{
}

void
kstat_runq_enter(kstat_io_t *kiop)
{
}

void
kstat_runq_exit(kstat_io_t *kiop)
{
}

void
__kstat_set_raw_ops(kstat_t *ksp,
                    int (*headers)(char *buf, size_t size),
                    int (*data)(char *buf, size_t size, void *data),
                    void *(*addr)(kstat_t *ksp, off_t index))
{
}

void
spl_kstat_init()
{
    /*
	 * Create the kstat root OID
	 */
	sysctl_register_oid(&sysctl__kstat);
}

void
spl_kstat_fini()
{
	/*
	 * Destroy the kstat module/class/name tree
	 *
	 * Done in two passes, first unregisters all
	 * of the oids, second releases all the memory.
	 */
	
	sysctl_tree_node_t *iter = tree_nodes;
	while (iter) {
		sysctl_tree_node_t *tn = iter;
		iter = tn->tn_next;
		sysctl_unregister_oid(&tn->tn_oid);
	}
	
	while (tree_nodes) {
		sysctl_tree_node_t *tn = tree_nodes;
		tree_nodes = tn->tn_next;
		bfree(tn, sizeof(sysctl_tree_node_t));
	}
	
    /*
     * Destroy the root oid
     */
    sysctl_unregister_oid(&sysctl__kstat);
}

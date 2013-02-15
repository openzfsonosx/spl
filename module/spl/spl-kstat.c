/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://github.com/behlendorf/spl/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************
 *  Solaris Porting Layer (SPL) Kstat Implementation.
\*****************************************************************************/

#include <sys/kstat.h>
#include <spl-debug.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/time.h>

/*
 * Extended kstat structure -- for internal use only.
 */
typedef struct ekstat {
        kstat_t         e_ks;           /* the kstat itself */
        size_t          e_size;         /* total allocation size */
        kthread_t       *e_owner;       /* thread holding this kstat */
        kcondvar_t      e_cv;           /* wait for owner == NULL */
} ekstat_t;


static void kstat_set_string(char *dst, const char *src)
{
    bzero(dst, KSTAT_STRLEN);
    (void) strncpy(dst, src, KSTAT_STRLEN - 1);
}

kstat_t *
kstat_create(char *ks_module, int ks_instance, char *ks_name, char *ks_class,
             uchar_t ks_type,
             ulong_t ks_ndata, uchar_t ks_flags)
{
    kstat_t *ksp;
    ekstat_t *e;
    size_t size;

    /*
     * Allocate memory for the new kstat header.
     */
    size = sizeof (ekstat_t);
    e = (ekstat_t *)zfs_kmem_alloc(size, KM_SLEEP);
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

    return (ksp);
}

void
kstat_install(kstat_t *ksp)
{
    ksp->ks_flags &= ~KSTAT_FLAG_INVALID;
}

void
kstat_delete(kstat_t *ksp)
{
    ekstat_t *e = (ekstat_t *)ksp;

    cv_destroy(&e->e_cv);
    zfs_kmem_free(e, e->e_size);
}

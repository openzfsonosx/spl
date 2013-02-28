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
\*****************************************************************************/

#ifndef _SPL_CRED_H
#define _SPL_CRED_H

//#include <linux/module.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/kauth.h>

//typedef struct task_struct cred_t;
typedef struct opaque_cred_t  cred_t;

#define kcred   (cred_t *)NOCRED
#define CRED()          (cred_t *)kauth_cred_get()

#include <AvailabilityMacros.h>

// Older OSX API
#if !(MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
#define kauth_cred_getruid(x) (x)->cr_ruid
#define kauth_cred_getrgid(x) (x)->cr_rgid
#define kauth_cred_getsvuid(x) (x)->cr_svuid
#endif


extern void crhold(cred_t *cr);
extern void crfree(cred_t *cr);
extern uid_t crgetuid(const cred_t *cr);
extern uid_t crgetruid(const cred_t *cr);
extern uid_t crgetsuid(const cred_t *cr);
extern uid_t crgetfsuid(const cred_t *cr);
extern gid_t crgetgid(const cred_t *cr);
extern gid_t crgetrgid(const cred_t *cr);
extern gid_t crgetsgid(const cred_t *cr);
extern gid_t crgetfsgid(const cred_t *cr);
extern int crgetngroups(const cred_t *cr);
extern gid_t * crgetgroups(const cred_t *cr);

#endif  /* _SPL_CRED_H */

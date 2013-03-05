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
 *  Solaris Porting Layer (SPL) Credential Implementation.
\*****************************************************************************/

#include <sys/cred.h>

/* Return the effective user id */
uid_t
crgetuid(const cred_t *cr)
{
    if (!cr) return 0;
	return kauth_cred_getuid((kauth_cred_t)cr);
}


/* Return the real user id */
uid_t
crgetruid(const cred_t *cr)
{
    if (!cr) return 0;
	return kauth_cred_getruid((kauth_cred_t)cr);
}

/* Return the saved user id */
uid_t
crgetsuid(const cred_t *cr)
{
    if (!cr) return 0;
	return kauth_cred_getsvuid((kauth_cred_t)cr);
}

/* Return the filesystem user id */
uid_t
crgetfsuid(const cred_t *cr)
{
    if (!cr) return 0;
	return -1;
}

/* Return the effective group id */
gid_t
crgetgid(const cred_t *cr)
{
    if (!cr) return 0;
    return kauth_cred_getgid((kauth_cred_t)cr);
}

/* Return the real group id */
gid_t
crgetrgid(const cred_t *cr)
{
    if (!cr) return 0;
    return kauth_cred_getrgid((kauth_cred_t)cr);
}

/* Return the saved group id */
gid_t
crgetsgid(const cred_t *cr)
{
    if (!cr) return 0;
    return kauth_cred_getsvgid((kauth_cred_t)cr);
}

/* Return the filesystem group id */
gid_t
crgetfsgid(const cred_t *cr)
{
	return -1;
}



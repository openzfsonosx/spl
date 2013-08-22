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



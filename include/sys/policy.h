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

#ifndef _SPL_POLICY_H
#define _SPL_POLICY_H

// These calls are slowly being moved into spl-vnode.c
#define	secpolicy_fs_unmount(c,vfs)			(0)
#define	secpolicy_nfs(c)				(0)
#define	secpolicy_sys_config(c,co)			(0)
#define	secpolicy_zfs(c)				(0)
#define	secpolicy_zinject(c)				(0)
//#define	secpolicy_vnode_setids_setgids(c,id)		(0)
//#define	secpolicy_vnode_setid_retain(c, sr)		(0)
//#define	secpolicy_setid_clear(v, c)			(0)
#define	secpolicy_vnode_any_access(c,vp,o)		(0)
#define	secpolicy_vnode_access2(c,cp,o,m1,m2)		(0)
//#define	secpolicy_vnode_chown(c,o)			(0)
//#define	secpolicy_vnode_setdac(c,o)			(0)
//#define	secpolicy_vnode_remove(c)			(0)
//#define	secpolicy_vnode_remove(c,x)			(0)
#define	secpolicy_vnode_setattr(c,v,a,o,f,func,n)	(0)
//#define	secpolicy_xvattr(x, o, c, t)			(0)
#define	secpolicy_vnode_stky_modify(c)			(0)
#define	secpolicy_setid_setsticky_clear(v,a,o,c)	(0)
//#define	secpolicy_basic_link(c)				(0)

#endif /* SPL_POLICY_H */

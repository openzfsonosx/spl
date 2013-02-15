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

#ifndef _SPL_ZFS_H
#define _SPL_ZFS_H

//#include <linux/mount.h>
///#include <linux/fs.h>
//#include <linux/dcache.h>
//#include <linux/statfs.h>
//#include <linux/xattr.h>
//#include <linux/security.h>
//#include <linux/seq_file.h>
#include <sys/attr.h>
#include <sys/mount.h>

#define	MAXFIDSZ	64

typedef struct mount vfs_t;

//#define LK_NOWAIT       0x00000010      /* do not sleep to await lock */
#define vn_vfswlock(vp)   (0)
#define vn_vfsunlock(vp)
#define VFS_HOLD(vfsp)
#define VFS_RELE(vfsp)



/*
 * File identifier.  Should be unique per filesystem on a single
 * machine.  This is typically called by a stateless file server
 * in order to generate "file handles".
 *
 * Do not change the definition of struct fid ... fid_t without
 * letting the CacheFS group know about it!  They will have to do at
 * least two things, in the same change that changes this structure:
 *   1. change CFSVERSION in usr/src/uts/common/sys/fs/cachefs_fs.h
 *   2. put the old version # in the canupgrade array
 *      in cachfs_upgrade() in usr/src/cmd/fs.d/cachefs/fsck/fsck.c
 * This is necessary because CacheFS stores FIDs on disk.
 *
 * Many underlying file systems cast a struct fid into other
 * file system dependent structures which may require 4 byte alignment.
 * Because a fid starts with a short it may not be 4 byte aligned, the
 * fid_pad will force the alignment.
 */
#define MAXFIDSZ        64
#define OLD_MAXFIDSZ    16

typedef struct fid {
    union {
        long fid_pad;
        struct {
            ushort_t len;   /* length of data in bytes */
            char    data[MAXFIDSZ]; /* data (variable len) */
        } _fid;
    } un;
} fid_t;


#endif /* SPL_ZFS_H */

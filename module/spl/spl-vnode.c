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
 *  Solaris Porting Layer (SPL) Vnode Implementation.
\*****************************************************************************/

#include <sys/vnode.h>
#include <spl-debug.h>
#include <libkern/libkern.h>
#include <sys/malloc.h>

int
vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode,
        struct vnode **vpp, enum create crwhy, mode_t umask)
{
    vfs_context_t vctx;
    int fmode;
    int error;

    fmode = filemode;
    if (crwhy)
        fmode |= O_CREAT;
    // TODO I think this should be 'fmode' instead of 'filemode'
    vctx = vfs_context_create((vfs_context_t)0);
    error = vnode_open(pnamep, filemode, createmode, 0, vpp, vctx);
    (void) vfs_context_rele(vctx);
    return (error);
}

int
vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode,
          struct vnode **vpp, enum create crwhy,
          mode_t umask, struct vnode *startvp)
{
    char *path;
    int pathlen = MAXPATHLEN;
    int error;

    path = (char *)zfs_kmem_zalloc(MAXPATHLEN, KM_SLEEP);

    error = vn_getpath(startvp, path, &pathlen);
    if (error == 0) {
        strlcat(path, pnamep, MAXPATHLEN);
        error = vn_open(path, seg, filemode, createmode, vpp, crwhy,
                        umask);
    }

    zfs_kmem_free(path, MAXPATHLEN);
    return (error);
}

extern errno_t vnode_rename(const char *, const char *, int, vfs_context_t);

errno_t
vnode_rename(const char *from, const char *to, int flags, vfs_context_t vctx)
{
    /*
     * We need proper KPI changes to be able to safely update
     * the zpool.cache file. For now, we return EPERM.
     */
    return (EPERM);
}

int
vn_rename(char *from, char *to, enum uio_seg seg)
{
    vfs_context_t vctx;
    int error;

    vctx = vfs_context_create((vfs_context_t)0);

    error = vnode_rename(from, to, 0, vctx);

    (void) vfs_context_rele(vctx);

    return (error);
}

extern errno_t vnode_remove(const char *, int, enum vtype, vfs_context_t);

errno_t
vnode_remove(const char *name, int flag, enum vtype type, vfs_context_t vctx)
{
    printf("vnode_remove: \"%s\"\n", name);
    printf("zfs: vnode_remove not yet supported\n");
    return (EPERM);
}


int
vn_remove(char *fnamep, enum uio_seg seg, enum rm dirflag)
{
    vfs_context_t vctx;
    enum vtype type;
    int error;

    type = dirflag == RMDIRECTORY ? VDIR : VREG;

    vctx = vfs_context_create((vfs_context_t)0);

    error = vnode_remove(fnamep, 0, type, vctx);

    (void) vfs_context_rele(vctx);

    return (error);
}

int zfs_vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len,
                offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit,
                cred_t *cr, ssize_t *residp)
{
    uio_t *auio;
    int spacetype;
    int error=0;
    vfs_context_t vctx;

    spacetype = UIO_SEG_IS_USER_SPACE(seg) ? UIO_USERSPACE32 : UIO_SYSSPACE;

    vctx = vfs_context_create((vfs_context_t)0);
    auio = uio_create(1, 0, spacetype, rw);
    uio_reset(auio, offset, spacetype, rw);
    uio_addiov(auio, (uint64_t)(uintptr_t)base, len);

    if (rw == UIO_READ) {
        error = VNOP_READ(vp, auio, ioflag, vctx);
    } else {
        error = VNOP_WRITE(vp, auio, ioflag, vctx);
    }

    if (residp) {
        *residp = uio_resid(auio);
    } else {
        if (uio_resid(auio) && error == 0)
            error = EIO;
    }

    uio_free(auio);
    vfs_context_rele(vctx);

    return (error);
}



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

#include <sys/vnode.h>
#include <spl-debug.h>
#include <sys/malloc.h>
#include <IOKit/IOLib.h>

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
    //printf("vn_open '%s' -> %d (vp %p)\n", pnamep, error, *vpp);
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
    IOLog("vnode_remove: \"%s\"\n", name);
    IOLog("zfs: vnode_remove not yet supported\n");
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


int
VOP_SPACE(struct vnode *vp, int cmd, void *fl, int flags, offset_t off,
          cred_t *cr, void *ctx)
{
    return (0);
}

int
VOP_CLOSE(struct vnode *vp, int flag, int count, offset_t off, void *cr, void *k)
{
    vfs_context_t vctx;
    int error;

    vctx = vfs_context_create((vfs_context_t)0);
    error = vnode_close(vp, flag & FWRITE, vctx);
    (void) vfs_context_rele(vctx);
    return (error);
}

int
VOP_FSYNC(struct vnode *vp, int flags, void* unused, void *uused2)
{
    vfs_context_t vctx;
    int error;

    vctx = vfs_context_create((vfs_context_t)0);
    error = VNOP_FSYNC(vp, (flags == FSYNC), vctx);
    (void) vfs_context_rele(vctx);
    return (error);
}

int VOP_GETATTR(struct vnode *vp, vattr_t *vap, int flags, void *x3, void *x4)
{
    vfs_context_t vctx;
    int error;

    //vap->va_size = 134217728;
    //return 0;

    //    panic("take this");
    //printf("VOP_GETATTR(%p, %p, %d)\n", vp, vap, flags);
    vctx = vfs_context_create((vfs_context_t)0);
    error= vnode_getattr(vp, vap, vctx);
    (void) vfs_context_rele(vctx);
    return error;
}


void vfs_mountedfrom(struct mount *vfsp, char *osname)
{
    (void) copystr(osname, vfs_statfs(vfsp)->f_mntfromname, MNAMELEN - 1, 0);
}



/*
 * Security Policy
 */


int
secpolicy_vnode_remove(struct vnode *vp, const cred_t *cr)
{
    return (0);
}

int
secpolicy_vnode_create_gid(const cred_t *cred)
{
    return (0);
}

int secpolicy_vnode_setids_setgids(struct vnode *vp, const cred_t *cr,
                                          gid_t gid)
{
    return 0;
}


int secpolicy_vnode_setdac(struct vnode *vp, const cred_t *cr, uid_t u)
{
    return 0;
}

int secpolicy_vnode_chown( struct vnode *vp, const cred_t *cr, uid_t u)
{
    return 0;
}

int secpolicy_vnode_setid_retain( struct vnode *vp, const cred_t *cr,
                                  int fal)
{
    return 0;
}

int secpolicy_xvattr(struct vnode *dvp, vattr_t *vap, uid_t uid,
                     const cred_t *cr, enum vtype ty)
{
    return 0;
}

int secpolicy_setid_clear(vattr_t *vap, struct vnode *vp,
                          const cred_t *cr)
{
    return 0;
}

int secpolicy_basic_link(struct vnode *svp, const cred_t *cr)
{
    return 0;
}

int secpolicy_fs_mount_clearopts(const cred_t *cr, struct mount *mp)
{
    return 0;
}

int secpolicy_fs_mount(const cred_t *cr, struct vnode *vp, struct mount *mp)
{
    return 0;
}









/*
 * DNLC Name Cache Support
 */
struct vnode *
dnlc_lookup(struct vnode *dvp, char *name)
{
    struct componentname cn;
	struct vnode *vp;

    //return DNLC_NO_VNODE;
	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);

	switch(cache_lookup(dvp, &vp, &cn)) {
	case -1:
		break;
	case ENOENT:
		vp = DNLC_NO_VNODE;
		break;
	default:
		vp = NULLVP;
	}
	return (vp);
}

int dnlc_purge_vfsp(struct mount *mp, int flags)
{
    return 0;
}

void dnlc_remove(struct vnode *vp, char *name)
{
    cache_purge(vp);
    return;
}


/*
 *
 *
 */
void dnlc_update(struct vnode *vp, char *name, struct vnode *tp)
{
    // If tp is NULL, it is a negative-cache entry
    struct componentname cn;

    // OSX panics if you give empty(non-NULL) name
    if (!name || !*name || !strlen(name)) return;

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);

    cache_enter(vp, tp==DNLC_NO_VNODE?NULL:tp, &cn);
    return;
}

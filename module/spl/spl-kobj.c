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
 *  Solaris Porting Layer (SPL) Kobj Implementation.
\*****************************************************************************/

#include <sys/kobj.h>
#include <spl-debug.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>

struct _buf *
kobj_open_file(char *name)
{
    struct vnode *vp;
    vfs_context_t vctx;
    struct _buf *file;
    int error;

    vctx = vfs_context_create((vfs_context_t)0);
    error = vnode_open(name, 0, 0, 0, &vp, vctx);
    (void) vfs_context_rele(vctx);

    printf("kobj_open_file: \"%s\", err %d from vnode_open\n", name ? name : "", error);

    if (error) {
        return ((struct _buf *)-1);
    }
    file = (struct _buf *)zfs_kmem_alloc(sizeof (struct _buf *), KM_SLEEP);
    file->_fd = (intptr_t)vp;

    return (file);
}

void
kobj_close_file(struct _buf *file)
{
    vfs_context_t vctx;

    vctx = vfs_context_create((vfs_context_t)0);
    (void) vnode_close((vnode_t)file->_fd, 0, vctx);
    (void) vfs_context_rele(vctx);

    zfs_kmem_free(file, sizeof (struct _buf));
}

int
kobj_fstat(struct vnode *vp, struct bootstat *buf)
{
    struct vnode_attr vattr;
    vfs_context_t vctx;
    int error;

    if (buf == NULL)
        return (-1);

    VATTR_INIT(&vattr);
    VATTR_WANTED(&vattr, va_mode);
    VATTR_WANTED(&vattr, va_data_size);
    vattr.va_mode = 0;
    vattr.va_data_size = 0;

    vctx = vfs_context_create((vfs_context_t)0);
    error = vnode_getattr(vp, &vattr, vctx);
    (void) vfs_context_rele(vctx);

    if (error == 0) {
        //buf->st_mode = (uint32_t)vattr.va_mode;
        buf->st_size = vattr.va_data_size;
    }
    return (error);
}

int
kobj_read_file(struct _buf *file, char *buf, ssize_t size, offset_t off)
{
    struct vnode *vp = (vnode_t)file->_fd;
    vfs_context_t vctx;
    uio_t *auio;
    int count;
    int error;

    vctx = vfs_context_create((vfs_context_t)0);
    auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);
    uio_reset(auio, off, UIO_SYSSPACE32, UIO_READ);
    uio_addiov(auio, (uintptr_t)buf, size);

    error = VNOP_READ(vp, auio, 0, vctx);

    if (error)
        count = -1;
    else
        count = size - uio_resid(auio);

    uio_free(auio);
    (void) vfs_context_rele(vctx);

    return (count);
}

/*
 * Get the file size.
 *
 * Before root is mounted, files are compressed in the boot_archive ramdisk
 * (in the memory). kobj_fstat would return the compressed file size.
 * In order to get the uncompressed file size, read the file to the end and
 * count its size.
 */
int
kobj_get_filesize(struct _buf *file, uint64_t *size)
{
    /*
     * In OSX, the root will always be mounted, so we can
     * just use kobj_fstat to stat the file
     */
    struct bootstat bst;

    if (kobj_fstat((vnode_t)file->_fd, &bst) != 0)
        return (EIO);
    *size = bst.st_size;
    return (0);
}

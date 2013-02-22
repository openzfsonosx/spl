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
 *  z_compress_level/z_uncompress are nearly identical copies of the
 *  compress2/uncompress functions provided by the official zlib package
 *  available at http://zlib.net/.  The only changes made we to slightly
 *  adapt the functions called to match the linux kernel implementation
 *  of zlib.  The full zlib license follows:
 *
 *  zlib.h -- interface of the 'zlib' general purpose compression library
 *  version 1.2.5, April 19th, 2010
 *
 *  Copyright (C) 1995-2010 Jean-loup Gailly and Mark Adler
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty.  In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgment in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 *
 *  Jean-loup Gailly
 *  Mark Adler
\*****************************************************************************/

#ifndef _SPL_ZMOD_H
#define _SPL_ZMOD_H


#include <sys/types.h>
//#include <linux/zlib.h>
#include <libkern/zlib.h>
#include <sys/kmem.h>

struct _zmemheader {
    uint64_t        length;
    char            data[0];
};

static inline void *
zfs_zalloc(void* opaque, uInt items, uInt size)
{
    struct _zmemheader *hdr;
    size_t alloc_size = (items * size) + sizeof (uint64_t);
    hdr = zfs_kmem_zalloc(alloc_size, KM_SLEEP);
    hdr->length = alloc_size;
    return (&hdr->data);
}

static inline void
zfs_zfree(void *opaque, void *addr)
{
    struct _zmemheader *hdr;
    hdr = addr;
    hdr--;
    zfs_kmem_free(hdr, hdr->length);
}

/*
 * Uncompress the buffer 'src' into the buffer 'dst'.  The caller must store
 * the expected decompressed data size externally so it can be passed in.
 * The resulting decompressed size is then returned through dstlen.  This
 * function return Z_OK on success, or another error code on failure.
 */
static inline int
    z_uncompress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
    z_stream zs;
    int err;

    bzero(&zs, sizeof (zs));
    zs.next_in = (uchar_t *)src;
    zs.avail_in = srclen;
    zs.next_out = dst;
    zs.avail_out = *dstlen;
    zs.zalloc = zfs_zalloc;
    zs.zfree = zfs_zfree;
    if ((err = inflateInit(&zs)) != Z_OK)
        return (err);
    if ((err = inflate(&zs, Z_FINISH)) != Z_STREAM_END) {
        (void) inflateEnd(&zs);
        return (err == Z_OK ? Z_BUF_ERROR : err);
    }
    *dstlen = zs.total_out;
    return (inflateEnd(&zs));
}

static inline int
z_compress_level(void *dst, size_t *dstlen, const void *src, size_t srclen,
                 int level)
{
    z_stream zs;
    int err;
    bzero(&zs, sizeof (zs));
    zs.next_in = (uchar_t *)src;
    zs.avail_in = srclen;
    zs.next_out = dst;
    zs.avail_out = *dstlen;
    zs.zalloc = zfs_zalloc;
    zs.zfree = zfs_zfree;
    if ((err = deflateInit(&zs, level)) != Z_OK)
        return (err);
    if ((err = deflate(&zs, Z_FINISH)) != Z_STREAM_END) {
        (void) deflateEnd(&zs);
        return (err == Z_OK ? Z_BUF_ERROR : err);
    }
    *dstlen = zs.total_out;
    return (deflateEnd(&zs));
}

static inline int
z_compress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
    return (z_compress_level(dst, dstlen, src, srclen,
                             Z_DEFAULT_COMPRESSION));
}


int spl_zlib_init(void);
void spl_zlib_fini(void);

#endif /* SPL_ZMOD_H */

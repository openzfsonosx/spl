
#ifndef _SPL_MOUNT_H
#define _SPL_MOUNT_H

#undef vnode_t
#include_next <sys/mount.h>
#define vnode_t struct vnode

#endif /* SPL_MOUNT_H */

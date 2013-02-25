#ifndef UBC_H_INCLUDED
#define UBC_H_INCLUDED

#undef vnode_t
#include_next <sys/ubc.h>
#define vnode_t struct vnode



#endif

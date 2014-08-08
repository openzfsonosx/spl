#ifndef _SPL_PRIV_H
#define _SPL_PRIV_H

//#include_next <sys/priv.h>

#if defined (__FreeBSD__) || defined(__APPLE__)
/*
 * ZFS-specific privileges.
 */
#define	PRIV_ZFS_POOL_CONFIG	280	/* Can configure ZFS pools. */
#define	PRIV_ZFS_INJECT		281	/* Can inject faults in the ZFS fault
					   injection framework. */
#endif

#if defined (__FreeBSD__)
#define	PRIV_ZFS_JAIL		282	/* Can attach/detach ZFS file systems
					   to/from jails. */
#endif

#endif  /* _SPL_PRIV_H */

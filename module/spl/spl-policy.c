#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/priv.h>

int
spl_priv_check_cred(kauth_cred_t cred, int priv, __unused int flags)
{
	int error;

	if (kauth_cred_getuid(cred) == 0) {
		error = 0;
		goto out;
	}

	/*
	 * The default is deny, so if no policies have granted it, reject
	 * with a privilege error here.
	 */
	error = EPERM;
out:
	return (error);
}

#ifdef illumos
/*
 * Catch all system configuration.
 */
int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
	if (checkonly) {
		return (PRIV_POLICY_ONLY(cr, PRIV_SYS_CONFIG, B_FALSE) ? 0 :
		    EPERM);
	} else {
		return (PRIV_POLICY(cr, PRIV_SYS_CONFIG, B_FALSE, EPERM, NULL));
	}
}
#elif defined (__FreeBSD__)
int
secpolicy_sys_config(cred_t *cr, int checkonly __unused)
{
	return (priv_check_cred(cr, PRIV_ZFS_POOL_CONFIG, 0));
}
#elif defined(__OPPLE__)
int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
        return (spl_priv_check_cred((kauth_cred_t)cr, PRIV_ZFS_POOL_CONFIG, 0));
}
#endif

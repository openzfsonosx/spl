
#ifndef _SPL_PARAM_H
#define _SPL_PARAM_H

#include_next <sys/param.h>
#include <mach/vm_param.h>

/* Pages to bytes and back */
#define ptob(pages)			(pages << PAGE_SHIFT)
#define btop(bytes)			(bytes >> PAGE_SHIFT)

#define MAXUID				UINT32_MAX

#endif /* SPL_PARAM_H */

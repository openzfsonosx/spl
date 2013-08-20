#include <sys/sysmacros.h>
#include <spl-debug.h>
#include <spl-trace.h>
#include <spl-ctl.h>

#ifdef SS_DEBUG_SUBSYS
#undef SS_DEBUG_SUBSYS
#endif

#define SS_DEBUG_SUBSYS SS_DEBUG

/* Debug log support enabled */

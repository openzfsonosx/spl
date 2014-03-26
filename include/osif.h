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

#ifndef OSIF_H
#define OSIF_H

#include <stdint.h>
#include <string.h>

#ifdef _KERNEL
#define IN_KERNEL 1
#else
#undef IN_KERNEL
#endif

#ifndef IN_KERNEL
#include "pthread.h"
#endif

typedef uint64_t sa_size_t;

void* osif_malloc(sa_size_t size);
void osif_free(void* buf, sa_size_t size);
void osif_zero_memory(void* buf, sa_size_t size);

#ifdef IN_KERNEL
typedef kmutex_t osif_mutex;
#else
typedef pthread_mutex_t osif_mutex;
#endif

void osif_mutex_init(osif_mutex* mutex);
void osif_mutex_enter(osif_mutex* mutex);
void osif_mutex_exit(osif_mutex* mutex);
void osif_mutex_destroy(osif_mutex* mutex);

int osif_memory_pressure();

#endif

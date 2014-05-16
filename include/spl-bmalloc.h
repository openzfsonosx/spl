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
 * Copyright 2014 Brendon Humphrey (brendon.humphrey@mac.com)
 *
 * CDDL HEADER END
 */

#ifndef BMALLOC_H
#define BMALLOC_H

//
// Initialises the allocator, must be called before any other function.
//
void bmalloc_init();

//
// Allocate <size> bytes of memory for the application
//
void* bmalloc(uint64_t size);

//
// Release memory from the application
//
void bfree(void* buf, uint64_t size);

//
// Release all free memory within the allocator
// Should be invoked if the machine is under
// memory pressure.
//
void bmalloc_release_memory();

//
// Manages from free memory within the allocator.
// Should be called periodically (say at least
// every 10 seconds).
//
void bmalloc_garbage_collect();

//
// Release all remaining memory and allocator resources
//
void bmalloc_fini();

#endif

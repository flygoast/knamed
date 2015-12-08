/*
 * Copyright (c) 2015, Gu Feng <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <linux/slab.h>
#include "knamed_memory.h"


#define KNAMED_ALIGN_UP(x, s)   (((x) + s - 1) & (~(s - 1)))


#define KNAMED_LARGE_SIZE       4096
#define KNAMED_UNIT_SIZE        8


int                  nr_data_cache;
struct kmem_cache  **data_cachep;


int
knamed_memory_init(void)
{
    int      i, log;
    size_t   size;
    uint8_t  buf[128];

    for (log = 3; (1 << log) < KNAMED_LARGE_SIZE; log++);

    nr_data_cache = log - 2;

    data_cachep = (struct kmem_cache **) kzalloc(
                         sizeof(struct kmem_cache *) * nr_data_cache, GFP_KERNEL);

    if (data_cachep == NULL) {
        goto failed;
    }

    size = 8;
    for (i = 0; i < nr_data_cache; i++, size *= 2) {
        snprintf(buf, sizeof(buf) - 1, "knamed-size-%d", (int) size);
        data_cachep[i] = kmem_cache_create(buf, size, 0,
                                           SLAB_HWCACHE_ALIGN, NULL);
        if (data_cachep[i] == NULL) {
            goto failed;
        }
    }

    return 0;

failed:

    if (data_cachep) {
        for (i = 0; i < nr_data_cache; i++) {
            if (data_cachep[i] != NULL) {
                kmem_cache_destroy(data_cachep[i]);
            }
        }

        kfree(data_cachep);
    }

    return -EINVAL;
}


void
knamed_memory_release(void)
{
    int  i;

    if (data_cachep) {
        for (i = 0; i < nr_data_cache; i++) {
            if (data_cachep[i] != NULL) {
                kmem_cache_destroy(data_cachep[i]);
            }
        }

        kfree(data_cachep);
    }
}


void *
knamed_memory_alloc(size_t size)
{
    void    *p;
    int      log;
    size_t   rounded_size;

    log = 3;
    rounded_size = 1 << log;
    while (rounded_size < size) {
        log++;
        rounded_size <<= 1;
    }

    if (rounded_size > KNAMED_LARGE_SIZE) {
        p = kmalloc(rounded_size, GFP_KERNEL);
        return p;
    }

    p = kmem_cache_alloc(data_cachep[log - 3], GFP_KERNEL);

    return p;
}


void
knamed_memory_free(void *p, size_t size)
{
    int      log;
    size_t   rounded_size;

    log = 3;
    rounded_size = 1 << log;
    while (rounded_size < size) {
        log++;
        rounded_size <<= 1;
    }

    if (rounded_size > KNAMED_LARGE_SIZE) {
        kfree(p);
        return;
    }

    kmem_cache_free(data_cachep[log - 3], p);
}

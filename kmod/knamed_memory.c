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
#include <linux/vmalloc.h>
#include <linux/log2.h>
#include "knamed.h"
#include "knamed_memory.h"


#define KNAMED_ALIGN_UP(x, s)   (((x) + s - 1) & (~(s - 1)))


#define KNAMED_LARGE_SIZE       4096
#define KNAMED_UNIT_LOG         4
#define KNAMED_UNIT_SIZE        (1 << KNAMED_UNIT_LOG)
#define KNAMED_NAME_SIZE        64


struct data_cache {
    struct kmem_cache  *cachep;
    uint8_t            *name;
};


int                 nr_data_cache;
struct data_cache  *data_cachep;
struct kmem_cache  *name_cachep;


int
knamed_memory_init(void)
{
    int       i, log;
    size_t    size;
    uint8_t  *buf;

    for (log = KNAMED_UNIT_LOG; (1 << log) < KNAMED_LARGE_SIZE; log++);

    nr_data_cache = log - KNAMED_UNIT_LOG + 1;

    PR_INFO("LOG: %d, count: %d", log, nr_data_cache);

    name_cachep = kmem_cache_create("knamed_name", KNAMED_NAME_SIZE, 0,
                                    SLAB_HWCACHE_ALIGN, NULL);
    if (name_cachep == NULL) {
        goto failed;
    }

    data_cachep = (struct data_cache *) kzalloc(
                           sizeof(struct data_cache) * nr_data_cache, GFP_KERNEL);

    if (data_cachep == NULL) {
        goto failed;
    }

    size = KNAMED_UNIT_SIZE;
    for (i = 0; i < nr_data_cache; i++, size <<= 1) {
        buf = kmem_cache_alloc(name_cachep, GFP_KERNEL);
        snprintf(buf, KNAMED_NAME_SIZE - 1, "knamed-size-%d", (int) size);
        PR_INFO("NAME: %s", buf);

        data_cachep[i].name = buf;
        data_cachep[i].cachep = kmem_cache_create(buf, size, 0,
                                                  SLAB_HWCACHE_ALIGN, NULL);
        if (data_cachep[i].cachep == NULL) {
            goto failed;
        }
    }

    return 0;

failed:

    knamed_memory_release();

    return -EINVAL;
}


void
knamed_memory_release(void)
{
    int  i;

    if (name_cachep) {
        if (data_cachep) {
            for (i = 0; i < nr_data_cache; i++) {
                if (data_cachep[i].cachep != NULL) {
                    kmem_cache_destroy(data_cachep[i].cachep);
                    data_cachep[i].cachep = NULL;
                }

                if (data_cachep[i].name != NULL) {
                    kmem_cache_free(name_cachep, data_cachep[i].name);
                    data_cachep[i].name = NULL;
                }
            }

            nr_data_cache = 0;
            kfree(data_cachep);
            data_cachep = NULL;
        }

        kmem_cache_destroy(name_cachep);
    }
}


void *
knamed_memory_alloc(size_t size)
{
    void    *p;
    int      log;
    size_t   rounded_size;

    rounded_size = roundup_pow_of_two(size + sizeof(size_t));
    log = ilog2(rounded_size);

    if (rounded_size > KNAMED_LARGE_SIZE) {
        p = __vmalloc(rounded_size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
        *(size_t *) p = size;
        return p + sizeof(size_t);
    }

    p = kmem_cache_alloc(data_cachep[log - KNAMED_UNIT_LOG].cachep, GFP_KERNEL);
    *(size_t *) p = size;

    return p + sizeof(size_t);
}


void *
knamed_memory_zalloc(size_t size)
{
    void    *p;
    int      log;
    size_t   rounded_size;

    rounded_size = roundup_pow_of_two(size + sizeof(size_t));
    log = ilog2(rounded_size);

    if (rounded_size > KNAMED_LARGE_SIZE) {
        p = __vmalloc(rounded_size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
                      PAGE_KERNEL);
        *(size_t *) p = size;
        return p + sizeof(size_t);
    }

    p = kmem_cache_zalloc(data_cachep[log - KNAMED_UNIT_LOG].cachep, GFP_KERNEL);
    *(size_t *) p = size;

    return p + sizeof(size_t);
}


void
knamed_memory_free(void *p)
{
    int       log;
    size_t    rounded_size, size;
    void     *np;

    if (p == NULL) {
        return;
    }

    np = p - sizeof(size_t);

    size = *(size_t *) np;

    rounded_size = roundup_pow_of_two(size + sizeof(size_t));
    log = ilog2(rounded_size);

    if (rounded_size > KNAMED_LARGE_SIZE) {
        vfree(np);
        return;
    }

    kmem_cache_free(data_cachep[log - KNAMED_UNIT_LOG].cachep, np);
}

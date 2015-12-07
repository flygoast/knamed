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


#include "knamed_mempool.h"


#define KNAMED_ALIGN_UP     (((x) + s - 1) & (~(s - 1)))


#define KNAMED_LARGE_SIZE   4096
#define KNAMED_UNIT_SIZE    8


struct knamed_mempool {
    size_t         large_object_size;
    kmem_cache   **data_cachep;
};


struct knamed_mempool *
knamed_mempool_create(const char *name)
{
    int                     i, count;
    struct knamed_mempool  *pool;
    uint8_t                 buf[128];

    pool = (struct knamed_mempool *) kcalloc(sizeof(struct knamed_mempool),
                                             GFP_KERNEL);
    if (pool == NULL) {
        goto failed;
    }

    pool->large_object_size = KNAMED_LARGE_SIZE;

    count = pool->large_object_size / KNAMED_UNIT_SIZE;

    pool->data_cachep = (struct kmem_cache *) kcalloc(
                                 sizeof(struct kmem_cache *) * count, GFP_KERNEL);

    if (pool->data_cachep == NULL) {
        goto failed;
    }

    for (i = 1; i <= count; i++) {
        snprintf(buf, sizeof(buf) - 1, "%s-size-%d", name, i * KNAMED_UNIT_SIZE);
        pool->data_cachep[i] = kmem_cache_create(buf, i * KNAMED_UNIT_SIZE,
                                                 0, SLAB_HWCACHE_ALIGN, NULL);
        if (pool->data_cachep[i] == NULL) {
            goto failed;
        }
    }

    return pool;

failed:

    if (pool != NULL) {
        if (pool->data_cachep) {
            for (i = 1; i <= count; i++) {
                if (pool->data_cachep[i] != NULL) {
                    kmem_cache_destroy(pool->data_cachep[i]);
                }
            }

            kfree(pool->data_cachep);
        }

        kfree(pool);
    }

    return NULL;
}


void
knamed_mempool_destroy(struct knamed_mempool *pool)
{
    int  i, count;

    count = pool->large_object_size / KNAMED_UNIT_SIZE;

    if (pool != NULL) {
        if (pool->cleanup_cachep) {
            kmem_cache_destroy(pool->cleanup_cachep);
        }

        if (pool->data_cachep) {
            for (i = 1; i <= count; i++) {
                if (pool->data_cachep[i] != NULL) {
                    kmem_cache_destroy(pool->data_cachep[i]);
                }
            }

            kfree(pool->data_cachep);
        }

        kfree(pool);
    }
}


void *
knamed_mempool_alloc(struct knamed_mempool *pool, size_t size)
{
    void    *p;
    int      i;
    size_t   aligned_size;

    aligned_size = KNAMED_ALIGN_UP(size, KNAMED_UNIT_SIZE);

    if (aligned_size > pool->large_object_size) {
        p = kmalloc(aligned_size, GFP_KERNEL);
        return p;
    }

    i = aligned_size / KNAMED_UNIT_SIZE;

    p = kmem_cache_alloc(pool->data_cachep[i], GFP_KERNEL);

    return p;
}


void
knamed_mempool_free(struct knamed_mempool *pool, void *p, size_t size)
{
    int     i;
    size_t  aligned_size;

    aligned_size = KNAMED_ALIGN_UP(size, KNAMED_UNIT_SIZE);

    if (aligned_size > pool->large_object_size) {
        kfree(p);
        return;
    }

    i = aligned_size / KNAMED_UNIT_SIZE;

    kmem_cache_free(pool->data_cachep[i], p);
}

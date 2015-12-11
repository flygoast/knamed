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


#include <linux/list.h>
#include <linux/slab.h>
#include "knamed.h"
#include "knamed_memory.h"
#include "knamed_iptable.h"


knamed_iptable_slot_t *
iptable_find(knamed_iptable_t *iptable, uint32_t addr)
{
    int                     i, h;
    uint32_t                a, m;
    knamed_iptable_slot_t  *slot;

    if (iptable == NULL) {
        return NULL;
    }

    m = 0xffffffff;
    for (i = 32; i >= 0; i--) {
        a = addr & (m << (32 - i));
        h = ((a >> 24) + (a >> 16) + (a >> 8) + (a & 0xff)) & 0xff;

        list_for_each_entry(slot, &iptable->hash[i].bucket[h], list) {
            if (a == slot->addr) {
                return slot;
            }
        }
    }

    return NULL;
}


int
knamed_iptable_add(knamed_iptable_t *iptable, uint32_t addr, int mask,
    void *value)
{
    knamed_iptable_slot_t  *slot;
    int                     h;
    uint32_t                m;

    if (mask < 0 || mask > 32) {
        return -1;
    }

    slot = (knamed_iptable_slot_t *) knamed_memory_alloc(
                                                 sizeof(knamed_iptable_slot_t));
    if (slot == NULL) {
        return -ENOMEM;
    }

    m = 0xffffffff;
    addr = addr & (m << (32 - mask));

    h = ((addr >> 24) + (addr >> 16) + (addr >> 8) + (addr & 0xff)) & 0xff;

    PR_INFO("ADD: %x %x", addr, h);
    slot->addr = addr;
    slot->value = value;

    list_add(&slot->list, &iptable->hash[mask].bucket[h]);

    return 0;
}


knamed_iptable_t *
knamed_iptable_create(void)
{
    int                i, j;
    knamed_iptable_t  *iptable;

    iptable = (knamed_iptable_t *) knamed_memory_alloc(
                                                      sizeof(knamed_iptable_t));
    if (iptable == NULL) {
        return NULL;
    }

    for (i = 0; i < 33; i++) {
        iptable->hash[i].bucket = NULL;
        iptable->hash[i].bucket = (struct list_head *) knamed_memory_alloc(
                                   sizeof(struct list_head) * HASH_BUCKET_SIZE);
        if (iptable->hash[i].bucket == NULL) {
            goto err;
        }

        for (j = 0; j < HASH_BUCKET_SIZE; j++) {
            INIT_LIST_HEAD(&iptable->hash[i].bucket[j]);
        }
    }

    return iptable;

err:

    for (i = 0; i < 33; i++) {
        if (iptable->hash[i].bucket == NULL) {
            knamed_memory_free(iptable->hash[i].bucket);
        }
    }

    knamed_memory_free(iptable);

    return NULL;
}


void
knamed_iptable_destroy(knamed_iptable_t *iptable,
    void (*value_free)(void *value))
{
    int                     i, j;
    knamed_iptable_slot_t  *slot, *s;

    if (iptable == NULL) {
        return;
    }

    for (i = 0; i < 33; i++) {
        for (j = 0; j < HASH_BUCKET_SIZE; j++) {
            list_for_each_entry_safe(slot, s,
                                     &iptable->hash[i].bucket[j], list)
            {
                list_del(&slot->list);

                if (value_free) {
                    value_free(slot->value);
                }
                knamed_memory_free(slot);
            }
        }

        knamed_memory_free(iptable->hash[i].bucket);
    }

    knamed_memory_free(iptable);
}


void
knamed_iptable_dump(knamed_iptable_t *iptable)
{
    knamed_iptable_slot_t  *slot;
    int                     i, j, buckets;
    int                     chain_len, max_chain_len, total_chain_len;
    int                     count[50];

    if (iptable == NULL) {
        return;
    }

    for (i = 0; i < 33; i++) {
        buckets = 0;
        max_chain_len = 0;
        total_chain_len = 0;

        memset(count, 0, sizeof(count));

        for (j = 0; j < HASH_BUCKET_SIZE; j++) {
            chain_len = 0;

            if (list_empty(&iptable->hash[i].bucket[j])) {
                count[0]++;
                continue;
            }

            buckets++;
            list_for_each_entry(slot, &iptable->hash[i].bucket[j], list) {
                chain_len++;
            }

            count[(chain_len < 50) ? chain_len : 49]++;

            if (chain_len > max_chain_len) {
                max_chain_len = chain_len;
            }

            total_chain_len += chain_len;
        }

        if (total_chain_len != 0) {
            PR_INFO("========== iptable dump ===========");
            PR_INFO("mask: %d", i);
            PR_INFO(" number of elements: %d", total_chain_len);
            PR_INFO(" buckets: %d", buckets);
            PR_INFO(" max chain length: %d", max_chain_len);
            PR_INFO(" avg chain length: %d", total_chain_len / buckets);
            PR_INFO(" chain length distribution:");
            for (j = 0; j < 50; j++) {
                if (count[j] == 0) {
                    continue;
                }
                PR_INFO("     %s%d: %d (%d%%)", (j == 49) ? ">=" : "",
                        j, count[j], count[j] * 100 / HASH_BUCKET_SIZE);
            }
        }
    }
}

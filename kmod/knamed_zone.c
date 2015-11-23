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


#include "knamed.h"
#include "knamed_zone.h"
#include "knamed_util.h"


LIST_HEAD(dns_zones);


int
name_encode(uint8_t *buf, int blen, uint8_t *str, int slen)
{
    uint8_t  *p, *q, *last, c;

    if (blen < slen + 1) {
        return -1;
    }

    if (*str == '.' || *str == '\0') {
        return -1;
    }

    q = buf;
    p = buf + 1;
    last = str + slen;

    while (str <= last) {
        c = *str++;
        if (c == '.' || c == '\0') {
            *q = p - q - 1;

            if (c == '\0') {
                *p++ = '\0';
                break;
            }
            q = p++;

        } else {
            if (c > 0x40 && c < 0x5B) {
                *p++ = c | 0x20;
            } else {
                *p++ = c;
            }
        }
    }

    return p - buf;
}


struct dns_zone *
zone_create(uint8_t *name, int default_ttl, uint8_t *peer)
{
    int               i;
    struct dns_zone  *zone;

    if (name == NULL || peer == NULL || default_ttl < 0) {
        return NULL;
    }

    zone = (struct dns_zone *) kmalloc(sizeof(struct dns_zone), GFP_KERNEL);
    if (zone == NULL) {
        return NULL;
    }

    strncpy(zone->name, name, MAX_DOMAIN_LEN);
    zone->len = strlen(zone->name);

    zone->peer_len = 0;
    if (peer) {
        strncpy(zone->peer, peer, MAX_LABEL_LEN);
        zone->peer_len = strlen(zone->peer);
    }

    for (i = 0; i < RECORD_HASH_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&zone->records_table[i]);
    }

    list_add_tail(&zone->list, &dns_zones);

    return zone;
}


struct dns_zone *
zone_find(struct dns_query *query)
{
    struct dns_zone  *zone;
    uint8_t          *p;

    p = query->name;

    list_for_each_entry(zone, &dns_zones, list) {
        if (query->len > zone->len
            && *(p + (query->len - zone->len - 1)) == '.'
            && strncmp(p + query->len - zone->len, zone->name, zone->len) == 0)
        {
            PR_INFO("Found zone \"%s\" for query \"%s\"",
                    zone->name, query->name);

            return zone;

        } else if (query->len == zone->len
                   && strncmp(query->name, zone->name, zone->len) == 0)
        {
            PR_INFO("Found zone \"%s\" for query \"%s\"",
                    zone->name, query->name);

            return zone;
        }
    }

    PR_INFO("No zone found for query \"%s\"", query->name);

    return NULL;
}


int
zone_add_record(struct dns_zone *zone, int rlen, uint8_t *rname, int region_id,
    uint16_t type, int weight, int ttl, int len, uint8_t *content)
{
    int                     slot;
    struct record          *r;
    struct dns_records     *rs;
    struct region_records  *rrs;

    if (region_id >= MAX_REGION_NUM) {
        return -1;
    }

    slot = bkdr_hash(rname, rlen) % RECORD_HASH_BUCKET_SIZE;

    list_for_each_entry(rs, &zone->records_table[slot], list) {
        if (rs->rlen == rlen && strncmp(rs->rname, rname, rlen) == 0) {
            goto found;
        }
    }

    rs = (struct dns_records *) kmalloc(sizeof(struct dns_records), GFP_KERNEL);
    if (rs == NULL) {
        return -ENOMEM;
    }

    strncpy(rs->rname, rname, rlen);
    rs->rlen = rlen;
    rs->region_count = 0;

    memset(rs->regions, 0, sizeof(struct region_records *) * MAX_REGION_NUM);

    list_add_tail(&rs->list, &zone->records_table[slot]);

found:

    rrs = rs->regions[region_id];
    if (rrs == NULL) {
        rrs = (struct region_records *) kmalloc(sizeof(struct region_records),
                                                GFP_KERNEL);
        rrs->NS_count = 0;
        rrs->TXT_count = 0;
        rrs->CNAME_count = 0;
        rrs->A_count = 0;
        INIT_LIST_HEAD(&rrs->NS_list);
        INIT_LIST_HEAD(&rrs->TXT_list);
        INIT_LIST_HEAD(&rrs->CNAME_list);
        INIT_LIST_HEAD(&rrs->A_list);

        if (rrs == NULL) {
            return -ENOMEM;
        }

        rs->regions[region_id] = rrs;
        rs->region_count++;
    }

    /* the more 2 bytes for encoding domain name */
    r = (struct record *) kmalloc(sizeof(struct record) + len + 2, GFP_KERNEL);
    if (r == NULL) {
        return -ENOMEM;
    }

    r->type = type;
    r->weight = weight;
    r->ttl = ttl;

    switch (type) {
    case TYPE_A:
        if (!list_empty(&rrs->CNAME_list)
            || !list_empty(&rrs->NS_list))
        {
            return -1;
        }

        memcpy(r->content, content, len);
        r->len = len;

        list_add_tail(&r->list, &rrs->A_list);
        rrs->A_count++;
        break;

    case TYPE_CNAME:
        if (!list_empty(&rrs->A_list)
            || !list_empty(&rrs->NS_list))
        {
            return -1;
        }

        r->len = name_encode(r->content, len + 1, content, len);

        list_add_tail(&r->list, &rrs->CNAME_list);
        rrs->CNAME_count++;
        break;

    case TYPE_TXT:
        if (!list_empty(&rrs->CNAME_list)
            || !list_empty(&rrs->NS_list))
        {
            return -1;
        }

        memcpy(r->content, content, len);
        r->len = len;

        list_add_tail(&r->list, &rrs->TXT_list);
        rrs->TXT_count++;
        break;

    case TYPE_NS:
        if (!list_empty(&rrs->CNAME_list)
            || !list_empty(&rrs->A_list)
            || !list_empty(&rrs->TXT_list))
        {
            return -1;
        }

        r->len = name_encode(r->content, len + 1, content, len);

        list_add_tail(&r->list, &rrs->NS_list);
        rrs->NS_count++;
        break;

    default:
        return -1;
    }

    return 0;
}


struct dns_records*
zone_find_records(struct dns_zone *zone, int rlen, uint8_t *rname)
{
    int                  slot;
    struct dns_records  *rs;

    slot = bkdr_hash(rname, rlen) % RECORD_HASH_BUCKET_SIZE;

    list_for_each_entry(rs, &zone->records_table[slot], list) {
        if (rs->rlen == rlen && strncmp(rs->rname, rname, rlen) == 0) {
            return rs;
        }
    }

    return NULL;
}


void
zone_destroy(struct dns_zone *zone)
{
    int                     i, j;
    struct dns_records     *rs, *_rs;
    struct region_records  *rrs;
    struct record          *r, *_r;

    list_del(&zone->list);

    for (i = 0; i < RECORD_HASH_BUCKET_SIZE; i++) {
        list_for_each_entry_safe(rs, _rs, &zone->records_table[i], list) {

            for (j = 0; j < MAX_REGION_NUM; j++) {
                if (rs->regions[j] == NULL) {
                    continue;
                }

                rrs = rs->regions[j];

                if (!list_empty(&rrs->NS_list)) {
                    list_for_each_entry_safe(r, _r, &rrs->NS_list, list) {
                        list_del(&r->list);
                        kfree(r);
                        rrs->NS_count--;
                    }
                }

                BUG_ON(rrs->NS_count != 0);

                if (!list_empty(&rrs->TXT_list)) {
                    list_for_each_entry_safe(r, _r, &rrs->TXT_list, list) {
                        list_del(&r->list);
                        kfree(r);
                        rrs->TXT_count--;
                    }
                }

                BUG_ON(rrs->TXT_count != 0);

                if (!list_empty(&rrs->CNAME_list)) {
                    list_for_each_entry_safe(r, _r, &rrs->CNAME_list, list) {
                        list_del(&r->list);
                        kfree(r);
                        rrs->CNAME_count--;
                    }
                }

                BUG_ON(rrs->CNAME_count != 0);

                if (!list_empty(&rrs->A_list)) {
                    list_for_each_entry_safe(r, _r, &rrs->A_list, list) {
                        list_del(&r->list);
                        kfree(r);
                        rrs->A_count--;
                    }
                }

                BUG_ON(rrs->A_count != 0);
            }

            list_del(&rs->list);
            kfree(rs);
        }
    }

    kfree(zone);
}


void
zones_destroy(void)
{
    struct dns_zone  *zone, *_zone;

    list_for_each_entry_safe(zone, _zone, &dns_zones, list) {
        zone_destroy(zone);
    }
}

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


#ifndef __KNAMED_ZONE_H_INCLUDED__
#define __KNAMED_ZONE_H_INCLUDED__


#include <linux/list.h>
#include "knamed_dns.h"


#define RECORD_HASH_BUCKET_SIZE     256
#define MAX_REGION_NUM              256


struct dns_zone {
    struct list_head   list;
    uint8_t            len;
    uint8_t            name[MAX_DOMAIN_LEN];
    uint8_t            peer_len;
    uint8_t            peer[MAX_LABEL_LEN];
    struct list_head   records_table[RECORD_HASH_BUCKET_SIZE];
};


struct region_records {
    int               NS_count;
    struct list_head  NS_list;
    int               TXT_count;
    struct list_head  TXT_list;
    int               CNAME_count;
    struct list_head  CNAME_list;
    int               A_count;
    struct list_head  A_list;
};


struct dns_records {
    struct list_head        list;
    uint8_t                 rlen;
    uint8_t                 rname[MAX_DOMAIN_LEN];
    int                     region_count;
    struct region_records  *regions[MAX_REGION_NUM];
};


struct record {
    struct list_head  list;
    int               weight;
    int               ttl;
    uint16_t          type;
    uint16_t          len;
    uint8_t           content[0];
};


int name_encode(uint8_t *buf, int blen, uint8_t *str, int slen);
struct dns_zone *zone_create(uint8_t *name, int default_ttl, uint8_t *peer);
struct dns_zone *zone_find(struct dns_query *query);
int zone_add_record(struct dns_zone *zone, int rlen, uint8_t *rname,
    int region_id, uint16_t type, int weight, int ttl, int len,
    uint8_t *content);
struct dns_records *zone_find_records(struct dns_zone *zone, int rlen,
    uint8_t *rname);
void zone_destroy(struct dns_zone *zone);
void zones_destroy(void);


#endif /* __KNAMED_ZONE_H_INCLUDED__ */

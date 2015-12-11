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


#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "knamed.h"
#include "knamed_dns.h"
#include "knamed_iptable.h"
#include "knamed_zone.h"
#include "knamed_util.h"


#define RESP_SET(resp, an, r)               \
    do {                                    \
        (resp)->qr = 1;                     \
        (resp)->aa = 1;                     \
        (resp)->tc = 0;                     \
        (resp)->unused = 0;                 \
        (resp)->rcode = r;                  \
        (resp)->qdcount = htons(1);         \
        (resp)->ancount = htons(an);        \
        (resp)->nscount = 0;                \
        (resp)->arcount = 0;                \
    } while (0)


knamed_iptable_t  *iptable;


struct region_ids {
    int  count;
    int  ids[0];
};


struct region_ids  *g_ids;


static uint8_t  id_server[]      = "id.server.";
static uint8_t  hostname_bind[]  = "hostname.bind.";
static uint8_t  version_server[] = "version.server.";
static uint8_t  version_bind[]   = "version.bind.";


static int check_query(struct dns_query *query, uint8_t *buf);
static int parse_query(struct dns_query *query);
static int process_class_chaos(struct dns_query *query, uint8_t *buf);
static int process_class_in(struct dns_query *query, uint8_t *buf);
static int answer_formerr(struct dns_query *query, uint8_t *buf);
static int answer_notimpl(struct dns_query *query, uint8_t *buf);
static int answer_refused(struct dns_query *query, uint8_t *buf);
static int answer_nxdomain(struct dns_query *query, uint8_t *buf);
static int answer_noerror(struct dns_query *query, uint8_t *buf);
static int answer_peer(struct dns_query *query, uint8_t *buf);
static int answer_A(struct dns_query *query, uint8_t *buf,
    struct dns_records *rs);
static int answer_TXT(struct dns_query *query, uint8_t *buf,
    struct dns_records *rs);
static int answer_NS(struct dns_query *query, uint8_t *buf,
    struct dns_records *rs);
static int answer_CNAME(struct dns_query *query, uint8_t *buf,
    struct dns_records *rs);

static int fill_rr_raw(uint8_t *buf, int offset, uint16_t qtype,
    uint16_t qclass, uint32_t ttl,  uint16_t len, uint8_t *raw);
static int fill_rr_str(uint8_t *buf, int offset, uint16_t qtype,
    uint16_t qclass, uint32_t ttl, uint16_t len, uint8_t *content);


static int
process_class_chaos(struct dns_query *query, uint8_t *buf)
{
    uint8_t        *p = buf;
    struct dnshdr  *resp;

    if (query->qtype != TYPE_TXT && query->qtype != TYPE_ANY) {
        PR_INFO("CHAOS type %d not implemented", query->qtype);
        return answer_notimpl(query, buf);
    }

    if ((query->len == sizeof(id_server) - 1
         && memcmp(query->name, id_server, query->len) == 0)
        || (query->len == sizeof(hostname_bind) - 1
            && memcmp(query->name, hostname_bind, query->len) == 0))
    {
        memcpy(p, query->packet, sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p += sizeof(struct dnshdr) + query->qlen + 2 + 2;

        p += fill_rr_str(p, sizeof(struct dnshdr), TYPE_TXT, CLASS_CHAOS,
                         sysctl_knamed_default_ttl, 8, "flygoast");

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, 1, RCODE_NOERROR);

        return p - buf;
    }

    if ((query->len == sizeof(version_server) - 1
         && memcmp(query->name, version_server, query->len) == 0)
        || (query->len == sizeof(version_bind) - 1
            && memcmp(query->name, version_bind, query->len) == 0))
    {
        if (sysctl_knamed_hide_version) {
            return answer_refused(query, buf);
        }

        memcpy(p, query->packet, sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p += sizeof(struct dnshdr) + query->qlen + 2 + 2;

        p += fill_rr_str(p, sizeof(struct dnshdr), TYPE_TXT, CLASS_CHAOS,
                         sysctl_knamed_default_ttl,
                         strlen(KNAMED_TOKEN),
                         KNAMED_TOKEN);

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, 1, RCODE_NOERROR);

        return p - buf;
    }

    return answer_notimpl(query, buf);
}


static int
fill_rr_raw(uint8_t *buf, int offset, uint16_t qtype, uint16_t qclass,
    uint32_t ttl, uint16_t len, uint8_t *content)
{
    uint8_t  *p = buf;

    *((uint16_t *) p) = htons(0xc000 | offset); /* compression label */
    p += 2;
    *((uint16_t *) p) = htons(qtype);
    p += 2;
    *((uint16_t *) p) = htons(qclass);
    p += 2;
    *((uint32_t *) p) = htonl(ttl);
    p += 4;
    *((uint16_t *) p) = htons(len);
    p += 2;

    memcpy(p, content, len);
    p += len;

    return p - buf;
}


static int
fill_rr_str(uint8_t *buf, int offset, uint16_t qtype, uint16_t qclass,
    uint32_t ttl, uint16_t len, uint8_t *content)
{
    uint8_t  *p = buf;

    *((uint16_t *) p) = htons(0xc000 | offset); /* compression label */
    p += 2;
    *((uint16_t *) p) = htons(qtype);
    p += 2;
    *((uint16_t *) p) = htons(qclass);
    p += 2;
    *((uint32_t *) p) = htonl(ttl);
    p += 4;
    *((uint16_t *) p) = htons(len + 1);
    p += 2;

    *p++ = (uint8_t) len;

    memcpy(p, content, len);
    p += len;

    return p - buf;
}


static int
process_class_in(struct dns_query *query, uint8_t *buf)
{
    struct dns_zone     *zone;
    uint8_t              qlen;
    struct dns_records  *rs;

    zone = zone_find(query);
    if (zone == NULL) {
        return answer_refused(query, buf);
    }

    /* qlen contained '.' at the label end */
    qlen = query->len - zone->len;

    if (qlen > 0) {
        /* used to got the IP of Local DNS */
        if (zone->peer_len != 0
            && query->qtype == TYPE_A
            && qlen - 1 == zone->peer_len
            && strncmp(query->name, zone->peer, qlen - 1) == 0)
        {
            return answer_peer(query, buf);
        }

        rs = zone_find_records(zone, qlen - 1, query->name);
        if (rs == NULL) {
            return answer_nxdomain(query, buf);
        }

        switch (query->qtype) {
        case TYPE_A:
            return answer_A(query, buf, rs);

        case TYPE_CNAME:
            return answer_CNAME(query, buf, rs);

        case TYPE_TXT:
            return answer_TXT(query, buf, rs);

        case TYPE_NS:
            return answer_NS(query, buf, rs);

        default:
            return answer_notimpl(query, buf);
        }

    } else if (qlen == 0) {
        rs = zone_find_records(zone, 1, (uint8_t *) "@");
        if (rs == NULL) {
            return answer_nxdomain(query, buf);
        }

        switch (query->qtype) {
        case TYPE_A:
            return answer_A(query, buf, rs);

        case TYPE_CNAME:
            return answer_CNAME(query, buf, rs);

        case TYPE_TXT:
            return answer_TXT(query, buf, rs);

        case TYPE_NS:
            return answer_NS(query, buf, rs);

        default:
            return answer_notimpl(query, buf);
        }
    }

    return -1;
}


static int
parse_query(struct dns_query *query)
{
    int       len, datalen, pos, dnslen;
    uint8_t  *buf, *p;

    dnslen = query->plen;

    buf = query->packet + sizeof(struct dnshdr);
    p = &query->name[0];
    pos = 0;

    datalen = dnslen - sizeof(struct dnshdr);

    while (1) {
        len = buf[pos];
        if (len & 0xc0) {
            PR_ERR("Lable compression detected in query");
            return -1;
        }

        if (len > MAX_LABEL_LEN) {
            PR_ERR("Lable too long in query");
            return -1;
        }

        pos++;

        if (len == 0) {
            *p++ = '\0';
            break;
        }

        if (pos + len >= datalen) {
            PR_ERR("Query name truncated");
            return -1;
        }

        if (pos + len > MAX_DOMAIN_LEN) {
            PR_ERR("Query domain name too long");
            return -1;
        }

        while (len--) {
            if (buf[pos] > 0x40 && buf[pos] < 0x5B) {
                *p++ = buf[pos] | 0x20;
            } else {
                *p++ = buf[pos];
            }

            pos++;
        }

        *p++ = '.';
    }

    /* length of the lowercased name */
    query->len = (uint8_t) (p - query->name - 1);
    query->qlen = (uint8_t) pos;

    if (pos + 4 > datalen) {
        PR_ERR("Length exhausted before parsing query type/class");
        return -1;

    } else {
        query->qtype = ntohs(*(uint16_t *) &buf[pos]);
        pos += 2;
        query->qclass = ntohs(*(uint16_t *) &buf[pos]);
        pos += 2;
    }

    return 0;
}


static int
answer_formerr(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr  *resp;

    memcpy(buf, query->packet, sizeof(struct dnshdr));

    resp = (struct dnshdr *) buf;
    resp->qr = 1;
    resp->aa = 0;
    resp->tc = 0;
    resp->unused = 0;
    resp->rcode = RCODE_FORMERR;

    resp->qdcount = 0;
    resp->ancount = 0;
    resp->nscount = 0;
    resp->arcount = 0;

    return sizeof(struct dnshdr);
}


static int
answer_notimpl(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr  *resp;

    memcpy(buf, query->packet, query->plen);

    resp = (struct dnshdr *) buf;
    resp->qr = 1;
    resp->aa = 0;
    resp->tc = 0;
    resp->unused = 0;
    resp->rcode = RCODE_NOTIMP;

    return query->plen;
}


static int
answer_refused(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr  *resp;

    memcpy(buf, query->packet, query->plen);

    resp = (struct dnshdr *) buf;
    resp->qr = 1;
    resp->aa = 0;
    resp->tc = 0;
    resp->unused = 0;
    resp->rcode = RCODE_REFUSED;

    return query->plen;
}


static int
answer_nxdomain(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr  *resp;

    memcpy(buf, query->packet, query->plen);

    resp = (struct dnshdr *) buf;
    resp->qr = 1;
    resp->aa = 1;
    resp->tc = 0;
    resp->unused = 0;
    resp->rcode = RCODE_NXDOMAIN;

    return query->plen;
}


static int
answer_noerror(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr  *resp;

    memcpy(buf, query->packet, query->plen);

    resp = (struct dnshdr *) buf;
    resp->qr = 1;
    resp->aa = 1;
    resp->tc = 0;
    resp->unused = 0;
    resp->rcode = RCODE_NOERROR;

    return query->plen;
}


static int
answer_peer(struct dns_query *query, uint8_t *buf)
{
    uint32_t        address;
    struct tm       tm;
    uint8_t        *p;
    struct dnshdr  *resp;

    get_local_time(&tm);

    address = htonl(((tm.tm_mon + 1) << 24)
                    + (tm.tm_mday << 16)
                    + (tm.tm_hour << 8)
                    + tm.tm_min);

    memcpy(buf, query->packet,
           sizeof(struct dnshdr) + query->qlen + 2 + 2);
    p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

    p += fill_rr_raw(p, sizeof(struct dnshdr),
                     TYPE_A, CLASS_IN,
                     (uint32_t) 0, 4,
                     (uint8_t *) &query->saddr);

    p += fill_rr_raw(p, sizeof(struct dnshdr),
                     TYPE_A, CLASS_IN,
                     (uint32_t) 0, 4,
                     (uint8_t *) &address);

    resp = (struct dnshdr *) buf;
    RESP_SET(resp, 2, RCODE_NOERROR);

    return p - buf;
}


static int
answer_CNAME(struct dns_query *query, uint8_t *buf, struct dns_records *rs)
{
    knamed_iptable_slot_t  *slot;
    struct region_records  *rrs;
    struct record          *r;
    int                     i, rid, len;
    uint8_t                *p;
    struct dnshdr          *resp;
    struct region_ids      *ids;

    if ((slot = knamed_iptable_find(iptable, query->saddr)) == NULL) {
        rrs = rs->regions[0];

        if (list_empty(&rrs->CNAME_list)) {
            return answer_nxdomain(query, buf);
        }

        r = list_first_entry(&rrs->CNAME_list, struct record, list);

        len = 2 + 2 + 2 + 4 + 2 + r->len + 1;
        if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
            return answer_noerror(query, buf);
        }

        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        p += fill_rr_raw(p, sizeof(struct dnshdr),
                         TYPE_CNAME, CLASS_IN,
                         (uint32_t) (r->ttl ? r->ttl:
                                              sysctl_knamed_default_ttl),
                         r->len, r->content);

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, 1, RCODE_NOERROR);
        return p - buf;
    }

    ids = (struct region_ids *) slot->value;

    for (i = 0; i < ids->count; i++) {
        rid = ids->ids[i];
        rrs = rs->regions[rid];
        if (rrs == NULL) {
            continue;
        }

        if (list_empty(&rrs->CNAME_list)) {
            continue;
        }

        r = list_first_entry(&rrs->CNAME_list, struct record, list);

        len = 2 + 2 + 2 + 4 + 2 + r->len + 1;
        if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
            return answer_noerror(query, buf);
        }

        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        p += fill_rr_raw(p, sizeof(struct dnshdr),
                         TYPE_CNAME, CLASS_IN,
                         (uint32_t) (r->ttl ? r->ttl:
                                              sysctl_knamed_default_ttl),
                         r->len, r->content);

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, 1, RCODE_NOERROR);

        return p - buf;
    }

    return answer_nxdomain(query, buf);
}


static int
answer_A(struct dns_query *query, uint8_t *buf, struct dns_records *rs)
{
    knamed_iptable_slot_t  *slot;
    struct region_records  *rrs;
    struct record          *r;
    int                     i, rid, len, ancount;
    uint8_t                *p;
    struct dnshdr          *resp;
    struct region_ids      *ids;

    if ((slot = knamed_iptable_find(iptable, query->saddr)) == NULL) {
        rrs = rs->regions[0];

        if (list_empty(&rrs->CNAME_list) && list_empty(&rrs->A_list)) {
            return answer_nxdomain(query, buf);
        }

        if (!list_empty(&rrs->CNAME_list)) {
            r = list_first_entry(&rrs->CNAME_list, struct record, list);

            len = 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                return answer_noerror(query, buf);
            }

            memcpy(buf, query->packet,
                   sizeof(struct dnshdr) + query->qlen + 2 + 2);
            p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_CNAME, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);

            resp = (struct dnshdr *) buf;
            RESP_SET(resp, 1, RCODE_NOERROR);

            return p - buf;
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->A_list, list) {
            len += 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_A, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    ids = (struct region_ids *) slot->value;

    for (i = 0; i < ids->count; i++) {
        rid = ids->ids[i];
        rrs = rs->regions[rid];
        if (rrs == NULL) {
            continue;
        }

        if (list_empty(&rrs->CNAME_list) && list_empty(&rrs->A_list)) {
            continue;
        }

        if (!list_empty(&rrs->CNAME_list)) {
            r = list_first_entry(&rrs->CNAME_list, struct record, list);

            len = 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                return answer_noerror(query, buf);
            }

            memcpy(buf, query->packet,
                   sizeof(struct dnshdr) + query->qlen + 2 + 2);
            p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_CNAME, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);

            resp = (struct dnshdr *) buf;
            RESP_SET(resp, 1, RCODE_NOERROR);

            return p - buf;
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->A_list, list) {
            len += 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_A, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    return answer_nxdomain(query, buf);
}


static int
answer_TXT(struct dns_query *query, uint8_t *buf, struct dns_records *rs)
{
    knamed_iptable_slot_t  *slot;
    struct region_records  *rrs;
    struct record          *r;
    int                     i, rid, len, ancount;
    uint8_t                *p;
    struct dnshdr          *resp;
    struct region_ids      *ids;

    if ((slot = knamed_iptable_find(iptable, query->saddr)) == NULL) {
        rrs = rs->regions[0];

        if (list_empty(&rrs->TXT_list)) {
            return answer_nxdomain(query, buf);
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->TXT_list, list) {
            len += 2 + 2 + 2 + 4 + 2 + r->len + 1;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_str(p, sizeof(struct dnshdr),
                             TYPE_TXT, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    ids = (struct region_ids *) slot->value;

    for (i = 0; i < ids->count; i++) {
        rid = ids->ids[i];
        rrs = rs->regions[rid];
        if (rrs == NULL) {
            continue;
        }

        if (list_empty(&rrs->TXT_list)) {
            continue;
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->TXT_list, list) {
            len += 2 + 2 + 2 + 4 + 2 + r->len + 1;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_str(p, sizeof(struct dnshdr),
                             TYPE_TXT, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    return answer_nxdomain(query, buf);
}


static int
answer_NS(struct dns_query *query, uint8_t *buf, struct dns_records *rs)
{
    knamed_iptable_slot_t  *slot;
    struct region_records  *rrs;
    struct record          *r;
    int                     i, rid, len, ancount;
    uint8_t                *p;
    struct dnshdr          *resp;
    struct region_ids      *ids;

    if ((slot = knamed_iptable_find(iptable, query->saddr)) == NULL) {
        rrs = rs->regions[0];

        if (list_empty(&rrs->NS_list)) {
            return answer_nxdomain(query, buf);
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->NS_list, list) {
            PR_INFO("NS: %d, %d", len, r->len);
            len += 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_NS, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    ids = (struct region_ids *) slot->value;

    for (i = 0; i < ids->count; i++) {
        rid = ids->ids[i];
        rrs = rs->regions[rid];
        if (rrs == NULL) {
            continue;
        }

        if (list_empty(&rrs->NS_list)) {
            continue;
        }

        len = 0;
        ancount = 0;
        memcpy(buf, query->packet,
               sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

        list_for_each_entry(r, &rrs->NS_list, list) {
            len += 2 + 2 + 2 + 4 + 2 + r->len;
            if (len >= MAX_DNS_PACKET_LEN - sizeof(struct dnshdr)) {
                break;
            }

            ancount++;
            p += fill_rr_raw(p, sizeof(struct dnshdr),
                             TYPE_NS, CLASS_IN,
                             (uint32_t) (r->ttl ? r->ttl:
                                                  sysctl_knamed_default_ttl),
                             r->len, r->content);
        }

        resp = (struct dnshdr *) buf;
        RESP_SET(resp, ancount, RCODE_NOERROR);

        return p - buf;
    }

    return answer_nxdomain(query, buf);
}



static int
check_query(struct dns_query *query, uint8_t *buf)
{
    struct dnshdr *dnsh = (struct dnshdr *) query->packet;

    if (dnsh->qr || dnsh->tc) {
        return answer_formerr(query, buf);
    }

    if (dnsh->opcode != OPCODE_QUERY) {
        return answer_notimpl(query, buf);
    }

    if (ntohs(dnsh->qdcount) != 1
        || ntohs(dnsh->ancount) != 0
        || ntohs(dnsh->nscount) != 0
        || ntohs(dnsh->arcount) != 0)
    {
        return answer_formerr(query, buf);
    }

    return 0;
}


int
process_query(struct iphdr *iph, struct udphdr *udph, struct dnshdr *dnsh,
    int dnslen, uint8_t *buf)
{
    int                ret;
    struct dns_query   query;

    query.saddr = iph->saddr;
    query.sport = udph->source;

    query.packet = (uint8_t *) dnsh;
    query.plen = dnslen;
    query.id = *(uint16_t *) dnsh;

    if ((ret = check_query(&query, buf)) != 0) {
        return ret;
    }

    if (parse_query(&query) < 0) {
        return answer_formerr(&query, buf);
    }

    switch (query.qclass) {
    case CLASS_IN:
        return process_class_in(&query, buf);

    case CLASS_CHAOS:
        return process_class_chaos(&query, buf);

    default:
        PR_ERR("Class %d not implemented", query.qclass);
        return answer_notimpl(&query, buf);
    }

    return -1;
}


int
dns_init(void)
{
    struct dns_zone  *zone;
    uint32_t          address;

    if ((zone = zone_create("example.com.", 60, "peer")) == NULL) {
        return -ENOMEM;
    }

    address = 0x12345678;
    if (zone_add_record(zone, 3, "www", 0, TYPE_A, 50, 300, 4,
                        (uint8_t *) &address) < 0)
    {
        goto error;
    }

    address = 0x78563412;
    if (zone_add_record(zone, 3, "www", 0, TYPE_A, 50, 300, 4,
                        (uint8_t *) &address) < 0)
    {
        goto error;
    }

    if (zone_add_record(zone, 3, "foo", 0, TYPE_CNAME, 50, 300,
                       12, (uint8_t *) "foo.fuck.com") < 0)
    {
        goto error;
    }

    address = 0x11112222;
    if (zone_add_record(zone, 1, "@", 0, TYPE_A, 50, 300,
                       4, (uint8_t *) &address) < 0)
    {
        goto error;
    }

    if (zone_add_record(zone, 1, "@", 0, TYPE_TXT, 50, 300,
                       4, (uint8_t *) "test") < 0)
    {
        goto error;
    }

    if (zone_add_record(zone, 1, "@", 0, TYPE_TXT, 50, 300,
                       5, (uint8_t *) "hello") < 0)
    {
        goto error;
    }

    if (zone_add_record(zone, 5, "hello", 0, TYPE_NS, 50, 300,
                        15, (uint8_t *) "ns1.example.com") < 0)
    {
        PR_ERR("ADDED failed");
        goto error;
    }

    iptable = knamed_iptable_create();
    if (iptable == NULL) {
        goto error;
    }

    g_ids = kmalloc(sizeof(struct region_ids) + sizeof(int) * 3, GFP_KERNEL);
    if (g_ids == NULL) {
        goto error;
    }

    g_ids->count = 3;
    g_ids->ids[0] = 3;
    g_ids->ids[1] = 5;
    g_ids->ids[2] = 0;

    if (knamed_iptable_add(iptable, 0x0a050000, 16, g_ids) != 0) {
        goto error;
    }

    knamed_iptable_dump(iptable);

    return 0;

error:

    if (iptable) {
        knamed_iptable_destroy(iptable, NULL);
    }

    zones_destroy();
    return -1;
}


void
dns_cleanup(void)
{
    kfree(g_ids);
    zones_destroy();
    knamed_iptable_destroy(iptable, NULL);
}

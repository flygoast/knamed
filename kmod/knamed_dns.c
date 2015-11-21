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
#include "knamed_acl.h"
#include "knamed_util.h"


#define MAX_LABEL_LEN       63
#define MAX_DOMAIN_LEN      255


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


LIST_HEAD(dns_zones);
struct acl_table  *acl_tbl;


struct dns_zone {
    struct list_head    list;
    uint8_t             len;
    uint8_t             name[MAX_DOMAIN_LEN];
    uint8_t             peer_len;
    uint8_t             peer[MAX_LABEL_LEN];
    struct hlist_head  *records_table;
};


struct dns_query {
    uint16_t   id;
    uint16_t   qtype;
    uint16_t   qclass;
    uint16_t   sport;
    uint32_t   saddr;
    uint8_t    len;                     /* length of FQDN, "www.example.com." */
    uint8_t    name[MAX_DOMAIN_LEN];    /* buffer for FQDN */
    uint8_t    qlen;                    /* length of domain name in packet */
    int        plen;                    /* length of the packet */
    uint8_t   *packet;
};


static uint8_t  id_server[]      = "id.server.";
static uint8_t  hostname_bind[]  = "hostname.bind.";
static uint8_t  version_server[] = "version.server.";
static uint8_t  version_bind[]   = "version.bind.";


static struct dns_zone *find_zone(struct dns_query *query);
static int check_query(struct dns_query *query, uint8_t *buf);
static int parse_query(struct dns_query *query);
static int process_class_chaos(struct dns_query *query, uint8_t *buf);
static int process_class_in(struct dns_query *query, uint8_t *buf);
static int answer_formerr(struct dns_query *query, uint8_t *buf);
static int answer_notimpl(struct dns_query *query, uint8_t *buf);
static int answer_refused(struct dns_query *query, uint8_t *buf);
static int answer_peer(struct dns_query *query, uint8_t *buf);
static int fill_rr_raw(uint8_t *buf, int offset, uint16_t qtype,
    uint16_t qclass, uint32_t ttl,  uint16_t len, uint8_t *raw);
static int fill_rr_str(uint8_t *buf, int offset, uint16_t qtype,
    uint16_t qclass, uint32_t ttl, uint16_t len, uint8_t *content);
static int label_encode(uint8_t *buf, uint8_t *str);


static int
label_encode(uint8_t *buf, uint8_t *str)
{
    uint8_t  *p, *q, c;

    if (*str == '.' || *str == '\0') {
        return -1;
    }

    q = buf;
    p = buf + 1;

    while (1) {
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
    uint8_t          *p;
    struct dnshdr    *resp;
    struct dns_zone  *zone;
    uint8_t           qlen;
    uint32_t          address;

    //////////////////
    uint8_t            temp[128];
    int                len;

    zone = find_zone(query);
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

        switch (query->qtype) {
        case TYPE_A:
            break;

        case TYPE_CNAME:
            break;

        case TYPE_TXT:
            break;
        }

        /* TODO */

    } else if (qlen == 0) {
        /* TODO */
    }

    memcpy(buf, query->packet, sizeof(struct dnshdr) + query->qlen + 2 + 2);
    p = buf + sizeof(struct dnshdr) + query->qlen + 2 + 2;

    len = label_encode(temp, "foo.fuck.com");

    p += fill_rr_raw(p, sizeof(struct dnshdr), TYPE_CNAME, CLASS_IN,
                     (uint32_t) sysctl_knamed_default_ttl, len,
                     (uint8_t *) temp);

    address = htonl(0x7f000002);
    p += fill_rr_raw(p, p - buf - len,
                     TYPE_A, CLASS_IN,
                     (uint32_t) sysctl_knamed_default_ttl, 4,
                     (uint8_t *) &address);

    resp = (struct dnshdr *) buf;
    RESP_SET(resp, 2, RCODE_NOERROR);

    return p - buf;
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


static struct dns_zone *
find_zone(struct dns_query *query)
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


static void
dump_zones(void)
{
    struct dns_zone  *zone;

    list_for_each_entry(zone, &dns_zones, list) {
        PR_INFO("ZONE: %s", zone->name);
    }
}


int
dns_init(void)
{
    struct dns_zone  *zone;

    zone = (struct dns_zone *) kmalloc(sizeof(struct dns_zone), GFP_KERNEL);
    if (zone == NULL) {
        return -ENOMEM;
    }

    memset(zone, 0, sizeof(struct dns_zone));

    strcpy(zone->name, "example.com.");
    zone->len = strlen("example.com.");

    strcpy(zone->peer, "peer");
    zone->peer_len = strlen("peer");

    list_add(&zone->list, &dns_zones);

    dump_zones();

    acl_tbl = acl_create();
    if (acl_tbl == NULL) {
        return -ENOMEM;
    }

    if (acl_add(acl_tbl, 0x0a050000, 16, "abc") != 0) {
        return -1;
    }

    acl_dump(acl_tbl);

    return 0;
}


void
dns_cleanup(void)
{
    struct dns_zone  *zone, *n;

    list_for_each_entry_safe(zone, n, &dns_zones, list) {
        list_del(&zone->list);
        kfree(zone);
    }

    acl_destroy(acl_tbl, NULL);
}

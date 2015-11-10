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


#define MAX_LABEL_LEN       63
#define MAX_DOMAIN_LEN      255

#define MAX_RDATA_LEN       64
#define MAX_RD_LENGTH       65535


LIST_HEAD(dns_zones);


struct dns_zone {
    struct list_head    list;
    uint8_t             len;
    uint8_t             name[MAX_DOMAIN_LEN];
    struct hlist_head  *records_table;
};


struct dns_query {
    uint16_t   id;
    uint16_t   qtype;
    uint16_t   qclass;
    uint8_t    len;                     /* length of FQDN, "www.example.com" */
    uint8_t    name[MAX_DOMAIN_LEN];    /* buffer for FQDN */
    uint8_t    qlen;                    /* length of domain name in packet */
    uint8_t    offset;                  /* offset of domain name in packet */
    int        plen;                    /* length of the packet */
    uint8_t   *packet;
};


static uint8_t  A_record[] = {
    0xc0, 0x0c,                         /* name */
    0x00, 0x01,                         /* type */
    0x00, 0x01,                         /* class */
    0x00, 0x00, 0x02, 0x58,             /* ttl */
    0x00, 0x04,                         /* length */
    0x6a, 0x78, 0xa7, 0x42              /* data */
};


static uint8_t  id_server[] = "id.server.";
static uint8_t  hostname_bind[] = "hostname.bind.";
static uint8_t  version_server[] = "version.server.";
static uint8_t  version_bind[] = "version.bind.";


static int parse_query(struct dns_query *query);
static int process_class_chaos(struct dns_query *query, uint8_t *buf);
static int process_class_in(struct dns_query *query, uint8_t *buf);
static struct dns_zone *find_zone(struct dns_query *query);
static int answer_formerr(struct dns_query *query, uint8_t *buf);
static int answer_notimpl(struct dns_query *query, uint8_t *buf);
static int answer_refused(struct dns_query *query, uint8_t *buf);
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
                         sysctl_knamed_ttl, 8, "flygoast");

        resp = (struct dnshdr *) buf;
        resp->qr = 1;
        resp->aa = 0;
        resp->tc = 0;
        resp->unused = 0;
        resp->rcode = RCODE_NOERROR;

        resp->qdcount = htons(1);
        resp->ancount = htons(1);
        resp->nscount = 0;
        resp->arcount = 0;

        return p - buf;
    }

    if ((query->len == sizeof(version_server) - 1
         && memcmp(query->name, version_server, query->len) == 0)
        || (query->len == sizeof(version_bind) - 1
            && memcmp(query->name, version_bind, query->len) == 0))
    {
        memcpy(p, query->packet, sizeof(struct dnshdr) + query->qlen + 2 + 2);
        p += sizeof(struct dnshdr) + query->qlen + 2 + 2;

        p += fill_rr_str(p, sizeof(struct dnshdr), TYPE_TXT, CLASS_CHAOS,
                         sysctl_knamed_ttl, 10, "knamed/0.1");

        resp = (struct dnshdr *) buf;
        resp->qr = 1;
        resp->aa = 0;
        resp->tc = 0;
        resp->unused = 0;
        resp->rcode = RCODE_NOERROR;

        resp->qdcount = htons(1);
        resp->ancount = htons(1);
        resp->nscount = 0;
        resp->arcount = 0;

        return p - buf;
    }

    PR_INFO("Only query version.bind of CHAOS TXT implemented");
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
    int               len;
    uint8_t          *p;
    struct dnshdr    *ndnsh;
    struct dns_zone  *zone;
    uint8_t           qlen;

    zone = find_zone(query);
    if (zone == NULL) {
        return -1;
    }

    qlen = query->len - zone->len;

    /*
    if (qlen > 0) {

    } else if (qlen == 0) {

    }
    */

    len = 12;

    memcpy(buf + 12, query->packet + query->offset, query->qlen);

    len += query->qlen;
    buf[len++] = 0;
    buf[len++] = 1;
    buf[len++] = 0;
    buf[len++] = 1;
    p = buf + len;

    len += sizeof(A_record);
    memcpy(p, A_record, sizeof(A_record));

    ndnsh = (struct dnshdr *) buf;
    ndnsh->id = query->id;

    *((uint8_t *) ndnsh + 2) = 0x81;
    *((uint8_t *) ndnsh + 3) = 0x80;
    *((uint8_t *) ndnsh + 4) = 0;
    *((uint8_t *) ndnsh + 5) = 1;
    *((uint8_t *) ndnsh + 6) = 0;
    *((uint8_t *) ndnsh + 7) = 1;
    *((uint8_t *) ndnsh + 8) = 0;
    *((uint8_t *) ndnsh + 9) = 0;
    *((uint8_t *) ndnsh + 10) = 0;
    *((uint8_t *) ndnsh + 11) = 0;

    return len;
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

    query->offset = sizeof(struct dnshdr);

    while (1) {
        len = buf[pos];
        if (len & 0xc0) {
            PR_ERR("Lable compression detected in query");
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
            /* upper letter */
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

    memcpy(buf, query->packet, sizeof(struct dns_query));

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



int
process_query(struct dnshdr *dnsh, int dnslen, uint8_t *buf)
{
    struct dns_query  query;

    query.packet = (uint8_t *) dnsh;
    query.plen = dnslen;
    query.id = *(uint16_t *) dnsh;

    if (dnsh->opcode != OPCODE_QUERY) {
        PR_INFO("Only standard query supported");
        return answer_notimpl(&query, buf);
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

    list_add(&zone->list, &dns_zones);

    dump_zones();

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
}

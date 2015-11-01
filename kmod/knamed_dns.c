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
#include "knamed.h"
#include "knamed_dns.h"


static uint8_t  A_record[] = {
    0xc0, 0x0c,                         /* name */
    0x00, 0x01,                         /* type */
    0x00, 0x01,                         /* class */
    0x00, 0x00, 0x02, 0x58,             /* ttl */
    0x00, 0x04,                         /* length */
    0x6a, 0x78, 0xa7, 0x42              /* data */
};


/*
 * support version.bind:
 *  dig @127.0.0.1 version.bind TXT CHAOS
 */
static uint8_t  version_bind_response[] = {
    0x00, 0x00,         /* QUERY ID, should be replaced */
    0x85, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,

    0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00,
    0x00, 0x10,
    0x00, 0x03,

    0xc0, 0x0c,
    0x00, 0x10,
    0x00, 0x03,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x09,
    0x08,
    'k', 'n', 'a', 'm', 'e', 'd', '/', '1',

    0xc0, 0x0c,
    0x00, 0x02,
    0x00, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0, 0x0c,
};


static uint8_t  *version_bind_qname = (uint8_t *) version_bind_response
                                      + sizeof(struct dnshdr);
static int  version_bind_length = 14;


struct dns_query {
    uint16_t   id;
    uint8_t    qname[256];
    uint8_t    len;
    uint16_t   qtype;
    uint16_t   qclass;
};


static int parse_dns_query(struct dns_query *query, struct dnshdr *dnsh,
    int dnslen);
static int process_class_chaos(struct dns_query *query, uint8_t *buf);



static int
process_class_chaos(struct dns_query *query, uint8_t *buf)
{
    if (query->qtype != TYPE_TXT) {
        PR_INFO("Only query version.bind of CHAOS TXT implemented");
        return -1;
    }

    if (query->len == version_bind_length
        && memcmp(query->qname, version_bind_qname, query->len) == 0)
    {

        *(uint16_t *) buf = query->id;
        memcpy(buf + 2, version_bind_response + 2,
               sizeof(version_bind_response) - 2);
        return sizeof(version_bind_response);
    }

    PR_INFO("Only query version.bind of CHAOS TXT implemented");
    return -1;
}


static int
process_class_in(struct dns_query *query, uint8_t *buf)
{
    int             len;
    uint8_t        *p;
    struct dnshdr  *ndnsh;

    len = 12;

    memcpy(buf + 12, query->qname, query->len);

    len += query->len;
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
parse_dns_query(struct dns_query *query, struct dnshdr *dnsh, int dnslen)
{
    int       len, datalen, pos;
    uint8_t  *buf, *p;

    query->id = *(uint16_t *) dnsh;

    buf = (uint8_t *) dnsh + sizeof(struct dnshdr);
    p = &query->qname[0];
    pos = 0;

    datalen = dnslen - sizeof(struct dnshdr);

    while ((len = buf[pos]) != 0) {
        *p++ = len;
        pos++;

        if (len & 0xc0) {
            PR_ERR("Lable compression detected in query, dropped");
            return -1;
        }

        if (pos + len >= datalen) {
            PR_ERR("Query name truncated, dropped");
            return -1;
        }

        if (pos + len > 254) {
            PR_ERR("Query domain name too long, dropped");
            return -1;
        }

        /* copy qname */
        while (len--) {
            /* upper letter */
            if (buf[pos] > 0x40 && buf[pos] < 0x5B) {
                *p++ = buf[pos++] | 0x20;
            } else {
                *p++ = buf[pos++];
            }
        }
    }

    *p++ = 0;
    pos++;

    /* length of the lowercased name */
    query->len = (uint8_t) pos;

    if (pos + 4 > datalen) {
        PR_ERR("Length exhausted before parsing query type/class, dropped");
        return -1;
    } else {
        query->qtype = ntohs(*(uint16_t *) &buf[pos]);
        pos += 2;
        query->qclass = ntohs(*(uint16_t *) &buf[pos]);
        pos += 2;
    }

    return 0;
}


int
process_dns_query(struct dnshdr *dnsh, int dnslen, uint8_t *buf)
{
    struct dns_query  query;

    if (dnsh->opcode != OPCODE_QUERY) {
        PR_ERR("Only standard query supported, dropped");
        return -1;
    }

    if (parse_dns_query(&query, dnsh, dnslen) < 0) {
        return -1;
    }

    switch (query.qclass) {
    case CLASS_IN:
        return process_class_in(&query, buf);
    case CLASS_CHAOS:
        return process_class_chaos(&query, buf);
    default:
        PR_ERR("Class not implemented: %d, dropped", query.qclass);
        return -1;
    }

    return -1;
}

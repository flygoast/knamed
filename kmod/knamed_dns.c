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


static unsigned char  A_record[] = {
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
 *
 * Hard-coded response packet to the "version.bind" query
 */
static unsigned char  version_bind_response[] = {
    0x87, 0x31,         /* QUERY ID */
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


int process_dns_query(struct dnshdr *dnsh, int dnslen, unsigned char *buf)
{
    int              len, pos, llen;
    struct dnshdr   *ndnsh;
    unsigned char   *p;
    unsigned char    lqname[256];
    uint16_t         qtype, qclass;
    unsigned char   *oldbuf = (unsigned char *) dnsh + sizeof(struct dnshdr);

    pos = 0;
    p = lqname + 1;

    if (dnsh->opcode != OPCODE_QUERY) {
        PR_ERR("Only standard query supported, dropped");
        return -1;
    }

    while ((llen = oldbuf[pos]) != 0) {
        *p++ = llen;
        pos++;

        if (llen & 0xc0) {
            PR_ERR("Lable compression detected in query, dropped");
            return -1;
        }

        if (pos + llen >= dnslen - sizeof(struct dnshdr)) {
            PR_ERR("Query name truncated, dropped");
            return -1;
        }

        if (pos + llen > 254) {
            PR_ERR("Query domain name too long, dropped");
            return -1;
        }

        /* copy lqname */
        while (llen--) {
            if (oldbuf[pos] > 0x40 && oldbuf[pos] < 0x5B) {
                *p++ = oldbuf[pos++] | 0x20;
            } else {
                *p++ = oldbuf[pos++];
            }
        }
    }

    *p++ = 0;
    pos++;

    /* store the total length of the lowercased name */
    *lqname = pos;

    if (pos + 4 > dnslen - sizeof(struct dnshdr)) {
        PR_ERR("Packet length exhausted before parsing query type/class"
               ", dropped");
        return -1;
    } else {
        qtype = ntohs(*(uint16_t *) &oldbuf[pos]);
        pos += 2;
        qclass = ntohs(*(uint16_t *) &oldbuf[pos]);
        pos += 2;
    }

    if (qtype != TYPE_A && qtype != TYPE_CNAME) {
        PR_ERR("Type not implemented: %d, dropped", qtype);
        return -1;
    }

    if (qclass != CLASS_IN && qclass != CLASS_CHAOS) {
        PR_ERR("Class not implemented: %d, dropped", qclass);
        return -1;
    }

    len = 12;

    memcpy(buf + 12, lqname + 1, *lqname);

    len += *lqname;
    buf[len++] = 0;
    buf[len++] = 1;
    buf[len++] = 0;
    buf[len++] = 1;
    p = buf + len;


    len += sizeof(A_record);
    memcpy(p, A_record, sizeof(A_record));

    ndnsh = (struct dnshdr *) buf;
    ndnsh->id = dnsh->id;

    *((unsigned char *) ndnsh + 2) = 0x81;
    *((unsigned char *) ndnsh + 3) = 0x80;
    *((unsigned char *) ndnsh + 4) = 0;
    *((unsigned char *) ndnsh + 5) = 1;
    *((unsigned char *) ndnsh + 6) = 0;
    *((unsigned char *) ndnsh + 7) = 1;
    *((unsigned char *) ndnsh + 8) = 0;
    *((unsigned char *) ndnsh + 9) = 0;
    *((unsigned char *) ndnsh + 10) = 0;
    *((unsigned char *) ndnsh + 11) = 0;

    return len;
}

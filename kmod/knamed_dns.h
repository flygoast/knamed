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


#include <asm/byteorder.h>


#define MAX_DNS_PACKET_LEN      512


/* possible OPCODE values */
#define OPCODE_QUERY        0   /* a standard query (QUERY) */
#define OPCODE_IQUEURY      1   /* an inverse query (IQUERY) */
#define OPCODE_STATUS       2   /* a server status request (STATUS) */
#define OPCODE_NOTIFY       4   /* NOTIFY */
#define OPCODE_UPDATE       5   /* dynamic update */


/* possible RCODE values */
#define RCODE_NOERROR       0   /* no error condition */
#define RCODE_FORMERR       1   /* fromat error */
#define RCODE_SERVFAIL      2   /* server failure */
#define RCODE_NXDOMAIN      3   /* name error */
#define RCODE_NOTIMP        4   /* not implemented */
#define RCODE_REFUSED       5   /* refused */
#define RCODE_YXDOMAIN      6   /* name should not exist */
#define RCODE_YXRRSET       7   /* rrset should not exist */
#define RCODE_NXRRSET       8   /* rrset does not exist */
#define RCODE_NOTAUTH       9   /* server not authoritative */
#define RCODE_NOTZONE       10  /* name not inside zone */


/* RFC1035 */
#define CLASS_IN            1   /* class IN */
#define CLASS_CS            2   /* class CS */
#define CLASS_CHAOS         3   /* class CHAOS */
#define CLASS_HS            4   /* class HS */
#define CLASS_NONE          254 /* class NONE rfc2136 */
#define CLASS_ANY           255 /* class ANY */


#define TYPE_A              1   /* a host address */
#define TYPE_NS             2   /* an authoritative name server */
#define TYPE_MD             3   /* a mail destination (Obsolete - use MX) */
#define TYPE_MF             4   /* a mail forwarder (Obsolete - use MX) */
#define TYPE_CNAME          5   /* the canonical name for an alias */
#define TYPE_SOA            6   /* marks the start of a zone of authority */
#define TYPE_MB             7   /* a mailbox domain name (EXPERIMENTAL) */
#define TYPE_MG             8   /* a mail group member (EXPERIMENTAL) */
#define TYPE_MR             9   /* a mail rename domain name (EXPERIMENTAL) */
#define TYPE_NULL           10  /* a null RR (EXPERIMENTAL) */
#define TYPE_WKS            11  /* a well known service descrition */
#define TYPE_PTR            12  /* a domain name pointer */
#define TYPE_HINFO          13  /* host information */
#define TYPE_MINFO          14  /* mailbox or mail list information */
#define TYPE_MX             15  /* mail exchange */
#define TYPE_TXT            16  /* text strings */
#define TYPE_RP             17  /* RFC1183 */
#define TYPE_AFSDB          18  /* RFC1183 */
#define TYPE_X25            19  /* RFC1183 */
#define TYPE_ISDN           20  /* RFC1183 */
#define TYPE_RT             21  /* RFC1183 */
#define TYPE_NSAP           22  /* RFC1706 */

#define TYPE_SIG            24  /* 2535typecode */
#define TYPE_KEY            25  /* 2535typecode */
#define TYPE_PX             26  /* RFC2163 */

#define TYPE_AAAA           28  /* ipv6 address */
#define TYPE_LOC            29  /* LOC record RFC1876 */
#define TYPE_NXT            30  /* 2535typecode */

#define TYPE_SRV            33  /* SRV record RFC2782 */

#define TYPE_NAPTR          35  /* RFC2915 */
#define TYPE_KX             36  /* RFC2230 Key Exchange Delegation Record */
#define TYPE_CERT           37  /* RFC2538 */
#define TYPE_A6             38  /* RFC2874 */
#define TYPE_DNAME          39  /* RFC2672 */

#define TYPE_OPT            41  /* pseudo OPT record... */
#define TYPE_APL            42  /* RFC3123 */
#define TYPE_DS             43  /* RFC 4033, 4034, and 4035 */
#define TYPE_SSHFP          44  /* SSH Key Fingerprint */
#define TYPE_IPSECKEY       45  /* public key for ipsec use. RFC 4025 */
#define TYPE_RRSIG          46  /* RFC 4033, 4034, and 4035 */
#define TYPE_NSEC           47  /* RFC 4033, 4034, and 4035 */
#define TYPE_DNSKEY         48  /* RFC 4033, 4034, and 4035 */
#define TYPE_DHCID          49  /* RFC4701 DHCP information */
#define TYPE_NSEC3          50  /* NSEC3, secure denial, prevents zonewalking */
#define TYPE_NSEC3PARAM     51  /* NSEC3PARAM at zone apex nsec3 parameters */
#define TYPE_TLSA           52  /* RFC 6698 */

#define TYPE_SPF            99  /* RFC 4408 */

#define TYPE_NID            104 /* RFC 6742 */
#define TYPE_L32            105 /* RFC 6742 */
#define TYPE_L64            106 /* RFC 6742 */
#define TYPE_LP             107 /* RFC 6742 */
#define TYPE_EUI48          108 /* RFC 7043 */
#define TYPE_EUI64          109 /* RFC 7043 */

#define TYPE_ISIG           250
#define TYPE_IXFR           251
#define TYPE_AXFR           252
#define TYPE_MAILB          253 /* A request for mailbox-related
                                   records (MB, MG or MR) */
#define TYPE_MAILA          254 /* A request for mail agent RRs
                                   (Obsolete - see MX) */
#define TYPE_ANY            255 /* any type (wildcard) */

#define TYPE_CAA            257 /* RFC 6844 */

#define TYPE_DLV            32769   /* RFC 4431 */


/*
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
struct dnshdr {
    unsigned  id:16;        /* query identification number */
#if defined(__BIG_ENDIAN)
              /* fields in third byte */
    unsigned  qr:1;         /* resposne flag */
    unsigned  opcode:4;     /* purpose of message */
    unsigned  aa:1;         /* authoritative answer */
    unsigned  tc:1;         /* truncated message */
    unsigned  rd:1;         /* recursion desired */
              /* fields in fourth byte */
    unsigned  ra:1;         /* recursion available */
    unsigned  unused:1;     /* unused bit */
    unsigned  ad:1;         /* authentic data from named */
    unsigned  cd:1;         /* checking disabled by resolver */
    unsigned  rcode:4;      /* response code */
#elif defined(__LITTLE_ENDIAN)
              /* fields in third byte */
    unsigned  rd:1;         /* recursion desired */
    unsigned  tc:1;         /* truncated message */
    unsigned  aa:1;         /* authoritative answer */
    unsigned  opcode:4;     /* purpose of message */
    unsigned  qr:1;         /* response flag */
              /* fields in fourth byte */
    unsigned  rcode:4;      /* response code */
    unsigned  cd:1;         /* checking disabled by resolver */
    unsigned  ad:1;         /* authentic data from named */
    unsigned  unused:1;     /* unused bits */
    unsigned  ra:1;         /* recursion available */
#endif
              /* remaining bytes */
    unsigned  qdcount:16;   /* number of question entries */
    unsigned  ancount:16;   /* number of answer entries */
    unsigned  nscount:16;   /* number of authority entries */
    unsigned  arcount:16;   /* number of resource entries */
};


int process_query(struct dnshdr *dnsh, int dnslen, unsigned char *buf);
int dns_init(void);
void dns_cleanup(void);

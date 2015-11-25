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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <asm/unaligned.h>
#include "knamed.h"
#include "knamed_dns.h"


static struct task_struct  *knamed_task;


static unsigned int knamed_in(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *));


static void process_skb(struct sk_buff *oskb);


static struct nf_hook_ops  knamed_ops[] __read_mostly = {
    {
        .hook = knamed_in,
        .owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
};


static int
knamed_loop(void *data)
{
    allow_signal(SIGHUP);

    while (1) {
        set_current_state(TASK_INTERRUPTIBLE);

        if (kthread_should_stop()) {
            break;
        }

        if (signal_pending(current)) {
            flush_signals(current);

            PR_INFO("SIGNAL received");
        }

        PR_INFO("Hello knamed_task");

        schedule_timeout(5 * HZ);
    }

    knamed_task = NULL;

    return 0;
}


static unsigned int knamed_in(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct iphdr    *iph;
    struct udphdr   *udph, _udph;

    if ((iph = ip_hdr(skb)) == NULL) {
        return NF_ACCEPT;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    udph = skb_header_pointer(skb, ip_hdrlen(skb),
                              sizeof(_udph), &_udph);
    if (udph == NULL) {
        return NF_ACCEPT;
    }

    if (ntohs(udph->dest) != sysctl_knamed_port) {
        return NF_ACCEPT;
    }

    process_skb(skb);

    return NF_DROP;
}


static void process_skb(struct sk_buff *oskb)
{
    int              ulen, len, dnslen;
    struct sk_buff  *nskb;
    struct iphdr    *oiph, *niph;
    struct udphdr   *oudph, *nudph, _oudph;
    struct dnshdr   *dnsh;

    oiph = ip_hdr(oskb);
    oudph = skb_header_pointer(oskb, ip_hdrlen(oskb),
                               sizeof(_oudph), &_oudph);

    if (oudph == NULL) {
        PR_ERR("Invalid UDP packet, dropped");
        return;
    }

    /*
     * 5 is the minimal question length
     * (1 byte root, 2 bytes each type and class)
     */
    dnslen = ntohs(oudph->len) - sizeof(struct udphdr);
    if (dnslen < sizeof(struct dnshdr) + 5) {
        PR_ERR("Incomplete DNS packet, dropped");
        return;
    }

    dnsh = (struct dnshdr *) ((unsigned char *) oudph + sizeof(struct udphdr));

    ulen = sizeof(struct udphdr) + MAX_DNS_PACKET_LEN;

    nskb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + ulen, GFP_ATOMIC);
    if (nskb == NULL) {
        PR_CRIT("alloc_skb failed, dropped");
        return;
    }

    skb_reserve(nskb, LL_MAX_HEADER
                      + sizeof(struct iphdr)
                      + sizeof(struct udphdr));

    len = process_query(oiph, oudph, dnsh, dnslen, nskb->data);
    if (len < 0) {
        kfree_skb(nskb);

        PR_CRIT("process dns query failed, dropped");
        return;
    }

    nskb->len += len;

    nudph = (struct udphdr *) skb_push(nskb, sizeof(struct udphdr));
    skb_reset_transport_header(nskb);

    ulen = sizeof(struct udphdr) + len;
    nudph->source = oudph->dest;
    nudph->dest = oudph->source;
    nudph->len = htons(ulen);
    nudph->check = 0;
    nudph->check = csum_tcpudp_magic(oiph->daddr,
                                     oiph->saddr,
                                     ulen,
                                     IPPROTO_UDP,
                                     csum_partial(nudph, ulen, 0));
    if (nudph->check == 0) {
        nudph->check = CSUM_MANGLED_0;
    }

    niph = (struct iphdr *) skb_push(nskb, sizeof(struct iphdr));
    skb_reset_network_header(nskb);

    /* niph->version = 4; niph->ihl = 5; */
    put_unaligned(0x45, (unsigned char *) niph);
    niph->tos = 0;
    put_unaligned(htons(nskb->len), &(niph->tot_len));
    niph->id = 0x8659; /* birthday of my wife ^o^ */
    niph->frag_off = htons(IP_DF);
    niph->ttl = 64;
    niph->protocol = IPPROTO_UDP;
    niph->check = 0;
    put_unaligned(oiph->daddr, &(niph->saddr));
    put_unaligned(oiph->saddr, &(niph->daddr));

    ip_send_check(niph);

    skb_dst_set(nskb, dst_clone(skb_dst(oskb)));

    if (ip_route_me_harder(nskb, RTN_LOCAL)) {
        goto free_nskb;
    }

    nf_ct_attach(nskb, oskb);

    ip_local_out(nskb);

    return;

free_nskb:

    kfree_skb(nskb);
}


static int __init knamed_init(void)
{
    struct file  *filp;
    int           ret;
    int           err;

    PR_INFO("starting");
    PR_INFO("Author: Gu Feng <flygoast@126.com>");
    PR_INFO("Version: %s", KNAMED_VERSION);
    PR_INFO("Repository: https://github.com/flygoast/knamed.git");

    filp = filp_open(KNAMED_CONF, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        PR_INFO("conf file \"%s\" didn't existed, ignored", KNAMED_CONF);
        goto init;
    }

    if (filp) {
        fput(filp);
    }

init:

    ret = nf_register_hooks(knamed_ops, ARRAY_SIZE(knamed_ops));
    if (ret < 0) {
        PR_ERR("can't register hooks.");
        goto cleanup;
    }

    knamed_procfs_init();
    knamed_sysctl_register();

    dns_init();

    knamed_task = kthread_run(knamed_loop, NULL, "knamedtask");
    if (IS_ERR(knamed_task)) {
        PR_ERR("Create kernel thread failed");
        err = PTR_ERR(knamed_task);
        return err;
    }

    PR_INFO("started");

    return 0;

cleanup:

    return ret;
}


static void __exit knamed_exit(void)
{
    nf_unregister_hooks(knamed_ops, ARRAY_SIZE(knamed_ops));

    knamed_sysctl_unregister();
    knamed_procfs_release();

    dns_cleanup();

    if (knamed_task) {
        kthread_stop(knamed_task);
    }

    PR_INFO("removed");
}


module_init(knamed_init);
module_exit(knamed_exit);


MODULE_AUTHOR("Gu Feng <flygoast@126.com>");
MODULE_DESCRIPTION("knamed: Authoritative name server in Linux kernel");
MODULE_LICENSE("GPL");

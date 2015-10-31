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


#include <linux/sysctl.h>
#include <linux/stat.h>
#include "knamed.h"


int sysctl_knamed_port = KNAMED_PORT;
int sysctl_knamed_ttl = KNAMED_TTL;


static struct ctl_table_header  *sysctl_header;


static int knamed_port_sysctl(ctl_table *table, int write, void __user *buffer,
    size_t *lenp, loff_t *ppos);
static int knamed_ttl_sysctl(ctl_table *table, int write, void __user *buffer,
    size_t *lenp, loff_t *ppos);


/*
 * knamed sysctl table (under the /proc/sys/net/ipv4/knamed/)
 */
static ctl_table  knamed_vars[] = {
    {
        .procname     = "port",
        .data         = &sysctl_knamed_port,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = knamed_port_sysctl,
    },

    {
        .procname     = "ttl",
        .data         = &sysctl_knamed_ttl,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = knamed_ttl_sysctl,
    },

    {
        .ctl_name = 0
    }
};


const static struct ctl_path knamed_ctl_path[] = {
    {
        .procname = "net",
        .ctl_name = CTL_NET,
    },
    {
        .procname = "ipv4",
        .ctl_name = NET_IPV4,
    },
    {
        .procname = "knamed",
    },
    {}
};


static int
knamed_port_sysctl(ctl_table *table,
                   int write,
                   void __user *buffer,
                   size_t *lenp,
                   loff_t *ppos)
{
    int  *valp = table->data;
    int   val = *valp;
    int   rc;

    rc = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && (*valp != val)) {
        if ((*valp < 0) || (*valp > 65535)) {
            PR_ERR("invalid port: %d, must be between 0-65535", *valp);
            /* Restore the correct value */
            *valp = val;
        } else {
            PR_INFO("change port from %d to %d", val, *valp);
        }
    }

    return rc;
}


static int
knamed_ttl_sysctl(ctl_table *table,
                  int write,
                  void __user *buffer,
                  size_t *lenp,
                  loff_t *ppos)
{
    int  *valp = table->data;
    int   val = *valp;
    int   rc;

    rc = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && (*valp != val)) {
        if (*valp < 0) {
            PR_ERR("Invalid ttl: %d, must be positive", *valp);
            /* Restore the correct value */
            *valp = val;
        } else {
            PR_INFO("Change ttl from %d to %d", val, *valp);
        }
    }

    return rc;
}


int
knamed_sysctl_register(void)
{
    sysctl_header = register_sysctl_paths(knamed_ctl_path, knamed_vars);
    if (sysctl_header == NULL) {
        return -1;
    }

    return 0;
}


void
knamed_sysctl_unregister(void)
{
    if (sysctl_header != NULL) {
        unregister_sysctl_table(sysctl_header);
    }
}

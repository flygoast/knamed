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


#ifndef __KNAMED_H_INCLUDED__
#define __KNAMED_H_INCLUDED__


#define DEBUG       1
#define LOG_PREFIX  "knamed: "


#define PR_EMERG(fmt, ...)                          \
    printk(KERN_EMERG LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_ALERT(fmt, ...)                          \
    printk(KERN_ALERT LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_CRIT(fmt, ...)                           \
    printk(KERN_CRIT LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_ERR(fmt, ...)                            \
    printk(KERN_ERR LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_WARNING(fmt, ...)                        \
    printk(KERN_WARNING LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_WARN PR_WARNING
#define PR_NOTICE(fmt, ...)                         \
    printk(KERN_NOTICE LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_INFO(fmt, ...)                           \
    printk(KERN_INFO LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define PR_CONT(fmt, ...)                           \
    printk(KERN_CONT LOG_PREFIX fmt "\n", ##__VA_ARGS__)


#ifdef DEBUG
#define PR_DEBUG(fmt, ...)                              \
    printk(KERN_DEBUG LOG_PREFIX "[%s:%d] " fmt "\n",   \
           __func__, __LINE__, ##__VA_ARGS__)
#else
#define PR_DEBUG(fmt, ...)  /* nothing */
#endif


#define KNAMED_VERSION   "0.0.1"
#define KNAMED_TOKEN     "knamed/" KNAMED_VERSION
#define KNAMED_CONF      "/etc/knamed/knamed.conf"


#define KNAMED_PORT             53
#define KNAMED_DEF_TTL          60
#define KNAMED_PAGE_NUMBER      8


extern int sysctl_knamed_port;
extern int sysctl_knamed_default_ttl;
extern int sysctl_knamed_hide_version;


void knamed_procfs_init(void);
void knamed_procfs_release(void);
int knamed_sysctl_register(void);
void knamed_sysctl_unregister(void);


#endif /* __KNAMED_H_INCLUDED__ */

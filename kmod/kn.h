#ifndef __KN_H_INCLUDED__
#define __KN_H_INCLUDED__


#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>


#include "kn_connector.h"
#include "kn_conf.h"


#define LOG_PREFIX  "knamed: "


#define PRINTK(fmt, ...)                            \
    printk(KERN_ERR LOG_PREFIX "[%s:%d] " fmt "\n",  \
           __func__, __LINE__, ##__VA_ARGS__)


#endif /* __KN_H_INCLUDED__ */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include "kn.h"


static struct kn_cn  kn_cn;


static void __kn_del_callback(struct kn_cn_id *id)
{
    struct kn_cn_entry  *pos, *n;
    struct kn_cn_queue  *queue = kn_cn.queue;

    spin_lock_bh(&queue->lock);
    list_for_each_entry_safe(pos, n, &queue->list, list_entry) {
        if (pos->id.idx == id->idx && pos->id.val == id->val) {
            list_del(&pos->list_entry);
            break;
        }
    }
    spin_unlock_bh(&queue->lock);

    if (&pos->list_entry != &queue->list) {
        kfree(pos);
    }
}


void kn_del_callback(struct kn_cn_id *id, int sync)
{
    if (likely(sync)) {
        __kn_del_callback(id);
    }
}


static void __kn_cn_work(struct work_struct *work, int sync)
{
    struct kn_cn_entry        *entry;
    struct kn_cn_callback     *callback;
    struct kn_cn_msg          *msg;
    struct netlink_skb_parms  *parms;

    entry = container_of(work, struct kn_cn_entry, work);
    callback = &entry->callback;
    msg = NLMSG_DATA(nlmsg_hdr(callback->skb));
    parms = &NETLINK_CB(callback->skb);

    callback->out = callback->f(msg, parms);
    kfree_skb(callback->skb);
    if (sync) {
        complete(&entry->comp);

    } else {
        __kn_del_callback(&entry->id);
    }
}


static void kn_cn_work(struct work_struct *work)
{
    __kn_cn_work(work, 1);
}


static void kn_cn_work_del(struct work_struct *work)
{
    __kn_cn_work(work, 0);
}


int kn_add_callback(struct kn_cn_id *id, kn_cn_cb_fn *f, int sync)
{
    int                  ret = 0;
    struct kn_cn_entry  *entry, *pos;
    struct kn_cn_queue  *queue = kn_cn.queue;

    entry = kzalloc(sizeof(struct kn_cn_entry), GFP_KERNEL);
    if (!entry) {
        ret = -ENOMEM;
        goto out;
    }

    entry->flags = KN_ENTRY_NEW;
    entry->id.idx = id->idx;
    entry->id.val = id->val;
    entry->callback.skb = NULL;
    entry->callback.out = NULL;
    entry->callback.f = f;
    
    if (likely(sync)) {
        INIT_WORK(&entry->work, kn_cn_work);
        init_completion(&entry->comp);

    } else {
        INIT_WORK(&entry->work, kn_cn_work_del);
    }

    spin_lock_bh(&queue->lock);

    list_for_each_entry(pos, &queue->list, list_entry) {
        if (pos->id.idx == id->idx && pos->id.val == id->val) {
            break;
        }
    }

    if (&pos->list_entry == &queue->list) {
        list_add_tail(&entry->list_entry, &queue->list);
        spin_unlock_bh(&queue->lock);

    } else {
        spin_unlock_bh(&queue->lock);
        ret = -EFAULT;
        goto free_entry;
    }

    return 0;

free_entry:

    kfree(entry);

out:

    return ret;
}


static void *kn_send_msg_timeout(struct kn_cn_msg *msg, unsigned long timeout)
{
    int                  ret = 0;
    size_t               size;
    struct sk_buff      *skb;
    struct nlmsghdr     *nlh;
    struct kn_cn_msg    *data;
    struct kn_cn_entry  *entry;
    struct kn_cn_queue  *queue = kn_cn.queue;

    spin_lock_bh(&queue->lock);
    list_for_each_entry(entry, &queue->list, list_entry) {
        if (entry->id.idx == msg->id.idx && entry->id.val == msg->id.val) {
            entry->flags = KN_ENTRY_RUNNING;
            break;
        }
    }
    spin_unlock_bh(&queue->lock);

    if (unlikely(&entry->list_entry == &queue->list)) {
        return NULL;
    }

    if (!netlink_has_listeners(kn_cn.sock, NETLINK_KNAMED_GRP)) {
        PRINTK("netlink hasn't got a listener");
        ret = -ESRCH;
        goto out;
    }

    size = NLMSG_SPACE(sizeof(struct kn_cn_msg) + msg->len);
    skb = alloc_skb(size, GFP_KERNEL);
    if (!skb) {
        PRINTK("alloc skb error");
        ret = -ENOMEM;
        goto out;
    }

    nlh = NLMSG_PUT(skb, 0, 0, NLMSG_DONE, size - sizeof(struct kn_cn_msg));
    data = NLMSG_DATA(nlh);

    memcpy(data, msg, sizeof(struct kn_cn_msg) + msg->len);

    NETLINK_CB(skb).dst_group = 0;

    if ((ret = netlink_broadcast(kn_cn.sock, skb, 0, NETLINK_KNAMED_GRP,
                                 GFP_KERNEL)))
    {
        PRINTK("netlink broadcast error");
        goto out;
    }

    if (unlikely(!timeout)) {
        entry->flags = KN_ENTRY_FINISHED;
        return NULL;
    }

    ret = wait_for_completion_timeout(&entry->comp, timeout);
    if (!ret) {
        PRINTK("wait kn_cn_entry callback timeout");
        ret = -EFAULT;
        goto out;
    }

    entry->flags = KN_ENTRY_FINISHED;
    return entry->callback.out;

nlmsg_failure:

    kfree_skb(skb);
    ret = -EFAULT;

out:

    return ERR_PTR(ret);
}


void *kn_send_msg(struct kn_cn_msg *msg)
{
    return kn_send_msg_timeout(msg, 0);
}


void *kn_send_msg_sync(struct kn_cn_msg *msg)
{
    return kn_send_msg_timeout(msg, MAX_SCHEDULE_TIMEOUT);
} 


static void kn_nl_callback(struct sk_buff *_skb)
{
    struct sk_buff      *skb;
    struct nlmsghdr     *nlh;
    struct kn_cn_msg    *msg;
    struct kn_cn_entry  *entry;
    struct kn_cn_queue  *queue = kn_cn.queue;

    skb = skb_get(_skb);
    if (skb->len < NLMSG_SPACE(0)) {
        goto out;
    }

    nlh = nlmsg_hdr(skb);
    if (nlh->nlmsg_len < sizeof(struct kn_cn_msg) 
        || skb->len < nlh->nlmsg_len
        || nlh->nlmsg_len > NETLINK_PAYLOAD)
    {
        goto out;
    }

    msg = NLMSG_DATA(nlh);
    spin_lock_bh(&queue->lock);
    list_for_each_entry(entry, &queue->list, list_entry) {
        if (entry->id.idx == msg->id.idx && entry->id.val == msg->id.val) {
            entry->callback.skb = skb;

            if (!schedule_work(&entry->work)) {
                spin_unlock_bh(&queue->lock);
                entry->callback.skb = NULL;
                PRINTK("may be dead lock, check callback");
                goto out;
            }
            break;
        }
    }
    spin_unlock_bh(&queue->lock);

    if (unlikely(&entry->list_entry == &queue->list)) {
        kfree_skb(skb);
    }

    return;

out:
    
    kfree_skb(skb);
    return;
}


int kn_connector_init(void)
{
    int  ret = 0;

    kn_cn.sock = netlink_kernel_create(&init_net, NETLINK_KNAMED,
                                       NETLINK_KNAMED_GRP,
                                       kn_nl_callback,
                                       NULL,
                                       THIS_MODULE);
    if (!kn_cn.sock) {
        PRINTK("create netlink failed");
        ret = -EIO;
        goto out;
    }

    kn_cn.queue = kzalloc(sizeof(struct kn_cn_queue), GFP_KERNEL);
    if (!kn_cn.queue) {
        PRINTK("alloc connector queue failed");
        ret = -ENOMEM;
        goto free_netlink;
    }

    INIT_LIST_HEAD(&kn_cn.queue->list);
    spin_lock_init(&kn_cn.queue->lock);

    return 0;

free_netlink:

    netlink_kernel_release(kn_cn.sock);
    kn_cn.sock = NULL;

out:

    return ret;
}


void kn_connector_exit(void)
{
    struct kn_cn_entry  *pos, *n;
    struct kn_cn_queue  *queue = kn_cn.queue;

retry:
    
    spin_lock_bh(&queue->lock);
    list_for_each_entry_safe(pos, n, &queue->list, list_entry) {
        if (pos->flags != KN_ENTRY_RUNNING) {
            list_del(&pos->list_entry);
            kfree(pos);

        } else {
            spin_unlock_bh(&queue->lock);
            flush_work(&pos->work);
            goto retry;
        }
    }
    spin_unlock_bh(&queue->lock);

    kfree(queue);
    netlink_kernel_release(kn_cn.sock);
}

#ifndef __KN_CONNECTOR_H_INCLUDED__
#define __KN_CONNECTOR_H_INCLUDED__


#define NETLINK_KNAMED      21
#define NETLINK_KNAMED_GRP  3
#define NETLINK_PAYLOAD     4096


#define KN_ENTRY_NEW       (0x1 << 0)
#define KN_ENTRY_RUNNING   (0x1 << 1)
#define KN_ENTRY_FINISHED  (0x1 << 2)


struct kn_cn_id {
    __u32  idx;
    __u32  val;
};


struct kn_cn_msg {
    struct kn_cn_id  id;
    __u16            len;
    __u8             data[0];
};


#ifdef __KERNEL__


typedef void *(kn_cn_cb_fn)(struct kn_cn_msg *, struct netlink_skb_parms *);


struct kn_cn_callback {
    struct sk_buff  *skb;
    kn_cn_cb_fn     *f;
    void            *out;
};


struct kn_cn_entry {
    __u32                  flags:4;
    __u32                  unused:28;
    struct kn_cn_id        id;
    struct list_head       list_entry;
    struct kn_cn_callback  callback;
    struct work_struct     work;
    struct completion      comp;
};


struct kn_cn_queue {
    struct list_head    list;
    spinlock_t          lock;
};


struct kn_cn {
    struct sock         *sock;
    struct kn_cn_queue  *queue;
};


int kn_add_callback(struct kn_cn_id *id, kn_cn_cb_fn *f, int sync);
int kn_connector_init(void);
void kn_connector_exit(void);


#endif /* __KERNEL__ */


#endif /* __KN_CONNECTOR_H_INCLUDED__ */

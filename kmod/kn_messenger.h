#ifndef __KN_MESSENGER_H_INCLUDED__
#define __KN_MESSENGER_H_INCLUDED__

struct kn_conn {
    unsigned long               event;
    atomic_t                    refcnt;
    struct kn_worker_storage   *ws;
    struct work_struct          work;
    struct list_head            list;
    struct socket              *sock;
    int                         state;
    int                         trans;
}

#endif /* __KN_MESSENGER_H_INCLUDED__ */

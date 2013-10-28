#ifndef __KN_WORKER_H_INCLUDED__
#define __KN_WORKER_H_INCLUDED__


struct kn_thread_stats {
    spinlock_t          lock;
    u64                 place_holder;
};


struct kn_conn_req {
    int                 state;
    int                 trans;
    struct socket      *sock;
    int                 rsize;
    struct work_struct  work;
};


struct kn_worker_thread {
    spinlock_t                lock;
    struct list_head          list;
    struct workqueue_struct  *wq;
    struct kn_thread_stats    stats;
};


int kn_worker_init(void);
void kn_worker_exit(void);


#endif /* __KN_WORKER_H_INCLUDED__ */

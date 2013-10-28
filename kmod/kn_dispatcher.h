#ifndef __KN_DISPATCHER_H_INCLUDED__
#define __KN_DISPATCHER_H_INCLUDED__


struct dispatcher_thread {
    struct workqueue_struct  *wq;
    struct list_head          udp_list;
    spinlock_t                lock;
};


extern struct dispatcher_thread  dispatcher;


int dispatcher_init(void);
void dispatcher_exit(void);


#endif /* __KN_DISPATCHER_H_INCLUDED__ */

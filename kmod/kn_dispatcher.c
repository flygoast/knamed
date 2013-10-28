#include "kn.h"
#include "kn_dispatcher.h"


#define DISPATCHER_COMM     "kn_dispatcher"


struct dispatcher_thread   dispatcher;

struct server_sock {
    struct socket      *sock;
    struct list_head    list;
    struct work_struct  work;
} ss;


int __init dispatcher_init(void)
{
    int              ret = 0;
    int              flags = 1;
    int              bs = 4096;
    struct sockaddr  in;

    /*
    ret = inet_aton("0.0.0.0", &in.in_addr);
    if (ret == 0) {
        return -1;
    }

    dispatcher.wq = create_singlethread_workqueue(DISPATCHER_COMM);

    if (dispatcher.wq == NULL) {
        PRINTK("create dispatcher workqueue failed");
        ret = -ENOMEM;
        goto out;
    }

    INIT_LIST_HEAD(&dispatcher.udp_list);

    memset(&ss, 0, sizeof(ss));
    INIT_LIST_HEAD(&ss->list);
    INIT_WORK(&ss->work, kn_listen_work);

    ret = sock_create_kern(AF_INET, SOCK_DGRAM, PROTOCOL_UDP, &ss->sock);
    if (ret < 0) {
        PRINTK("create server socker error(%d)", ret);
        goto out;
    }

    ret = kernel_setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR, 
                            (char *)&flags, sizeof(flags));
    if (ret < 0) {
        goto out;
    }

    ret = kernel_setsockopt(ss->sock, SQL_SOCKET, SO_SNDBUF, 
                            (char *)&bs, sizeof(bs));
    if (ret < 0) {
        goto out;
    }

    ret = kernel_bind(ss->sock, (struct sockaddr *)in, sizeof(struct in_addr));
    if (ret < 0) {
        goto out;
    }

    */


    ret = 0;

out:

    return ret;
}


void __exit dispatcher_exit(void)
{
    /*
    destroy_workqueue(dispatcher.wq);
    */
}

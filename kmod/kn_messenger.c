#include "kn.h"

struct kmem_cache *kn_conn_cache;


static inline kn_conn *_conn_new(void)
{
    return kmem_cache_zalloc(kn_conn_cache, GFP_KERNEL);
}


static inline void _conn_free(void *conn)
{
    kmem_cache_free(kn_conn_cache, conn);
}


static void kn_conn_free(kn_conn *c)
{
    
}


kn_conn *kn_conn_new(struct kn_conn_req *req)
{
    struct kn_worker_storage  *ws;
    kn_conn                   *c;

    c = _conn_new();
    if (!c) {
        PRINTK("alloc new kn_conn failed");
        c = ERR_PTR(-ENOMEM);
        goto out;
    }



}

#include "kn.h"


static int  knamed_running;


static void *kn_reload(struct kn_cn_msg *msg, struct netlink_skb_parms *parms)
{
    PRINTK("reload knamed success");
    return NULL;
}


static void *kn_stop(struct kn_cn_msg *msg, struct netlink_skb_parms *parms)
{
    PRINTK("stop knamed success");
    return NULL;
}


static int __kn_start(void *unused)
{
    int  ret = 0;

    /* TODO */

    if (ret = workers_init()) 

    knamed_running = 1;
    PRINTK("start knamed success");
    return ret;
}


static void *kn_start(struct kn_cn_msg *msg, struct netlink_skb_parms *parms)
{
    struct task_struct  *helper;

    helper = kthread_run(__kn_start, NULL, "knamed_bh");
    if (IS_ERR(helper)) {
        PRINTK("create knamed bh kthread failed");
    }

    return NULL;
}


static int kn_register_callbacks(void)
{
    int  ret = 0;

    ret = kn_add_callback(&knamed_cn_ctrl_start, kn_start, 0);
    if (ret) {
        PRINTK("add kn_start callback failed");
        return ret;
    }

    ret = kn_add_callback(&knamed_cn_ctrl_stop, kn_stop, 0);
    if (ret) {
        PRINTK("add kn_stop callback failed");
        return ret;
    }

    ret = kn_add_callback(&knamed_cn_ctrl_reload, kn_reload, 0);
    if (ret) {
        PRINTK("add kn_stop callback failed");
        return ret;
    }

    return ret;
}


static int __init knamed_init(void)
{
    int  ret;

    ret = kn_connector_init();
    if (ret) {
        PRINTK("init connector failed");
        goto out;
    }

    ret = kn_register_callbacks();
    if (ret) {
        PRINTK("add kn_start callback failed");
        goto cn_exit;
    }

    PRINTK("insert knamed module success");
    return 0;

cn_exit:

    kn_connector_exit();

out:

    return ret;
}


static void __exit knamed_exit(void)
{
    /* TODO */
    if (knamed_running) {
        PRINTK("stop knamed success");
    }

    kn_connector_exit();

    PRINTK("remove knamed module success"); 
}


module_init(knamed_init);
module_exit(knamed_exit);


MODULE_AUTHOR("FengGu <flygoast@126.com>");
MODULE_DESCRIPTION("knamed: kernel named");
MODULE_LICENSE("GPL");

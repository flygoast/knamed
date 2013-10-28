#include "kn.h"
#include "kn_worker.h"


#define WORKER_COMM     "kn_worker"


static struct kn_worker_storage  *storage __percpu;
static struct workqueue_struct   *workqueue;
int                               cpu_num __read_mostly;


int __init kn_worker_init(void)
{
    int                        cpu, ret = 0;
    char                       thread_comm[TASK_COMM_LEN];
    struct workqueue_struct   *wq;
    struct kn_worker_storage  *stor;

    cpu_num = num_possible_cpus();

    storage = alloc_percpu(struct kn_worker_storage);
    if (!storage) {
        PRINTK("alloc worker_storage failed");
        ret = -ENOMEM;
        goto out;
    }

    for_each_possible_cpu(cpu) {
        stor = per_cpu_ptr(storage, cpu);
        memset(stor, 0, sizeof(*stor));
        INIT_LIST_HEAD(&stor->list);
        spin_lock_init(&stor->lock);
    }

    workqueue = create_workqueue(WORKER_COMM);
    if (!workqueue) {
        PRINTK("create worker_queue failed");
        ret = -ENOMEM;
        goto free_storage;
    }

    return 0;

free_storage:

    free_percpu(storage);

out:

    return ret;
}


void __exit workers_exit(void)
{
    int                        cpu;
    struct kn_worker_storage  *stor;

    for_each_possible_cpu(cpu) {
        stor = per_cpu_ptr(storage, cpu);
        spin_lock(&stor->lock);
        list_for_each_entry(c, &stor->list, list) {
            set_bit(EV_DEAD, &c->event);
        }
        spin_unlock(&stor->lock);
    }
    flush_workqueue(workqueue);


    PRINTK("exit worker thread success");
}

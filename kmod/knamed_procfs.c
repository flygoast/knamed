/*
 * Copyright (c) 2015, Gu Feng <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "knamed.h"


#ifdef CONFIG_PROC_FS

static atomic_t  knamed_file_available = ATOMIC_INIT(1);


static unsigned long  *knamed_pages;


int knamed_page_number = KNAMED_PAGE_NUMBER;


static int
knamed_version_show(struct seq_file *seq, void *v)
{
    seq_printf(seq, "knamed: Authoritative name server in Linux kernel\n");
    seq_printf(seq, "Author: Gu Feng <flygoast@126.com>\n");
    seq_printf(seq, "Version: %s\n", KNAMED_VERSION);
    seq_printf(seq, "Repository: https://github.com/flygoast/knamed.git\n");

    return 0;
}


static int
knamed_version_open(struct inode *inode, struct file *file)
{
    return single_open(file, &knamed_version_show, 0);
}


static int
knamed_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct page        *page;

    if (vmf->pgoff >= knamed_page_number) {
        return VM_FAULT_SIGBUS;
    }

    page = virt_to_page((void *) knamed_pages[vmf->pgoff]);
    if (page == NULL) {
        return VM_FAULT_SIGBUS;
    }

    get_page(page);
    vmf->page = page;

    return 0;
}


struct vm_operations_struct knamed_buf_vm_ops = {
    .fault = knamed_vma_fault,
};


static int
knamed_buf_open(struct inode *inode, struct file *filp)
{
    if (!atomic_dec_and_test(&knamed_file_available)) {
        atomic_inc(&knamed_file_available);
        return -EBUSY;
    }

    return nonseekable_open(inode, filp);
}


static int
knamed_buf_release(struct inode *inode, struct file *filp)
{
    atomic_inc(&knamed_file_available);
    return 0;
}


static int
knamed_buf_mmap(struct file *filp, struct vm_area_struct *vma)
{
    uint32_t  pages;

    pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

    if (pages > knamed_page_number) {
        PR_ERR("Attempt to map pages %d while the buffer has %d pages",
               pages, knamed_page_number);
        return -EINVAL;
    }

    vma->vm_ops = &knamed_buf_vm_ops;
    vma->vm_flags |= VM_IO|VM_RESERVED;

    return 0;
}


static struct file_operations  knamed_buffer_operations = {
    .owner      = THIS_MODULE,
    .open       = knamed_buf_open,
    .release    = knamed_buf_release,
    .mmap       = knamed_buf_mmap,
    .llseek     = no_llseek,
};


static struct file_operations  knamed_version_operations = {
    .open       = knamed_version_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};


void
knamed_procfs_init(void)
{
    int                     i, sz;
    struct proc_dir_entry  *entry;

    if (proc_mkdir("knamed", NULL)) {
        entry = create_proc_entry("knamed/version", 0, NULL);
        if (entry) {
            entry->proc_fops = &knamed_version_operations;
        }

        entry = create_proc_entry("knamed/buffer", 0, NULL);
        if (entry) {
            entry->proc_fops = &knamed_buffer_operations;
            sz = sizeof(unsigned long) * knamed_page_number;
            knamed_pages = (unsigned long *) kmalloc(sz, GFP_KERNEL);
            if (knamed_pages == NULL) {
                goto failed;
            }

            memset(knamed_pages, 0, sz);

            for (i = 0; i < knamed_page_number; i++) {
                knamed_pages[i] = get_zeroed_page(GFP_KERNEL);
                if (knamed_pages[i] == 0) {
                    goto failed;
                }
            }

            memcpy((char *) knamed_pages[7], "Hello world fuck page 7", 30);
        }
    }

    return;

failed:

    (void) remove_proc_entry("knamed/buffer", NULL);
    (void) remove_proc_entry("knamed/version", NULL);
    (void) remove_proc_entry("knamed", NULL);

    if (knamed_pages != NULL) {
        for (i = 0; i < knamed_page_number; i++) {
            if (knamed_pages[i] != 0) {
                free_page(knamed_pages[i]);
            }
        }

        kfree(knamed_pages);
    }
}


void
knamed_procfs_release(void)
{
    int  i;

    (void) remove_proc_entry("knamed/buffer", NULL);
    (void) remove_proc_entry("knamed/version", NULL);
    (void) remove_proc_entry("knamed", NULL);

    for (i = 0; i < knamed_page_number; i++) {
        if (knamed_pages[i] != 0) {
            free_page(knamed_pages[i]);
        }
    }

    kfree(knamed_pages);
}


#else

#error "CONFIG_PROC_FS needed by knamed"

#endif /* CONFIG_PROC_FS */

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


#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "knamed.h"


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


static struct file_operations knamed_version_operations = {
    .open = knamed_version_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};


void
knamed_procfs_init(void)
{
#ifdef CONFIG_PROC_FS
    struct proc_dir_entry  *entry;

    if (proc_mkdir("knamed", NULL)) {
        entry = create_proc_entry("knamed/version", 0, NULL);
        if (entry) {
            entry->proc_fops = &knamed_version_operations;
        }
    }
#endif /* CONFIG_PROC_FS */
}


void
knamed_procfs_release(void)
{
#ifdef CONFIG_PROC_FS
    (void) remove_proc_entry("knamed/version", NULL);
    (void) remove_proc_entry("knamed", NULL);
#endif /* CONFIG_PROC_FS */
}

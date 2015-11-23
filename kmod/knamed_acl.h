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


#ifndef __KNAMED_ACL_H_INCLUDED__
#define __KNAMED_ACL_H_INCLUDED__


#define HASH_BUCKET_SIZE    256


struct acl_slot {
    struct list_head   list;
    uint32_t           addr;
    void              *value;
};


struct acl_hash {
    struct list_head  *bucket;
};


struct acl_table {
    struct acl_hash  hash[33];
};


struct acl_slot *acl_find(struct acl_table *acl, uint32_t addr);
int acl_add(struct acl_table *acl, uint32_t addr, int mask, void *value);
struct acl_table *acl_create(void);
void acl_destroy(struct acl_table *acl, void (*value_free)(void *value));
void acl_dump(struct acl_table *acl);


#endif /* __KNAMED_ACL_H_INCLUDED__ */

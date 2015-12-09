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


#ifndef __KNAMED_RADIX_H_INCLUDED__
#define __KNAMED_RADIX_H_INCLUDED__


typedef struct knamed_radix_node  knamed_radix_node_t;


typedef struct knamed_radix_array {
    /* additional string after the selection-byte for this edge. */
    uint8_t              *str;
    /* length of the additional string for this edge */
    uint16_t              len;
    /* node that deals with byte+str */
    knamed_radix_node_t  *node;
} knamed_radix_array_t;


struct knamed_radix_node {
    /* data element associated with the binary string up to this node */
    void                  *elem;
    /* parent node (NULL for root) */
    knamed_radix_node_t   *parent;
    /* index in the parent lookup array */
    uint8_t                pidx;
    /* offset of the lookup array, add to [i] for lookups */
    uint8_t                offset;
    /* length of the lookup array */
    uint16_t               len;
    /* capacity of the lookup array (can be larger than length) */
    uint16_t               capacity;
    /* the lookup array by [byte-offset] */
    knamed_radix_array_t  *array;
};


typedef struct knamed_radix {
    knamed_radix_node_t  *root;
    size_t                count;
} knamed_radix_t;


knamed_radix_t *knamed_radix_create(void);
void knamed_radix_init(knamed_radix_t *rt);
void knamed_radix_release(knamed_radix_t *rt);
void knamed_radix_destroy(knamed_radix_t *rt);
int knamed_radix_insert(knamed_radix_t *rt, uint8_t *key, uint16_t len,
    void *elem);
void *knamed_radix_delete(knamed_radix_t *rt, uint8_t *key, uint16_t len);
knamed_radix_node_t *knamed_radix_search(knamed_radix_t *rt, uint8_t *key,
    uint16_t len);
int knamed_radix_find_less_equal(knamed_radix_t *rt, uint8_t *key, uint16_t len,
    knamed_radix_node_t **result);
knamed_radix_node_t *knamed_radix_first(knamed_radix_t *rt);
knamed_radix_node_t *knamed_radix_last(knamed_radix_t *rt);
knamed_radix_node_t *knamed_radix_next(knamed_radix_node_t *node);
knamed_radix_node_t *knamed_radix_prev(knamed_radix_node_t *node);


void knamed_radix_traverse_postorder(knamed_radix_node_t *node,
    void (*func)(knamed_radix_node_t *, void *), void *arg);
knamed_radix_node_t *knamed_radix_search(knamed_radix_t *rt, uint8_t *key,
    uint16_t len);


#endif /* __KNAMED_RADIX_H_INCLUDED__ */

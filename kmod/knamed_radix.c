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


#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "knamed.h"
#include "knamed_memory.h"
#include "knamed_radix.h"


static knamed_radix_node_t *knamed_radix_new_node(void *elem);
static int knamed_radix_find_prefix(knamed_radix_t *rt, uint8_t *key,
    uint16_t len, knamed_radix_node_t **result, uint16_t *respos);
static int knamed_radix_array_space(knamed_radix_node_t *n, uint8_t byte);
static int knamed_radix_array_grow(knamed_radix_node_t *n, uint16_t want);
static int knamed_radix_str_create(knamed_radix_array_t *r, uint8_t *key,
    uint16_t pos, uint16_t len);
static int knamed_radix_prefix_remainder(uint16_t plen, uint8_t *l,
    uint16_t llen, uint8_t **s, uint16_t *slen);
static int knamed_radix_array_split(knamed_radix_array_t *r, uint8_t *key,
    uint16_t pos, uint16_t len, knamed_radix_node_t *add);
static int knamed_radix_str_is_prefix(uint8_t *p, uint16_t plen, uint8_t *x,
    uint16_t xlen);
static uint16_t knamed_radix_str_common(uint8_t *x, uint16_t xlen, uint8_t *y,
    uint16_t ylen);
static knamed_radix_node_t *knamed_radix_next_in_subtree(
    knamed_radix_node_t *node);
static knamed_radix_node_t *knamed_radix_prev_from_index(
    knamed_radix_node_t *node, uint8_t index);
static knamed_radix_node_t *knamed_radix_last_in_subtree_incl_self(
    knamed_radix_node_t *node);
static knamed_radix_node_t *knamed_radix_last_in_subtree(
    knamed_radix_node_t *node);
static void knamed_radix_cleanup_onechild(knamed_radix_node_t *node);
static void knamed_radix_cleanup_leaf(knamed_radix_node_t *node);
static void knamed_radix_node_free(knamed_radix_node_t *node, void *arg);
static void knamed_radix_node_array_free(knamed_radix_node_t *node);
static void knamed_radix_node_array_free_front(knamed_radix_node_t *node);
static void knamed_radix_node_array_free_end(knamed_radix_node_t *node);
static void knamed_radix_array_reduce(knamed_radix_node_t *node);
static void knamed_radix_self_or_prev(knamed_radix_node_t *node,
    knamed_radix_node_t **result);
static void knamed_radix_del_fix(knamed_radix_t *rt, knamed_radix_node_t *node);


static knamed_radix_node_t *
knamed_radix_new_node(void *elem)
{
    knamed_radix_node_t  *node;

    node = knamed_memory_alloc(sizeof(knamed_radix_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->elem = elem;
    node->parent = NULL;
    node->pidx = 0;
    node->len = 0;
    node->offset = 0;
    node->capacity = 0;
    node->array = NULL;

    return node;
}


knamed_radix_t *
knamed_radix_create(void)
{
    knamed_radix_t  *rt;

    rt = knamed_memory_alloc(sizeof(knamed_radix_t));
    if (rt == NULL) {
        return NULL;
    }

    knamed_radix_init(rt);

    return rt;
}


void
knamed_radix_init(knamed_radix_t *rt)
{
    if (rt != NULL) {
        rt->root = NULL;
        rt->count = 0;
    }
}


void
knamed_radix_release(knamed_radix_t *rt)
{
    if (rt != NULL) {
        if (rt->root != NULL) {
            knamed_radix_traverse_postorder(rt->root, knamed_radix_node_free,
                                            NULL);
        }
    }
}


void
knamed_radix_destroy(knamed_radix_t *rt)
{
    if (rt != NULL) {
        knamed_radix_release(rt);
        knamed_memory_free(rt);
    }
}


int
knamed_radix_insert(knamed_radix_t *rt, uint8_t *key, uint16_t len, void *elem)
{
    uint8_t               byte;
    knamed_radix_node_t  *n, *add;
    uint16_t              pos;

    add = knamed_radix_new_node(elem);
    if (add == NULL) {
        return -ENOMEM;
    }

    if (knamed_radix_find_prefix(rt, key, len, &n, &pos) == 0) {
        /* new root */
        if (len == 0) {
            rt->root = add;
        } else {
            n = knamed_radix_new_node(NULL);
            if (n == NULL) {
                knamed_memory_free(add);
                return -ENOMEM;
            }

            if (knamed_radix_array_space(n, key[0]) < 0) {
                knamed_memory_free(add);
                knamed_memory_free(n->array);
                knamed_memory_free(n);
                return -ENOMEM;
            }

            add->parent = n;
            add->pidx = 0;
            n->array[0].node = add;

            if (len > 1) {
                if (knamed_radix_prefix_remainder(1, key, len,
                                                  &n->array[0].str,
                                                  &n->array[0].len)
                    < 0)
                {
                    knamed_memory_free(add);
                    knamed_memory_free(n->array);
                    knamed_memory_free(n);
                    return -ENOMEM;
                }
            }

            rt->root = n;
        }

    } else if (pos == len) {
        /* found an exact match */
        if (n->elem) {
            /* already exists, failure */
            knamed_memory_free(add);
            return -EEXIST;
        }

        n->elem = elem;
        knamed_memory_free(add);
    } else {
        /* prefix found */
        BUG_ON(pos >= len);

        byte = key[pos];

        if (byte < n->offset || byte - n->offset >= n->len) {
            /* make space in the array for it; adjusts offset */
            if (knamed_radix_array_space(n, byte) < 0) {
                knamed_memory_free(add);
                return -ENOMEM;
            }

            byte -= n->offset;

            /* see if more prefix needs to be split off */
            if (pos + 1 < len) {
                if (knamed_radix_str_create(&n->array[byte], key, pos + 1, len)
                    < 0)
                {
                    knamed_memory_free(add);
                    return -ENOMEM;
                }
            }

            add->parent = n;
            add->pidx = byte;
            n->array[byte].node = add;

        } else if (n->array[byte - n->offset].node == NULL) {
            byte -= n->offset;
            if (pos + 1 < len) {
                if (knamed_radix_str_create(&n->array[byte], key, pos + 1, len)
                    < 0)
                {
                    knamed_memory_free(add);
                    return -ENOMEM;
                }
            }

            add->parent = n;
            add->pidx = byte;
            n->array[byte].node = add;

        } else {
            /* use existing bucket, but it has a shared prefix, need a split */
            if (knamed_radix_array_split(&n->array[byte - n->offset],
                                         key, pos + 1, len, add)
                < 0)
            {
                knamed_memory_free(add);
                return -ENOMEM;
            }
        }
    }

    rt->count++;
    return 0;
}


void *
knamed_radix_delete(knamed_radix_t *rt, uint8_t *key, uint16_t len)
{
    void                 *elem;
    knamed_radix_node_t  *node;

    node = knamed_radix_search(rt, key, len);

    if (node) {
        rt->count--;
        elem = node->elem;
        node->elem = NULL;
        knamed_radix_del_fix(rt, node);
        return elem;
    }

    return NULL;
}


knamed_radix_node_t *
knamed_radix_search(knamed_radix_t *rt, uint8_t *key, uint16_t len)
{
    knamed_radix_node_t  *n;
    uint16_t              pos;
    uint8_t               byte;

    pos = 0;
    n = rt->root;

    while (n) {
        if (pos == len) {
            return n->elem ? n : NULL;
        }

        byte = key[pos];
        if (byte < n->offset) {
            return NULL;
        }

        byte -= n->offset;
        if (byte >= n->len) {
            return NULL;
        }

        pos++;
        if (n->array[byte].len != 0) {
            if (pos + n->array[byte].len > len) {
                return NULL;
            }

            if (memcmp(&key[pos], n->array[byte].str, n->array[byte].len) != 0)
            {
                return NULL;
            }
            pos += n->array[byte].len;
        }

        n = n->array[byte].node;
    }

    return NULL;
}


/* search data in tree, and if not found, return the closest smaller element */
int
knamed_radix_find_less_equal(knamed_radix_t *rt, uint8_t *key, uint16_t len,
    knamed_radix_node_t **result)
{
    knamed_radix_node_t  *n;
    uint16_t              pos;
    uint8_t               byte;
    int                   r;

    n = rt->root;
    pos = 0;

    if (rt == NULL || n == NULL || key == NULL) {
        *result = NULL;
        return 0;
    }

    while (pos < len) {
        byte = key[pos];
        if (byte < n->offset) {
            /* the lesser is in this or the previous node */
            knamed_radix_self_or_prev(n, result);
            return 0;
        }

        byte -= n->offset;
        if (byte >= n->len) {
            /* the lesser is in this node or the last of this array, or
             * something before this node */
            *result = knamed_radix_last_in_subtree_incl_self(n);
            if (*result == NULL) {
                *result = knamed_radix_prev(n);
            }
            return 0;
        }

        pos++;
        if (n->array[byte].node == NULL) {
            /* find the previous in the array from this index */
            *result = knamed_radix_prev_from_index(n, byte);
            if (*result == NULL) {
                knamed_radix_self_or_prev(n, result);
            }
            return 0;
        }

        if (n->array[byte].len != 0) {
            if (pos + n->array[byte].len > len) {
                /* addtional string is longer than key */
                if ((memcmp(&key[pos], n->array[byte].str, len - pos)) <= 0) {
                    /* key is before this node */
                    *result = knamed_radix_prev(n->array[byte].node);
                } else {
                    /* key is after additional string */
                    *result = knamed_radix_last_in_subtree_incl_self(
                                                           n->array[byte].node);
                    if (*result == NULL) {
                        *result = knamed_radix_prev(n->array[byte].node);
                    }
                }

                return 0;
            }

            r = memcmp(&key[pos], n->array[byte].str, n->array[byte].len);
            if (r < 0) {
                *result = knamed_radix_prev(n->array[byte].node);
                return 0;
            } else if (r > 0) {
                *result = knamed_radix_last_in_subtree_incl_self(
                                                           n->array[byte].node);
                if (*result == NULL) {
                    *result = knamed_radix_prev(n->array[byte].node);
                }
                return 0;
            }

            pos += n->array[byte].len;
        }

        n = n->array[byte].node;
    }

    if (n->elem) {
        /* exact match */
        *result = n;
        return 1;
    }

    /* there is a node which is an exact match, but it has no element */
    *result = knamed_radix_prev(n);
    return 0;
}


knamed_radix_node_t *
knamed_radix_first(knamed_radix_t *rt)
{
    knamed_radix_node_t  *first;
    if (rt == NULL || rt->root == NULL) {
        return NULL;
    }

    first = rt->root;
    if (first->elem) {
        return first;
    }

    return knamed_radix_next(first);
}


knamed_radix_node_t *
knamed_radix_last(knamed_radix_t *rt)
{
    if (rt == NULL || rt->root == NULL) {
        return NULL;
    }

    return knamed_radix_last_in_subtree_incl_self(rt->root);
}


knamed_radix_node_t *
knamed_radix_next(knamed_radix_node_t *node)
{
    uint8_t               index;
    knamed_radix_node_t  *next;

    if (node == NULL) {
        return NULL;
    }

    if (node->len) {
        /* go down: most-left child is the next */
        next = knamed_radix_next_in_subtree(node);
        if (next) {
            return next;
        }
    }

    /* no element in subtree, get to parent and go down next branch */
    while (node->parent) {
        index = node->pidx;
        node = node->parent;

        index++;
        for ( ; index < node->len; index++) {
            if (node->array[index].node) {
                if (node->array[index].node->elem) {
                    /* node itself */
                    return node->array[index].node->elem;
                }

                /* dive into subtree */
                next = knamed_radix_next_in_subtree(node);
                if (next) {
                    return next;
                }
            }
        }
    }

    return NULL;
}


knamed_radix_node_t *
knamed_radix_prev(knamed_radix_node_t *node)
{
    uint8_t               index;
    knamed_radix_node_t  *prev;

    if (node == NULL) {
        return NULL;
    }

    /* get to parent and go down previous branch */
    while (node->parent) {
        index = node->pidx;
        node = node->parent;
        prev = knamed_radix_prev_from_index(node, index);
        if (prev) {
            return prev;
        }

        if (node->elem) {
            return node;
        }
    }

    return NULL;
}


void
knamed_radix_traverse_postorder(knamed_radix_node_t *node,
    void (*func)(knamed_radix_node_t *, void *), void *arg)
{
    uint8_t  i;

    if (node == NULL) {
        return;
    }

    for (i = 0; i < node->len; i++) {
        knamed_radix_traverse_postorder(node->array[i].node, func, arg);
    }

    (*func)(node, arg);
}



/*
 * Find a prefix of the key.
 *
 * @result: the longest prefix, the entry itself if *respos == len,
 *          otherwise an array entry.
 *
 * @respos: position in string where next unmatched byte is.
 *          If *respos == len, an exact match was found.
 *          If *respos == 0, a "" match was found.
 */
static int
knamed_radix_find_prefix(knamed_radix_t *rt, uint8_t *key, uint16_t len,
    knamed_radix_node_t **result, uint16_t *respos)
{
    knamed_radix_node_t  *n;
    uint16_t              pos;
    uint8_t               byte;

    n = rt->root;
    pos = 0;
    *respos = 0;
    *result = n;

    if (n == NULL) {
        return 0;
    }

    /* for each node, look if we can make further progress */
    while (n) {
        if (pos == len) {
            return 1;
        }

        byte = key[pos];
        if (byte < n->offset) {
            return 1;
        }

        byte -= n->offset;
        if (byte >= n->len) {
            return 1;
        }

        /* so far, the trie matches */
        pos++;

        if (n->array[byte].len != 0) {
            /* must match addtional string */
            if (pos + n->array[byte].len > len) {
                return 1;
            }

            if (memcmp(&key[pos], n->array[byte].str, n->array[byte].len) != 0)
            {
                return 1;
            }

            pos += n->array[byte].len;
        }

        /* continue searching prefix at this child node */
        n = n->array[byte].node;
        if (n == NULL) {
            return 1;
        }

        /* update the prefix node */
        *respos = pos;
        *result = n;
    }

    return 1;
}


/* make space in the node's array for another byte */
static int
knamed_radix_array_space(knamed_radix_node_t *n, uint8_t byte)
{
    uint8_t  i, needed;

    if (n->array == NULL) {
        /* no array */
        BUG_ON(n->capacity != 0);

        n->array = (knamed_radix_array_t *) knamed_memory_zalloc(
                                                  sizeof(knamed_radix_array_t));
        if (n->array == NULL) {
            return -ENOMEM;
        }

        n->len = 1;
        n->capacity = 1;
        n->offset = byte;

        return 0;
    }

    if (n->len == 0) {
        /* array unused */
        n->len = 1;
        n->offset = byte;

    } else if (byte < n->offset) {
        needed = n->offset - byte;

        if (n->len + needed > n->capacity) {
            if (knamed_radix_array_grow(n, n->len + needed) < 0) {
                return -ENOMEM;
            }
        }

        memmove(&n->array[needed], &n->array[0],
                n->len * sizeof(knamed_radix_array_t));

        /* fix parent index */
        for (i = 0; i < n->len; i++) {
            if (n->array[i + needed].node) {
                n->array[i + needed].node->pidx = i + needed;
            }
        }

        /* zero the first */
        memset(&n->array[0], 0, needed * sizeof(knamed_radix_array_t));
        n->len += needed;
        n->offset = byte;

    } else if (byte - n->offset >= n->len) {
        /* above the max */
        needed = (byte - n->offset) - n->len + 1;
        if (n->len + needed > n->capacity) {
            if (knamed_radix_array_grow(n, n->len + needed) < 0) {
                return -ENOMEM;
            }
        }

        /* zero added entries */
        memset(&n->array[n->len], 0, needed * sizeof(knamed_radix_array_t));
        n->len += needed;
    }

    return 0;
}


/* grow array to at lease the given size, offset unchanged */
static int
knamed_radix_array_grow(knamed_radix_node_t *n, uint16_t want)
{
    uint16_t               ns;
    knamed_radix_array_t  *a;

    BUG_ON(want > 256);

    ns = n->capacity * 2;

    if (want > ns) {
        ns = want;
    }

    a = (knamed_radix_array_t *) knamed_memory_alloc(
                                             ns * sizeof(knamed_radix_array_t));
    if (a == NULL) {
        return -ENOMEM;
    }

    memcpy(&a[0], &n->array[0], n->len * sizeof(knamed_radix_array_t));

    knamed_memory_free(n->array);
    n->array = a;
    n->capacity = ns;

    return 0;
}


static int
knamed_radix_str_create(knamed_radix_array_t *r, uint8_t *key, uint16_t pos,
    uint16_t len)
{
    r->str = (uint8_t *) knamed_memory_alloc(sizeof(uint8_t) * (len - pos));
    if (r->str == NULL) {
        return -ENOMEM;
    }

    memmove(r->str, key + pos, len - pos);
    r->len = len - pos;
    return 0;
}


/* allocate remainder from prefixes for a split:
 * @plen: len prefix,
 * @l: longer string,
 * @llen: length of l,
 */
static int
knamed_radix_prefix_remainder(uint16_t plen, uint8_t *l, uint16_t llen,
    uint8_t **s, uint16_t *slen)
{
    *slen = llen - plen;
    *s = (uint8_t *) knamed_memory_alloc(sizeof(uint8_t) * (*slen));
    if (*s == NULL) {
        return -ENOMEM;
    }

    memmove(*s, l + plen, llen - plen);
    return 0;
}


static int
knamed_radix_array_split(knamed_radix_array_t *r, uint8_t *key, uint16_t pos,
    uint16_t len, knamed_radix_node_t *add)
{
    uint8_t              *addstr, *split_str, *dupstr;
    uint8_t              *common_str, *s1_str, *s2_str;
    uint16_t              addlen, split_len, common_len, s1_len, s2_len;
    knamed_radix_node_t  *com;

    addstr = key + pos;
    addlen = len - pos;
    split_str = NULL;
    dupstr = NULL;
    split_len = 0;

    if (knamed_radix_str_is_prefix(addstr, addlen, r->str, r->len)) {
        /* 'add' is a prefix of the existing string */

        if (r->len - addlen > 1) {
            /* shift one because a char is in the lookup array */
            if (knamed_radix_prefix_remainder(addlen + 1, r->str, r->len,
                                              &split_str, &split_len)
                < 0)
            {
                return -ENOMEM;
            }
        }

        if (addlen != 0) {
            dupstr = (uint8_t *) knamed_memory_alloc(sizeof(uint8_t) * addlen);
            if (dupstr == NULL) {
                knamed_memory_free(split_str);
                return -ENOMEM;
            }
            memcpy(dupstr, addstr, addlen);
        }

        if (knamed_radix_array_space(add, r->str[addlen]) < 0) {
            knamed_memory_free(split_str);
            knamed_memory_free(dupstr);
            return -ENOMEM;
        }

        /* alloc succeeded, now link it in */
        add->parent = r->node->parent;
        add->pidx = r->node->pidx;
        add->array[0].node = r->node;
        add->array[0].str = split_str;
        add->array[0].len = split_len;
        r->node->parent = add;
        r->node->pidx = 0;

        r->node = add;
        knamed_memory_free(r->str);
        r->str = dupstr;
        r->len = addlen;

    } else if (knamed_radix_str_is_prefix(r->str, r->len, addstr, addlen)) {
        /* the existing string is a prefix of the string to add */
        if (addlen - r->len > 1) {
            if (knamed_radix_prefix_remainder(r->len + 1, addstr, addlen,
                                              &split_str, &split_len)
                < 0)
            {
                knamed_memory_free(split_str);
                return -ENOMEM;
            }
        }

        if (knamed_radix_array_space(r->node, addstr[r->len]) < 0) {
            knamed_memory_free(split_str);
            return -ENOMEM;
        }

        add->parent = r->node;
        add->pidx = addstr[r->len] - r->node->offset;
        r->node->array[add->pidx].node = add;
        r->node->array[add->pidx].str = split_str;
        r->node->array[add->pidx].len = split_len;

    } else {
        /* create a new split node. */

        common_len = knamed_radix_str_common(r->str, r->len, addstr, addlen);

        com = knamed_radix_new_node(NULL);
        if (com == NULL) {
            return -ENOMEM;
        }

        if (r->len - common_len > 1) {
            /* shift by one char because it goes in lookup array */
            if (knamed_radix_prefix_remainder(common_len + 1, r->str, r->len,
                                              &s1_str, &s1_len)
                < 0)
            {
                knamed_memory_free(com);
                return -ENOMEM;
            }
        }

        if (addlen - common_len > 1) {
            if (knamed_radix_prefix_remainder(common_len + 1, addstr, addlen,
                                              &s2_str, &s2_len)
                < 0)
            {
                knamed_memory_free(com);
                knamed_memory_free(s1_str);
                return -ENOMEM;
            }
        }

        /* create the shared prefix */
        if (common_len > 0) {
            common_str = (uint8_t *) knamed_memory_alloc(
                                                  common_len * sizeof(uint8_t));
            if (common_str == NULL) {
                knamed_memory_free(com);
                knamed_memory_free(s1_str);
                knamed_memory_free(s2_str);
                return -ENOMEM;
            }
            memcpy(common_str, addstr, common_len);
        }

        /* make space in the common node array */
        if (knamed_radix_array_space(com, r->str[common_len]) < 0
            || knamed_radix_array_space(com, addstr[common_len]) < 0)
        {
            knamed_memory_free(com->array);
            knamed_memory_free(com);
            knamed_memory_free(common_str);
            knamed_memory_free(s1_str);
            knamed_memory_free(s2_str);
            return -ENOMEM;
        }

        /* The common node should go directly under the parent node.
         * The added and existing nodes go under the common node */
        com->parent = r->node->parent;
        com->pidx = r->node->pidx;
        r->node->parent = com;
        r->node->pidx = r->str[common_len] - com->offset;
        add->parent = com;
        add->pidx = addstr[common_len] - com->offset;
        com->array[r->node->pidx].node = r->node;
        com->array[r->node->pidx].str = s1_str;
        com->array[r->node->pidx].len = s1_len;
        com->array[add->pidx].node = add;
        com->array[add->pidx].str = s2_str;
        com->array[add->pidx].len = s2_len;

        knamed_memory_free(r->str);
        r->str = common_str;
        r->len = common_len;
        r->node = com;
    }

    return 0;
}


static int
knamed_radix_str_is_prefix(uint8_t *p, uint16_t plen, uint8_t *x, uint16_t xlen)
{
    if (plen == 0) {
        return 1;
    }

    if (plen > xlen) {
        return 0;
    }

    return (memcmp(p, x, plen) == 0);
}


static uint16_t
knamed_radix_str_common(uint8_t *x, uint16_t xlen, uint8_t *y, uint16_t ylen)
{
    uint16_t  i, max;

    max = (xlen < ylen) ? xlen : ylen;
    for (i = 0; i < max; i++) {
        if (x[i] != y[i]) {
            return i;
        }
    }

    return max;
}


static knamed_radix_node_t *
knamed_radix_next_in_subtree(knamed_radix_node_t *node)
{
    uint16_t              i;
    knamed_radix_node_t  *next;

    for (i = 0; i < node->len; i++) {
        if (node->array[i].node) {
            if (node->array[i].node->elem) {
                return node->array[i].node;
            }

            /* dive into subtree */
            next = knamed_radix_next_in_subtree(node->array[i].node);
            if (next) {
                return next;
            }
        }
    }

    return NULL;
}


static knamed_radix_node_t *
knamed_radix_prev_from_index(knamed_radix_node_t *node, uint8_t index)
{
    knamed_radix_node_t  *prev;
    uint8_t               i = index;

    while (i > 0) {
        i--;
        if (node->array[i].node) {
            prev = knamed_radix_last_in_subtree_incl_self(node);
            if (prev) {
                return prev;
            }
        }
    }

    return NULL;
}


/* find last node in subtree or this node if have element with it */
static knamed_radix_node_t *
knamed_radix_last_in_subtree_incl_self(knamed_radix_node_t *node)
{
    knamed_radix_node_t  *last = knamed_radix_last_in_subtree(node);

    if (last) {
        return last;
    } else if (node->elem) {
        return node;
    }

    return NULL;
}


/* find last node in subtree */
static knamed_radix_node_t *
knamed_radix_last_in_subtree(knamed_radix_node_t *node)
{
    int  i;
    knamed_radix_node_t  *last;

    for (i = node->len - 1; i >= 0; i--) {
        if (node->array[i].node) {
            /* keep looking for the most right leaf node. */
            if (node->array[i].node->len > 0) {
                last = knamed_radix_last_in_subtree(node->array[i].node);
                if (last) {
                    return last;
                }
            }
        }

        if (node->array[i].node->elem) {
            return node->array[i].node;
        }
    }

    return NULL;
}


static void
knamed_radix_del_fix(knamed_radix_t *rt, knamed_radix_node_t *node)
{
    knamed_radix_node_t  *parent;

    while (node) {
        if (node->elem) {
            /* don't delete nodes with element attached */
            return;
        } else if (node->len == 1 && node->parent) {
            /* node with one child is fold back into */
            knamed_radix_cleanup_onechild(node);
            return;
        } else if (node->len == 0) {
            /* leaf node */
            parent = node->parent;
            if (parent == NULL) {
                knamed_radix_node_free(node, NULL);
                rt->root = NULL;
                return;
            }

            knamed_radix_cleanup_leaf(node);
            node = parent;
        } else {
            /* node cannot be deleted, because it has edge nodes
             * and no parent to fix up to. */
            return;
        }
    }
}


/* clean up a node with one child */
static void
knamed_radix_cleanup_onechild(knamed_radix_node_t *node)
{
    uint8_t              *join_str;
    uint16_t              join_len;
    uint8_t               pidx = node->pidx;
    knamed_radix_node_t  *child = node->array[0].node;
    knamed_radix_node_t  *parent = node->parent;

    join_len = parent->array[pidx].len + node->array[0].len + 1;

    join_str = knamed_memory_alloc(sizeof(uint8_t) * join_len);
    if (join_str == NULL) {
        return;
    }

    memcpy(join_str, parent->array[pidx].str, parent->array[pidx].len);
    join_str[parent->array[pidx].len] = child->pidx + node->offset;

    memmove(join_str + parent->array[pidx].len + 1, node->array[0].str,
            node->array[0].len);

    knamed_memory_free(parent->array[pidx].str);

    parent->array[pidx].str = join_str;
    parent->array[pidx].len = join_len;
    parent->array[pidx].node = child;
    child->parent = parent;
    child->pidx = pidx;
    knamed_radix_node_free(node, NULL);
}


static void
knamed_radix_cleanup_leaf(knamed_radix_node_t *node)
{
    uint8_t               pidx = node->pidx;
    knamed_radix_node_t  *parent = node->parent;

    knamed_radix_node_free(node, NULL);
    knamed_memory_free(parent->array[pidx].str);
    parent->array[pidx].str = NULL;
    parent->array[pidx].len = 0;
    parent->array[pidx].node = NULL;

    if (parent->len == 1) {
        knamed_radix_node_array_free(parent);
    } else if (pidx == 0) {
        knamed_radix_node_array_free_front(parent);
    } else {
        knamed_radix_node_array_free_end(parent);
    }
}


static void
knamed_radix_node_free(knamed_radix_node_t *node, void *arg)
{
    uint16_t  i;

    if (node == NULL) {
        return;
    }

    for (i = 0; i < node->len; i++) {
        knamed_memory_free(node->array[i].str);
    }

    knamed_memory_free(node->array);
    knamed_memory_free(node);
}


static void
knamed_radix_node_array_free(knamed_radix_node_t *node)
{
    node->offset = 0;
    node->len = 0;
    knamed_memory_free(node->array);
    node->array = NULL;
    node->capacity = 0;
}


static void
knamed_radix_node_array_free_front(knamed_radix_node_t *node)
{
    uint16_t  i, n = 0;

    while (n < node->len && node->array[n].node == NULL) {
        n++;
    }

    if (n == 0) {
        return;
    }

    if (n == node->len) {
        knamed_radix_node_array_free(node);
        return;
    }

    memmove(&node->array[0], &node->array[n],
            (node->len - n) * sizeof(knamed_radix_array_t));

    node->offset += n;
    node->len -= n;

    for (i = 0; i < node->len; i++) {
        if (node->array[i].node) {
            node->array[i].node->pidx = i;
        }
    }

    knamed_radix_array_reduce(node);
}


static void
knamed_radix_node_array_free_end(knamed_radix_node_t *node)
{
    uint16_t  n = 0;

    while (n < node->len && node->array[node->len - 1 - n].node == NULL) {
        n++;
    }

    if (n == 0) {
        return;
    }

    if (n == node->len) {
        knamed_radix_node_array_free(node);
        return;
    }

    node->len -= n;
    knamed_radix_array_reduce(node);
}


static void
knamed_radix_array_reduce(knamed_radix_node_t *node)
{
    knamed_radix_array_t  *a;
    if (node->len <= node->capacity / 2 && node->len != node->capacity) {
        a = knamed_memory_alloc(sizeof(knamed_radix_array_t) * node->len);
        if (a == NULL) {
            return;
        }

        memcpy(a, node->array, sizeof(knamed_radix_array_t) * node->len);
        knamed_memory_free(node->array);
        node->array = a;
        node->capacity = node->len;
    }
}


static void
knamed_radix_self_or_prev(knamed_radix_node_t *node,
    knamed_radix_node_t **result)
{
    if (node->elem) {
        *result = node;
    } else {
        *result = knamed_radix_prev(node);
    }
}

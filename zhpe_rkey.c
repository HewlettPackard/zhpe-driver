/*
 * Copyright (C) 2018 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Generation of random R-keys */

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/random.h>
#include <linux/rbtree_augmented.h>
#include "zhpe.h"
#include "zhpe_driver.h"

#define RKEY_RAND_BYTES  (((RKEY_RKD_SHIFT + 7) & ~7) / 8)
#define RKEY_BITMAP_SZ   256
#define RKEY_BASE_MASK   (~(RKEY_BITMAP_SZ - 1))
#define RKEY_DEBUG_ALLOC 20
#define RKEY_DEBUG_ALL   (RKEY_DEBUG_ALLOC <= 100)

#define RKEY_RO_RKD      2  /* Revisit: replace with fabric manager values */
#define RKEY_RW_RKD      3
#define rkn_count(_rkn)  bitmap_weight((_rkn)->bitmap, RKEY_BITMAP_SZ)

struct rkey_info {
    atomic_t       allocated;
    struct rb_root rbtree;
    spinlock_t     rk_lock;
};

struct rkey_node {
    struct rb_node rb;
    DECLARE_BITMAP(bitmap, RKEY_BITMAP_SZ);
    uint32_t rkey_base;
    uint32_t count;
};

static struct rkey_info rki;

void zhpe_rkey_init(void)
{
    atomic_set(&rki.allocated, 0);
    rki.rbtree = RB_ROOT;
    spin_lock_init(&rki.rk_lock);
    /* Revisit: debug */
    {
        int i;
        uint32_t ro_rkey, rw_rkey;

        debug(DEBUG_RKEYS, "%s:%s,%u: RKEY_TOTAL=%ld, RKEY_RAND_BYTES=%d, RKEY_BASE_MASK=0x%x, RKEY_DEBUG_ALLOC=%d\n",
              zhpe_driver_name, __func__, __LINE__,
              RKEY_TOTAL, RKEY_RAND_BYTES, RKEY_BASE_MASK, RKEY_DEBUG_ALLOC);
        for (i = 0; i < RKEY_DEBUG_ALLOC; i++)
            zhpe_rkey_alloc(&ro_rkey, &rw_rkey);

        zhpe_rkey_print_all();
    }
}

void zhpe_rkey_exit(void)
{
    struct rb_node *rb, *next;
    ulong flags;

    /* free all leftover rkey nodes */
    spin_lock_irqsave(&rki.rk_lock, flags);
    for (rb = rb_first_postorder(&rki.rbtree); rb; rb = next) {
        struct rkey_node *rkn = rb_entry(rb, struct rkey_node, rb);

        debug(DEBUG_RKEYS, "%s:%s,%u:rkey_base=0x%05x, rkn_count=%u\n",
              zhpe_driver_name, __func__, __LINE__,
              rkn->rkey_base, rkn_count(rkn));
        next = rb_next_postorder(rb);  /* must precede kfree() */
        do_kfree(rkn);
    }

    atomic_set(&rki.allocated, 0);
    rki.rbtree = RB_ROOT;
    spin_unlock_irqrestore(&rki.rk_lock, flags);
}

static inline uint32_t compute_subtree_count(struct rkey_node *rkn)
{
    uint32_t count = rkn_count(rkn);

    if (rkn->rb.rb_left)
        count += rb_entry(rkn->rb.rb_left, struct rkey_node, rb)->count;
    if (rkn->rb.rb_right)
        count += rb_entry(rkn->rb.rb_right, struct rkey_node, rb)->count;

    return count;
}

RB_DECLARE_CALLBACKS(static, augment_callbacks, struct rkey_node, rb,
                     uint32_t, count, compute_subtree_count);

#ifdef REVISIT
/* Revisit: delete this, or change rkey_delete to use it */
static struct rkey_node *rkey_search(struct rkey_info *rki, uint32_t rkey)
{
    struct rkey_node *rkn;
    struct rb_node *rb;
    struct rb_root *root = &rki->rbtree;
    uint32_t rkey_base, bit_pos;
    ulong flags;

    rkey &= RKEY_OS_MASK;
    rkey_base = rkey & RKEY_BASE_MASK;
    bit_pos = rkey & ~RKEY_BASE_MASK;
    spin_lock_irqsave(&rki->rk_lock, flags);
    rb = root->rb_node;

    while (rb) {
        rkn = rb_entry(rb, struct rkey_node, rb);
        if (rkey_base < rkn->rkey_base)
            rb = rb->rb_left;
        else if (rkey_base >= (rkn->rkey_base + RKEY_BITMAP_SZ))
            rb = rb->rb_right;
        else {
            /* found right node - check bitmap bit */
            if (test_bit(bit_pos, rkn->bitmap) == 1)
                goto out;
            else
                break;  /* not found */
        }
    }

    rkn = NULL;  /* not found */

 out:
    spin_unlock_irqrestore(&rki->rk_lock, flags);
    return rkn;
}
#endif

static int rkey_delete(struct rkey_info *rki, uint32_t rkey)
{
    struct rkey_node *rkn;
    struct rb_node *rb;
    struct rb_root *root = &rki->rbtree;
    uint32_t rkey_base, bit_pos;
    int ret = 0;
    ulong flags;

    rkey &= RKEY_OS_MASK;
    rkey_base = rkey & RKEY_BASE_MASK;
    bit_pos = rkey & ~RKEY_BASE_MASK;
    spin_lock_irqsave(&rki->rk_lock, flags);
    rb = root->rb_node;

    while (rb) {
        rkn = rb_entry(rb, struct rkey_node, rb);
        if (rkey_base < rkn->rkey_base)
            rb = rb->rb_left;
        else if (rkey_base >= (rkn->rkey_base + RKEY_BITMAP_SZ))
            rb = rb->rb_right;
        else {
            /* found right node - check bitmap bit */
            if (__test_and_clear_bit(bit_pos, rkn->bitmap) == 1) {
                atomic_sub(1, &rki->allocated);
                if (rkn_count(rkn) == 0) {
                    rb_erase_augmented(&rkn->rb, root, &augment_callbacks);
                    do_kfree(rkn);
                }
                goto out;
            }
            break;  /* not found */
        }
    }

    ret = -ENOENT;  /* not found */

 out:
    spin_unlock_irqrestore(&rki->rk_lock, flags);
    return ret;
}


/* like bitmap_ord_to_pos from bitmap.c except using 0 bits */
static inline unsigned int rkey_ord_to_pos(const unsigned long *buf,
                                           unsigned int ord, unsigned int nbits)
{
    unsigned int pos;

    for (pos = find_first_zero_bit(buf, nbits);
         pos < nbits && ord;
         pos = find_next_zero_bit(buf, nbits, pos + 1))
            ord--;

    return pos;
}

static struct rkey_node *insert_nth_free_rkey(struct rkey_info *rki,
                                              struct rkey_node *new_rkn,
                                              uint32_t ord, uint32_t *rkeyp)
{
    uint32_t rkey = 0, rkey_base = 0, bit_pos;
    struct rb_root *root = &rki->rbtree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct rkey_node *ret = new_rkn;
    ulong flags;

    spin_lock_irqsave(&rki->rk_lock, flags);
    while (*new) {
        struct rkey_node *this = rb_entry(*new, struct rkey_node, rb);
        uint32_t left_free, this_free = RKEY_BITMAP_SZ - rkn_count(this);
        uint32_t this_base;

        this_base = this->rkey_base;
        parent = *new;
        left_free = this_base - rkey_base;
        if (this->rb.rb_left)
            left_free -=
                rb_entry(this->rb.rb_left, struct rkey_node, rb)->count;

        if (ord < left_free) {
            new = &((*new)->rb_left);
        } else if (ord >= (left_free + this_free)) {
            new = &((*new)->rb_right);
            rkey_base = this_base + RKEY_BITMAP_SZ;
            ord -= (left_free + this_free);
        } else  {  /* fits in this node */
            bit_pos = rkey_ord_to_pos(this->bitmap, ord - left_free,
                                      RKEY_BITMAP_SZ);
            rkey = this_base + bit_pos;
            set_bit(bit_pos, this->bitmap);
            /* propagate new count to root */
            augment_callbacks_propagate(*new, NULL);
            ret = this;
            goto unlock;
        }
    }

    /* not found - add new node */
    rkey = rkey_base + ord;
    new_rkn->rkey_base = rkey & RKEY_BASE_MASK;
    new_rkn->count = 1;
    bit_pos = rkey & ~RKEY_BASE_MASK;
    set_bit(bit_pos, new_rkn->bitmap);
    rb_link_node(&new_rkn->rb, parent, new);
    augment_callbacks_propagate(parent, NULL);
    rb_insert_augmented(&new_rkn->rb, root, &augment_callbacks);

 unlock:
    spin_unlock_irqrestore(&rki->rk_lock, flags);
    *rkeyp = rkey;
    return ret;  /* either the new node we added or the one we found */
}

int zhpe_rkey_alloc(uint32_t *ro_rkey, uint32_t *rw_rkey)
{
    uint32_t rand = 0, rkey;
    u8 rand_bytes[RKEY_RAND_BYTES];
    int allocated = 0, ret, i;
    struct rkey_node *rkn, *new_rkn = 0;

    /* allocate a new node in case we need it */
    new_rkn = do_kmalloc(sizeof(*new_rkn), GFP_KERNEL, true);
    if (unlikely(!new_rkn)) {
        ret = -ENOMEM;
        goto out;
    }
    allocated = atomic_fetch_add(1, &rki.allocated);
    if (unlikely(allocated >= RKEY_OS_MASK)) {
        ret = -ENOSPC;
        goto sub;
    }
    /* Generate a random integer in the interval [1, RKEY_TOTAL-allocated)
     * which represents the ordinal value of the Nth free rkey.
     * We never generate 0, to avoid overlapping the Gen-Z default key,
     * in case RKD is also 0.
     */
    get_random_bytes(rand_bytes, sizeof(rand_bytes));
    for (i = 0; i < RKEY_RAND_BYTES; i++)
        rand |= (((uint32_t)rand_bytes[i]) << (i * 8));
    rand = (rand % (RKEY_TOTAL - 1 - allocated)) + 1;

    /* compute Nth free rkey and insert into rbtree */
    rkn = insert_nth_free_rkey(&rki, new_rkn, rand, &rkey);

    /* Revisit: contact fabric manager to request correct RKDs */
    *ro_rkey = rkey | (RKEY_RO_RKD << RKEY_RKD_SHIFT);
    *rw_rkey = rkey | (RKEY_RW_RKD << RKEY_RKD_SHIFT);

    if (rkn != new_rkn) { /* found existing node - free new_rkn */
        ret = 0;
        goto free;
    }

    ret = 0;
    goto out;

 sub:
    atomic_sub(1, &rki.allocated);
 free:
    if (new_rkn)
        do_kfree(new_rkn);
 out:
#if RKEY_DEBUG_ALL
    debug(DEBUG_RKEYS, "%s:%s,%u: ret=%d, allocated=%d, rand=0x%05x (bytes=%02x:%02x:%02x), ro_rkey=0x%08x, rw_rkey=0x%08x\n",
          zhpe_driver_name, __func__, __LINE__,
          ret, allocated, rand,
          rand_bytes[2], rand_bytes[1], rand_bytes[0],
          *ro_rkey, *rw_rkey);
#endif
    return ret;
}

void zhpe_rkey_free(uint32_t ro_rkey, uint32_t rw_rkey)
{
    if ((ro_rkey & RKEY_OS_MASK) != (rw_rkey & RKEY_OS_MASK))
        return;

    rkey_delete(&rki, ro_rkey);
}

#if RKEY_DEBUG_ALL
static char *rkey_bitmap_str(const unsigned long *bitmap, char *str,
                             const size_t maxlen)
{
    int i, cnt, len = maxlen;
    char *p = str;

    for (i = 0; ; i++) {
        cnt = scnprintf(p, len, "%016lx", bitmap[i]);
        p += cnt;
        len -= (cnt + 1);
        if (i == (BITS_TO_LONGS(RKEY_BITMAP_SZ) - 1) || len <= 0)
            break;
        *p++ = ':';
    }

    return str;
}
#endif

void zhpe_rkey_print_all(void)
{
    struct rb_node *node;
    uint32_t nodes = 0;
    ulong flags;
#if RKEY_DEBUG_ALL
    char str[BITS_TO_LONGS(RKEY_BITMAP_SZ) * (1 + BITS_PER_LONG/4)];
#endif

    spin_lock_irqsave(&rki.rk_lock, flags);
    for (node = rb_first(&rki.rbtree); node; node = rb_next(node)) {
#if RKEY_DEBUG_ALL
        struct rkey_node *rkn = rb_entry(node, struct rkey_node, rb);

        debug(DEBUG_RKEYS, "%s:%s,%u:rkey_base=0x%05x, count=%u, bitmap=%s, rkn_count=%u, rkn=%pxx, left=%pxx, right=%pxx\n",
              zhpe_driver_name, __func__, __LINE__,
              rkn->rkey_base, rkn->count,
              rkey_bitmap_str(rkn->bitmap, str, sizeof(str)),
              rkn_count(rkn), rkn, rkn->rb.rb_left, rkn->rb.rb_right);
#endif
        nodes++;
    }

    debug(DEBUG_RKEYS, "%s:%s,%u: allocated=%d, nodes=%u\n",
          zhpe_driver_name, __func__, __LINE__,
          atomic_read(&rki.allocated), nodes);
    spin_unlock_irqrestore(&rki.rk_lock, flags);
}

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

#include <zhpe.h>
#include <zhpe_driver.h>

MODULE_LICENSE("GPL");

static struct rb_root   uuid_rbtree = RB_ROOT;
DEFINE_SPINLOCK(zhpe_uuid_rbtree_lock);

char *zhpe_uuid_str(const uuid_t *uuid, char *str, const size_t len)
{
    snprintf(str, len, "%pUb", uuid);
    return str;
}

struct uuid_tracker *zhpe_uuid_search(uuid_t *uuid)
{
    struct uuid_tracker *uu;
    struct rb_node      *node;
    struct rb_root      *root = &uuid_rbtree;
    char                uustr[UUID_STRING_LEN+1];
    ulong               flags;

    spin_lock_irqsave(&zhpe_uuid_rbtree_lock, flags);
    node = root->rb_node;

    while (node) {
        int result;

        uu = container_of(node, struct uuid_tracker, node);
        result = zhpe_uuid_cmp(uuid, &uu->uuid);
        if (result < 0) {
            node = node->rb_left;
        } else if (result > 0) {
            node = node->rb_right;
        } else {
            kref_get(&uu->refcount);
            debug(DEBUG_UUID, "%s:%s,%u:get uuid=%s, refcount=%u\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__,
                  zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr)),
                  kref_read(&uu->refcount));
            goto out;
        }
    }

    uu = NULL;

 out:
    spin_unlock_irqrestore(&zhpe_uuid_rbtree_lock, flags);
    return uu;
}

static struct uuid_tracker *uuid_insert(struct uuid_tracker *uu)
{
    struct rb_root *root = &uuid_rbtree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    char           uustr[UUID_STRING_LEN+1];
    ulong          flags;

    spin_lock_irqsave(&zhpe_uuid_rbtree_lock, flags);

    /* figure out where to put new node */
    while (*new) {
        struct uuid_tracker *this =
            container_of(*new, struct uuid_tracker, node);
        int result = zhpe_uuid_cmp(&uu->uuid, &this->uuid);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {
            uu = this;
            kref_get(&uu->refcount);
            debug(DEBUG_UUID, "%s:%s,%u:get uuid=%s, refcount=%u\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__,
                  zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr)),
                  kref_read(&uu->refcount));
            goto out;  /* already there */
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&uu->node, parent, new);
    rb_insert_color(&uu->node, root);

 out:
    spin_unlock_irqrestore(&zhpe_uuid_rbtree_lock, flags);
    return uu;
}

void zhpe_generate_uuid(struct bridge *bridge, uuid_t *uuid)
{
    uint32_t cid = bridge->gcid;

    uuid_gen(uuid);
    /* insert local bridge 28-bit Global CID */
    uuid->b[0] = (cid >> 20) & 0xff;
    uuid->b[1] = (cid >> 12) & 0xff;
    uuid->b[2] = (cid >>  4) & 0xff;
    uuid->b[3] = ((cid & 0x0f) << 4) | (uuid->b[3] & 0x0f);
}

uint32_t zhpe_gcid_from_uuid(const uuid_t *uuid)
{
    return (uuid->b[0] << 20) | (uuid->b[1] << 12) |
           (uuid->b[2] <<  4) | (uuid->b[3] >> 4);
}

struct uuid_tracker *zhpe_uuid_tracker_alloc(uuid_t *uuid,
                                             uint type,
                                             gfp_t alloc_flags,
                                             int *status)
{
    struct uuid_tracker *uu;
    char                uustr[UUID_STRING_LEN+1];
    int                 ret = 0;

    uu = do_kmalloc(sizeof(struct uuid_tracker), alloc_flags, 1);
    if (!uu) {
        ret = -ENOMEM;
        goto done;
    }
    uuid_copy(&uu->uuid, uuid);
    kref_init(&uu->refcount);

    if (type & UUID_TYPE_LOCAL) {
        uu->local = do_kmalloc(sizeof(struct uuid_tracker_local),
                               alloc_flags, 1);
        if (!uu->local) {
            do_kfree(uu);
            ret = -ENOMEM;
            goto done;
        }
    }

    if (type & UUID_TYPE_REMOTE) {
        uu->remote = do_kmalloc(sizeof(struct uuid_tracker_remote),
                               alloc_flags, 1);
        if (!uu->remote) {
            if (uu->local)
                do_kfree(uu->local);
            do_kfree(uu);
            ret = -ENOMEM;
            goto done;
        }
    }

 done:
    *status = ret;
    debug(DEBUG_UUID, "%s:%s,%u:alloc uuid=%s, refcount=%u, local=%px, remote=%px, ret=%d\n",
          zhpe_driver_name, __FUNCTION__, __LINE__,
          zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr)),
          kref_read(&uu->refcount), uu->local, uu->remote, ret);
    return uu;
}

static inline void _uuid_tracker_free(struct uuid_tracker *uu)
{
    if (uu->local)
        do_kfree(uu->local);
    if (uu->remote)
        do_kfree(uu->remote);
    do_kfree(uu);
}

struct uuid_tracker *zhpe_uuid_tracker_insert(struct uuid_tracker *uu,
                                               int *status)
{
    struct uuid_tracker *found;
    int ret = 0;

    found = uuid_insert(uu);
    if (found != uu) {  /* already there */
        ret = -EEXIST;
        /* make sure found has union of found+uu local & remote */
        if (uu->local && !found->local) {
            found->local = uu->local;
            uu->local = NULL;  /* so _uuid_tracker_free doesn't free it */
        }
        if (uu->remote && !found->remote) {
            found->remote = uu->remote;
            uu->remote = NULL;  /* so _uuid_tracker_free doesn't free it */
        }
        _uuid_tracker_free(uu);
    }

    *status = ret;
    return found;
}


void zhpe_uuid_tracker_free(struct kref *ref)
{
    /* caller must already hold zhpe_uuid_rbtree_lock */
    struct rb_root *root = &uuid_rbtree;
    struct uuid_tracker *uu = container_of(ref, struct uuid_tracker, refcount);

    rb_erase(&uu->node, root);
    _uuid_tracker_free(uu);
}

static void teardown_local_uuid(struct uuid_tracker *local_uu)
{
    struct rb_node          *rb, *next;
    struct uuid_node        *node;
    struct uuid_tracker     *uu;
    char                    uustr[UUID_STRING_LEN+1];

    /* caller must already hold uuid_lock */

    debug(DEBUG_UUID, "%s:%s,%u: uuid=%s\n",
          zhpe_driver_name, __FUNCTION__, __LINE__,
          zhpe_uuid_str(&local_uu->uuid, uustr, sizeof(uustr)));

    for (rb = rb_first_postorder(&local_uu->local->uu_remote_uuid_tree);
         rb; rb = next) {
        node = container_of(rb, struct uuid_node, node);
        uu = node->tracker;
        debug(DEBUG_UUID, "%s:%s,%u: uu_remote_uuid_tree uuid=%s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr)));
        next = rb_next_postorder(rb);  /* must precede kfree() */
        do_kfree(node);
        zhpe_uuid_remove(uu); /* remove local_uuid reference */
    }

    local_uu->local->uu_remote_uuid_tree = RB_ROOT;
}

int zhpe_free_local_uuid(struct file_data *fdata, bool teardown)
{
    struct uuid_tracker     *local_uu;
    int                     ret = 0;

    /* caller must already hold uuid_lock */
    local_uu = fdata->local_uuid;
    if (!local_uu) {
        ret = -EINVAL;
        goto out;
    }

    if (teardown) {
        teardown_local_uuid(local_uu);
    } else {
        if (!(zhpe_umem_empty(fdata) && zhpe_remote_uuid_empty(fdata))) {
            ret = -EBUSY;
            goto out;
        }
    }

    zhpe_rkey_free(fdata->ro_rkey, fdata->rw_rkey);
    zhpe_uuid_remove(local_uu); /* remove local_uuid reference */
    fdata->local_uuid = NULL;

 out:
    return ret;
}

static struct uuid_node *uuid_node_search(struct rb_root *root,
                                          uuid_t *uuid, bool teardown)
{
    struct uuid_node *unode;
    struct rb_node   *rnode;
    char             uustr[UUID_STRING_LEN+1];

    /* caller must already hold the appropriate spinlock for root */
    rnode = root->rb_node;

    while (rnode) {
        int result;

        unode = container_of(rnode, struct uuid_node, node);
        result = zhpe_uuid_cmp(uuid, &unode->tracker->uuid);
        if (result < 0) {
            rnode = rnode->rb_left;
        } else if (result > 0) {
            rnode = rnode->rb_right;
        } else {
            if (!teardown && unode->tracker->remote &&
                READ_ONCE(unode->tracker->remote->torndown)) {
                debug(DEBUG_UUID, "%s:%s,%u:returning NULL because torndown=true, uuid=%s\n",
                      zhpe_driver_name, __FUNCTION__, __LINE__,
                      zhpe_uuid_str(uuid, uustr, sizeof(uustr)));
                goto null;
            }
            goto out;
        }
    }

 null:
    unode = NULL;

 out:
    return unode;
}

struct uuid_node *zhpe_remote_uuid_get(struct file_data *fdata,
                                       uuid_t *uuid)
{
    struct uuid_node        *unode;
    struct uuid_tracker     *uu;
    ulong                   flags;
    char                    uustr[UUID_STRING_LEN+1];

    debug(DEBUG_UUID, "%s:%s,%u:uuid = %s\n",
          zhpe_driver_name, __FUNCTION__, __LINE__,
          zhpe_uuid_str(uuid, uustr, sizeof(uustr)));
    spin_lock_irqsave(&fdata->uuid_lock, flags);
    unode = uuid_node_search(&fdata->fd_remote_uuid_tree, uuid, false);
    if (unode) {
        uu = unode->tracker;
        kref_get(&uu->refcount);
        debug(DEBUG_UUID, "%s:%s,%u:get uuid=%s, refcount=%u\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr)),
              kref_read(&uu->refcount));
    }
    spin_unlock_irqrestore(&fdata->uuid_lock, flags);
    debug(DEBUG_UUID, "%s:%s,%u:unode = %px\n",
          zhpe_driver_name, __FUNCTION__, __LINE__, unode);

    return unode;
}

struct uuid_node *zhpe_remote_uuid_insert(spinlock_t *lock,
                                          struct rb_root *root,
                                          struct uuid_node *node)
{
    struct rb_node **new = &root->rb_node, *parent = NULL;
    ulong flags;

    spin_lock_irqsave(lock, flags);

    /* figure out where to put new node */
    while (*new) {
        struct uuid_node *this =
            container_of(*new, struct uuid_node, node);
        int result = zhpe_uuid_cmp(&node->tracker->uuid, &this->tracker->uuid);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {  /* already there */
            node = this;
            goto out;
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&node->node, parent, new);
    rb_insert_color(&node->node, root);

 out:
    spin_unlock_irqrestore(lock, flags);
    return node;
}

static int _free_uuid_node(struct file_data *fdata, struct rb_root *root,
                           uuid_t *uuid, bool teardown)
{
    struct uuid_node *node;
    struct uuid_tracker *uu;
    int ret = 0;
    char str[UUID_STRING_LEN+1];

    /* caller must already hold the appropriate spinlock for root */
    node = uuid_node_search(root, uuid, teardown);
    if (!node) {
        ret = -EINVAL;
        goto out;
    }

    uu = node->tracker;
    if (teardown) {
        zhpe_rmr_remove_unode(fdata, node);
    } else if (!zhpe_unode_rmr_empty(node)) {
        ret = -EBUSY;
        debug(DEBUG_UUID, "%s:%s,%u:ret = %d uuid = %s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__, ret,
              zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
        goto out;
    }

    rb_erase(&node->node, root);
    do_kfree(node);
    zhpe_uuid_remove(uu); /* remove remote_uuid reference */

 out:
    return ret;
}

int zhpe_free_uuid_node(struct file_data *fdata, spinlock_t *lock,
                        struct rb_root *root,
                        uuid_t *uuid, bool teardown)
{
    int ret;
    ulong flags;

    spin_lock_irqsave(lock, flags);
    ret = _free_uuid_node(fdata, root, uuid, teardown);
    spin_unlock_irqrestore(lock, flags);

    return ret;
}

void zhpe_free_remote_uuids(struct file_data *fdata)
{
    struct rb_node          *rb, *next;
    struct uuid_node        *node;
    struct uuid_tracker     *uu;
    char                    str[UUID_STRING_LEN+1];

    /* caller must already hold uuid_lock */

    for (rb = rb_first_postorder(&fdata->fd_remote_uuid_tree); rb; rb = next) {
        node = container_of(rb, struct uuid_node, node);
        uu = node->tracker;
        debug(DEBUG_UUID, "%s:%s,%u:uuid = %s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
        zhpe_free_uuid_node(fdata, &uu->remote->local_uuid_lock,
                            &uu->remote->local_uuid_tree,
                            &fdata->local_uuid->uuid, false);
        next = rb_next_postorder(rb);  /* must precede kfree() */
        do_kfree(node);
        zhpe_uuid_remove(uu); /* remove remote_uuid reference */
    }

    fdata->fd_remote_uuid_tree = RB_ROOT;
}

void zhpe_notify_remote_uuids(struct file_data *fdata)
{
    struct rb_node          *rb;
    struct uuid_node        *node;
    struct uuid_tracker     *uu;
    struct zhpe_msg_state   *state;
    int                     status;
    struct list_head        free_msg_list, teardown_msg_list;
    ktime_t                 start;
    uint32_t                prev_gcid, gcid;
    char                    str[UUID_STRING_LEN+1];

    /* caller must hold no spinlocks (we are going to sleep) */
    INIT_LIST_HEAD(&free_msg_list);
    INIT_LIST_HEAD(&teardown_msg_list);

    start = ktime_get();

    /* special case for loopback UUIDs */
    /* Revisit: what if rbtree changes while we're looping? */
    for (rb = rb_first(&fdata->fd_remote_uuid_tree); rb; rb = rb_next(rb)) {
        node = container_of(rb, struct uuid_node, node);
        uu = node->tracker;
        if (uu->local && uu->remote) {  /* loopback UUID */
            debug(DEBUG_UUID, "%s:%s,%u: TEARDOWN loopback uuid=%s\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__,
                  zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
            state = zhpe_msg_send_UUID_TEARDOWN(fdata->bridge,
                                                &uu->uuid,
                                                &fdata->local_uuid->uuid);
            if (IS_ERR(state)) {
                status = PTR_ERR(state);
                debug(DEBUG_MSG,
                      "%s:%s,%u: zhpe_msg_send_UUID_TEARDOWN status=%d\n",
                      zhpe_driver_name, __FUNCTION__, __LINE__, status);
                continue;
            }
            list_add_tail(&state->msg_list, &teardown_msg_list);
        }
    }

    if (zhpe_uu_remote_uuid_empty(fdata)) {
        debug(DEBUG_UUID, "%s:%s,%u: no remote UUIDs to TEARDOWN\n",
              zhpe_driver_name, __FUNCTION__, __LINE__);
        goto teardown_done;
    }

    /* Revisit: what if rbtree changes while we're looping? */
    prev_gcid = -1u;
    for (rb = rb_first(&fdata->local_uuid->local->uu_remote_uuid_tree); rb;
         rb = rb_next(rb)) {
        node = container_of(rb, struct uuid_node, node);
        uu = node->tracker;
        gcid = zhpe_gcid_from_uuid(&uu->uuid);
        if (gcid == prev_gcid)  /* skip send if this GCID same as previous */
            continue;
        prev_gcid = gcid;
        debug(DEBUG_UUID, "%s:%s,%u: TEARDOWN uuid=%s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
        state = zhpe_msg_send_UUID_TEARDOWN(fdata->bridge,
                                            &fdata->local_uuid->uuid,
                                            &uu->uuid);
        if (IS_ERR(state)) {
            status = PTR_ERR(state);
            debug(DEBUG_MSG,
                  "%s:%s,%u: zhpe_msg_send_UUID_TEARDOWN status=%d\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__, status);
            continue;
        }
        list_add_tail(&state->msg_list, &teardown_msg_list);
    }

 teardown_done:
    /* wait for replies to all TEARDOWN messages */
    zhpe_msg_list_wait(&teardown_msg_list, start);

    /* Revisit: what if rbtree changes while we're looping? */
    for (rb = rb_first(&fdata->fd_remote_uuid_tree); rb; rb = rb_next(rb)) {
        node = container_of(rb, struct uuid_node, node);
        uu = node->tracker;
        if (uu->remote->uu_flags & UUID_IS_FAM) { /* skip send if this is FAM */
            debug(DEBUG_UUID, "%s:%s,%u: IS_FAM skipping FREE uuid=%s\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__,
                  zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
            continue;
        }
        debug(DEBUG_UUID, "%s:%s,%u: FREE uuid=%s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&uu->uuid, str, sizeof(str)));
        state = zhpe_msg_send_UUID_FREE(fdata->bridge,
                                        &fdata->local_uuid->uuid, &uu->uuid,
                                        false);
        if (IS_ERR(state)) {
            status = PTR_ERR(state);
            debug(DEBUG_MSG, "%s:%s,%u: zhpe_msg_send_UUID_FREE status=%d\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__, status);
            continue;
        }
        list_add_tail(&state->msg_list, &free_msg_list);
    }

    /* wait for replies to all the FREE messages */
    zhpe_msg_list_wait(&free_msg_list, start);
}

int zhpe_teardown_remote_uuid(uuid_t *src_uuid)
{
    int                    status = ZHPE_MSG_OK;
    struct uuid_tracker    *suu, *tuu;
    struct rb_node         *rb, *next;
    struct uuid_node       *node;
    struct file_data       *fdata;
    ulong                  flags;
    char                   uustr[UUID_STRING_LEN+1];

    suu = zhpe_uuid_search(src_uuid);
    if (!suu) {
        status = ZHPE_MSG_ERR_NO_UUID;
        debug(DEBUG_UUID, "%s:%s,%u: src_uuid=%s not found\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(src_uuid, uustr, sizeof(uustr)));
        goto out;
    }
    /* we now hold an extra reference to suu */

    debug(DEBUG_UUID, "%s:%s,%u: uuid=%s\n",
          zhpe_driver_name, __FUNCTION__, __LINE__,
          zhpe_uuid_str(&suu->uuid, uustr, sizeof(uustr)));

    if (!suu->remote) {
        debug(DEBUG_UUID, "%s:%s,%u:unexpected null ptr, "
              "suu->remote=%px, uuid=%s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              suu->remote, uustr);
        goto local;
    }
    WRITE_ONCE(suu->remote->torndown, true);
    spin_lock_irqsave(&suu->remote->local_uuid_lock, flags);
    for (rb = rb_first_postorder(&suu->remote->local_uuid_tree);
         rb; rb = next) {
        node = container_of(rb, struct uuid_node, node);
        tuu = node->tracker;
        debug(DEBUG_UUID, "%s:%s,%u:local_uuid_tree uuid = %s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__,
              zhpe_uuid_str(&tuu->uuid, uustr, sizeof(uustr)));
        next = rb_next_postorder(rb);  /* must precede kfree() */
        fdata = tuu->local->fdata;
        status = zhpe_free_uuid_node(fdata, &fdata->uuid_lock,
                                     &fdata->fd_remote_uuid_tree,
                                     src_uuid, true);
        if (status < 0) {
            status = ZHPE_MSG_ERR_NO_UUID;  /* Revisit: unique error? */
        }
        do_kfree(node);
        zhpe_uuid_remove(tuu); /* remove local_uuid reference */
    }
    suu->remote->local_uuid_tree = RB_ROOT;
    spin_unlock_irqrestore(&suu->remote->local_uuid_lock, flags);

 local:
    /* special case for alias loopback UUIDs */
    if (suu->local) {
        spin_lock_irqsave(&suu->local->fdata->uuid_lock, flags);
        teardown_local_uuid(suu);
        spin_unlock_irqrestore(&suu->local->fdata->uuid_lock, flags);
    }

    zhpe_uuid_remove(suu);  /* release extra reference */

 out:
    return status;
}

static inline bool uuid_tree_empty(void)
{
    return RB_EMPTY_ROOT(&uuid_rbtree);
}

void zhpe_uuid_exit(void)
{
    struct rb_node          *rb;
    struct uuid_tracker     *uu;
    ulong                   flags;
    char                    str[UUID_STRING_LEN+1];

    spin_lock_irqsave(&zhpe_uuid_rbtree_lock, flags);

    if (!uuid_tree_empty()) {
        debug(DEBUG_UUID, "%s:%s,%u:uuid_tree not empty\n",
              zhpe_driver_name, __FUNCTION__, __LINE__);
        for (rb = rb_first(&uuid_rbtree); rb; rb = rb_next(rb)) {
            uu = container_of(rb, struct uuid_tracker, node);
            debug(DEBUG_UUID, "%s:%s,%u: orphaned uuid=%s, refcount=%u\n",
                  zhpe_driver_name, __FUNCTION__, __LINE__,
                  zhpe_uuid_str(&uu->uuid, str, sizeof(str)),
                  kref_read(&uu->refcount));
        }
    }

    spin_unlock_irqrestore(&zhpe_uuid_rbtree_lock, flags);
}

int zhpe_user_req_UUID_IMPORT(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    struct file_data        *fdata = entry->fdata;
    struct uuid_tracker     *uu;
    int                     status = 0;
    uint                    type = UUID_TYPE_REMOTE;
    uuid_t                  *uuid = &req->uuid_import.uuid;
    struct uuid_node        *fd_node, *uu_node;
    uint32_t                ro_rkey, rw_rkey;
    char                    uustr[UUID_STRING_LEN+1];
    uint32_t                uu_flags = req->uuid_import.uu_flags;

    CHECK_INIT_STATE(entry, status, out);
    if (zhpe_uuid_is_local(fdata->bridge, uuid)) {
        if (genz_loopback) {
            type = UUID_TYPE_LOOPBACK;
        } else {
            status = -EINVAL;  /* only remote UUIDs can be imported */
            goto out;
        }
    }
    uu = zhpe_uuid_tracker_alloc_and_insert(uuid, type, uu_flags,
                                            fdata, GFP_KERNEL, &status);
    if (status == -EEXIST) {  /* duplicates ok - even expected */
        status = 0;
    } else if (status < 0) {
        goto out;
    }
    /* we now hold a reference to uu */
    /* add uu to fdata->fd_remote_uuid_tree */
    fd_node = zhpe_remote_uuid_alloc_and_insert(uu, &fdata->uuid_lock,
                                                &fdata->fd_remote_uuid_tree,
                                                GFP_KERNEL, &status);
    if (status < 0) {
        zhpe_uuid_remove(uu);
        goto out;
    }
    /* add fdata->local_uuid to uu->remote->local_uuid_tree */
    kref_get(&fdata->local_uuid->refcount);
    debug(DEBUG_UUID, "%s:%s,%u:get uuid=%s, refcount=%u\n",
          zhpe_driver_name, __FUNCTION__, __LINE__,
          zhpe_uuid_str(&fdata->local_uuid->uuid, uustr, sizeof(uustr)),
          kref_read(&fdata->local_uuid->refcount));
    uu_node = zhpe_remote_uuid_alloc_and_insert(fdata->local_uuid,
                                                &uu->remote->local_uuid_lock,
                                                &uu->remote->local_uuid_tree,
                                                GFP_KERNEL, &status);
    if (status < 0) {
        zhpe_free_uuid_node(fdata, &fdata->uuid_lock,
                            &fdata->fd_remote_uuid_tree, uuid, false);
        zhpe_uuid_remove(uu);
        zhpe_uuid_remove(fdata->local_uuid);
        goto out;
    }
    /* send msg to retrieve R-keys from remote node - this can sleep a while */
    if (!(uu_flags & UUID_IS_FAM)) {
        status = zhpe_msg_send_UUID_IMPORT(fdata->bridge,
                                       &fdata->local_uuid->uuid, uuid,
                                       &ro_rkey, &rw_rkey);
        if (status < 0)
            goto out;

        uu->remote->ro_rkey = ro_rkey;
        uu->remote->rw_rkey = rw_rkey;
        uu->remote->rkeys_valid = true;
    }

 out:
    debug(DEBUG_UUID, "%s:%s,%u:ret = %d uuid = %s uu_flags = 0x%x\n",
          zhpe_driver_name, __FUNCTION__, __LINE__, status,
          zhpe_uuid_str(uuid, uustr, sizeof(uustr)), uu_flags);
    return queue_io_rsp(entry, sizeof(rsp->uuid_import), status);
}

int zhpe_user_req_UUID_FREE(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    struct file_data        *fdata = entry->fdata;
    struct uuid_tracker     *uu;
    int                     status = 0;
    struct zhpe_msg_state   *state;
    uuid_t                  *uuid = &req->uuid_free.uuid;
    bool                    local;
    ulong                   flags;
    char                    str[UUID_STRING_LEN+1];
    uint32_t                uu_flags = 0;

    CHECK_INIT_STATE(entry, status, out);
    uu = zhpe_uuid_search(uuid);
    if (!uu) {
        status = -EINVAL;
        goto out;
    }

    /* we now hold an extra reference to uu - release it */
    zhpe_uuid_remove(uu);
    spin_lock_irqsave(&fdata->uuid_lock, flags);
    local = (uu == fdata->local_uuid);
    if (local) {
        status = zhpe_free_local_uuid(fdata, false);
    } else {
        status = _free_uuid_node(fdata, &fdata->fd_remote_uuid_tree,
                                 uuid, false);
    }
    spin_unlock_irqrestore(&fdata->uuid_lock, flags);
    if (status < 0)
        goto out;

    if (local) {
        spin_lock(&fdata->io_lock);
        fdata->state &= ~STATE_INIT;
        spin_unlock(&fdata->io_lock);
    } else {
        spin_lock_irqsave(&uu->remote->local_uuid_lock, flags);
        status = _free_uuid_node(fdata, &uu->remote->local_uuid_tree,
                                 &fdata->local_uuid->uuid, false);
        spin_unlock_irqrestore(&uu->remote->local_uuid_lock, flags);
        /* send msg to release UUID on remote node - this can sleep a while */
        uu_flags = uu->remote->uu_flags;
        if (!(uu_flags & UUID_IS_FAM)) {
            state = zhpe_msg_send_UUID_FREE(fdata->bridge,
                                        &fdata->local_uuid->uuid, uuid, true);
            if (IS_ERR(state)) {
                status = PTR_ERR(state);
                debug(DEBUG_MSG,
                      "%s:%s,%u: zhpe_msg_send_UUID_FREE status=%d\n",
                      zhpe_driver_name, __FUNCTION__, __LINE__, status);
            }
        }
    }

 out:
    debug(DEBUG_UUID, "%s:%s,%u:ret = %d uuid = %s uu_flags = 0x%x\n",
          zhpe_driver_name, __FUNCTION__, __LINE__, status,
          zhpe_uuid_str(uuid, str, sizeof(str)), uu_flags);
    return queue_io_rsp(entry, sizeof(rsp->uuid_free), status);
}

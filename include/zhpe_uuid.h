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

#ifndef _ZHPE_UUID_H_
#define _ZHPE_UUID_H_

enum uuid_type {
    UUID_TYPE_LOCAL    = 0x1,
    UUID_TYPE_REMOTE   = 0x2,
    UUID_TYPE_LOOPBACK = 0x3
};

struct uuid_tracker_remote {
    uint32_t                ro_rkey;
    uint32_t                rw_rkey;
    uint32_t                uu_flags;
    bool                    rkeys_valid;
    bool                    torndown;  /* UUID is being torndown */
    /* Revisit: add bool to distinguish "alias" vs "real" loopback */
    /* local users of this remote UUID - protected by local_uuid_lock */
    struct rb_root          local_uuid_tree;
    spinlock_t              local_uuid_lock;
};

struct uuid_tracker_local {
    struct file_data *fdata;
    /* remote users of this local UUID - protected by fdata->uuid_lock */
    struct rb_root   uu_remote_uuid_tree;
};

struct uuid_tracker {
    uuid_t                      uuid;
    struct rb_node              node;
    struct kref                 refcount;
    struct uuid_tracker_remote  *remote;
    struct uuid_tracker_local   *local;
};

struct uuid_node {
    struct uuid_tracker *tracker;
    struct rb_node      node;
    struct rb_root      un_rmr_tree;
};

extern spinlock_t zhpe_uuid_rbtree_lock;

int zhpe_user_req_UUID_IMPORT(struct io_entry *entry);
int zhpe_user_req_UUID_FREE(struct io_entry *entry);
int zhpe_free_local_uuid(struct file_data *fdata, bool teardown);
void zhpe_generate_uuid(struct bridge *bridge, uuid_t *uuid);
char *zhpe_uuid_str(const uuid_t *uuid, char *str, const size_t len);
int zhpe_free_uuid_node(struct file_data *fdata, spinlock_t *lock,
                        struct rb_root *root, uuid_t *uuid, bool force);
void zhpe_free_remote_uuids(struct file_data *fdata);
void zhpe_uuid_tracker_free(struct kref *ref);
void zhpe_notify_remote_uuids(struct file_data *fdata);
int zhpe_teardown_remote_uuid(uuid_t *src_uuid);
struct uuid_tracker *zhpe_uuid_tracker_alloc(uuid_t *uuid, uint type,
                                             gfp_t alloc_flags, int *status);
struct uuid_tracker *zhpe_uuid_tracker_insert(struct uuid_tracker *uu,
                                               int *status);
struct uuid_node *zhpe_remote_uuid_get(struct file_data *fdata,
                                       uuid_t *uuid);
struct uuid_node *zhpe_remote_uuid_insert(spinlock_t *lock,
                                          struct rb_root *root,
                                          struct uuid_node *node);
struct uuid_tracker *zhpe_uuid_search(uuid_t *uuid);
uint32_t zhpe_gcid_from_uuid(const uuid_t *uuid);
void zhpe_uuid_exit(void);

static inline bool zhpe_remote_uuid_empty(struct file_data *fdata)
{
    return RB_EMPTY_ROOT(&fdata->fd_remote_uuid_tree);
}

static inline bool zhpe_uu_remote_uuid_empty(struct file_data *fdata)
{
    return (!fdata->local_uuid ||
            RB_EMPTY_ROOT(&fdata->local_uuid->local->uu_remote_uuid_tree));
}

static inline bool zhpe_unode_rmr_empty(struct uuid_node *node)
{
    return RB_EMPTY_ROOT(&node->un_rmr_tree);
}

static inline int zhpe_uuid_cmp(const uuid_t *u1, const uuid_t *u2)
{
    /* this must sort all UUIDs for a given GCID together, which it does
     * because the GCID is in the first 7 bytes
     */
    return memcmp(u1, u2, sizeof(uuid_t));
}

static inline bool zhpe_uuid_is_local(struct bridge *br, uuid_t *uuid)
{
    return zhpe_gcid_from_uuid(uuid) == br->gcid;
}

static inline void zhpe_uuid_remove(struct uuid_tracker *uu)
{
    bool  gone;
    ulong flags;
    char  uustr[UUID_STRING_LEN+1];

    zhpe_uuid_str(&uu->uuid, uustr, sizeof(uustr));
    spin_lock_irqsave(&zhpe_uuid_rbtree_lock, flags);
    gone = kref_put(&uu->refcount, zhpe_uuid_tracker_free);
    if (gone)
        debug(DEBUG_UUID, "%s:%s,%u:freed uuid=%s\n",
              zhpe_driver_name, __FUNCTION__, __LINE__, uustr);
    else
        debug(DEBUG_UUID, "%s:%s,%u:removed uuid=%s, refcount=%u\n",
              zhpe_driver_name, __FUNCTION__, __LINE__, uustr,
              kref_read(&uu->refcount));
    spin_unlock_irqrestore(&zhpe_uuid_rbtree_lock, flags);
}

static inline struct uuid_tracker *zhpe_uuid_tracker_alloc_and_insert(
    uuid_t *uuid,
    uint type,
    uint32_t uu_flags,
    struct file_data *fdata,
    gfp_t alloc_flags,
    int *status)
{
    struct uuid_tracker *uu;

    uu = zhpe_uuid_tracker_alloc(uuid, type, alloc_flags, status);
    if (uu) {
        if (type & UUID_TYPE_LOCAL) {
            uu->local->fdata = fdata;
            uu->local->uu_remote_uuid_tree = RB_ROOT;
        }
        if (type & UUID_TYPE_REMOTE) {
            uu->remote->rkeys_valid = false;
            uu->remote->uu_flags = uu_flags;
            uu->remote->local_uuid_tree = RB_ROOT;
            spin_lock_init(&uu->remote->local_uuid_lock);
        }

        uu = zhpe_uuid_tracker_insert(uu, status);
    }

    return uu;
}

static inline struct uuid_node *zhpe_remote_uuid_alloc_and_insert(
    struct uuid_tracker *uu,
    spinlock_t *lock,
    struct rb_root *root,
    gfp_t alloc_flags,
    int *status)
{
    struct uuid_node *node, *found;
    int ret = 0;

    node = do_kmalloc(sizeof(struct uuid_node), alloc_flags, 0);
    if (!node) {
        ret = -ENOMEM;
        goto out;
    }
    node->tracker = uu;
    node->un_rmr_tree = RB_ROOT;
    found = zhpe_remote_uuid_insert(lock, root, node);
    if (found != node) {  /* already there */
        do_kfree(node);
        ret = -EEXIST;
        node = found;
        goto out;
    }

 out:
    *status = ret;
    return node;
}
#endif /* _ZHPE_UUID_H_ */

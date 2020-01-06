/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
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

uint zhpe_kmsg_timeout;

/* msg_state & msgid's are global */
static struct rb_root msg_rbtree = RB_ROOT;
DEFINE_SPINLOCK(zhpe_msg_rbtree_lock);
static atomic_t msgid = ATOMIC_INIT(0);

static inline ktime_t get_timeout(void)
{
    return ktime_set((zhpe_kmsg_timeout > 0 ? zhpe_kmsg_timeout : 2), 0);
}

static inline uint16_t msg_alloc_msgid(void)
{
    return (uint16_t)atomic_inc_return(&msgid);
}

static struct zhpe_msg_state *msg_state_alloc(void)
{
    struct zhpe_msg_state *state;

    state = do_kmalloc(sizeof(*state), GFP_KERNEL, true);
    if (state) {
        init_waitqueue_head(&state->wq);
        INIT_LIST_HEAD(&state->msg_list);
    }
    return state;
}

static struct zhpe_msg_state *msg_state_search(uint16_t msgid)
{
    struct zhpe_msg_state *state;
    struct rb_node *node;
    struct rb_root *root = &msg_rbtree;

    spin_lock(&zhpe_msg_rbtree_lock);
    node = root->rb_node;

    while (node) {
        int result;

        state = container_of(node, struct zhpe_msg_state, node);
        result = arithcmp(msgid, state->req_msg.hdr.msgid);
        if (result < 0) {
            node = node->rb_left;
        } else if (result > 0) {
            node = node->rb_right;
        } else {
            goto out;
        }
    }

    state = NULL;

 out:
    spin_unlock(&zhpe_msg_rbtree_lock);
    return state;
}

static struct zhpe_msg_state *msg_state_insert(struct zhpe_msg_state *ms)
{
    struct rb_root *root = &msg_rbtree;
    struct rb_node **new = &root->rb_node, *parent = NULL;

    spin_lock(&zhpe_msg_rbtree_lock);

    /* figure out where to put new node */
    while (*new) {
        struct zhpe_msg_state *this =
            container_of(*new, struct zhpe_msg_state, node);
        int result = arithcmp(ms->req_msg.hdr.msgid, this->req_msg.hdr.msgid);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {
            ms = this;
            goto out;  /* already there */
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&ms->node, parent, new);
    rb_insert_color(&ms->node, root);

 out:
    spin_unlock(&zhpe_msg_rbtree_lock);
    return ms;
}

static void msg_state_free(struct zhpe_msg_state *ms)
{
    struct rb_root *root = &msg_rbtree;

    spin_lock(&zhpe_msg_rbtree_lock);
    rb_erase(&ms->node, root);
    spin_unlock(&zhpe_msg_rbtree_lock);
    do_kfree(ms);
}

static int _msg_xdm_get_cmpl(struct xdm_info *xdmi, struct zhpe_cq_entry *entry)
{
    int ret = 0;
    uint head, next_head, cmdq_ent, cmpl_index;
    struct zhpe_cq_entry *xdm_entry, *next_entry;
    void *cpu_addr;

    /* caller must hold xdm_info_lock */

    cmdq_ent = xdmi->cmdq_ent;
    head = xdmi->cmplq_head;
    cpu_addr = xdmi->cmplq_zpage->dma.cpu_addr;
    xdm_entry = &(((struct zhpe_cq_entry *)cpu_addr)[head]);

    /* check valid bit */
    if (xdm_entry->valid != xdmi->cur_valid) {
        ret = -EBUSY;
        goto out;
    }
    xdmi->active_cmds--;
    /* copy XDM completion entry to caller */
    *entry = *xdm_entry;
    /* do mod-add to compute next head value */
    next_head = (head + 1) % xdmi->cmplq_ent;
    /* toggle cur_valid on wrap */
    if (next_head < head)
        xdmi->cur_valid = !xdmi->cur_valid;
    /* update cmplq_head - SW-only */
    xdmi->cmplq_head = next_head;
    /* update cmdq_head_shadow if this completion moves it forward */
    cmpl_index = entry->index;
    if (cmpl_index < cmdq_ent) {
        if (((xdmi->cmdq_tail_shadow - cmpl_index) % cmdq_ent) <
            ((xdmi->cmdq_tail_shadow - xdmi->cmdq_head_shadow) % cmdq_ent))
            xdmi->cmdq_head_shadow = cmpl_index;
    }  /* Revisit: add support for cmd buffers */
    /* peek at next entry to determine if it is valid */
    next_entry = &(((struct zhpe_cq_entry *)cpu_addr)[next_head]);
    ret = (next_entry->valid == xdmi->cur_valid);

 out:
    return ret;
}

int msg_xdm_get_cmpl(struct xdm_info *xdmi, struct zhpe_cq_entry *entry)
{
    int ret;

    spin_lock(&xdmi->xdm_info_lock);
    ret = _msg_xdm_get_cmpl(xdmi, entry);
    spin_unlock(&xdmi->xdm_info_lock);
    return ret;
}

static int msg_xdm_queue_cmd(struct xdm_info *xdmi,
                             union zhpe_hw_wq_entry *cmd)
{
    int ret = 0, cmpl_ret;
    uint head, tail, next_tail;
    union zhpe_hw_wq_entry *xdm_entry;
    struct zhpe_cq_entry cq_entry;
    void *cpu_addr;
    bool more = 0;

    spin_lock(&xdmi->xdm_info_lock);
    /* Revisit: add support for cmd buffers */
    tail = xdmi->cmdq_tail_shadow;
    /* do mod-add to compute next tail value */
    next_tail = (tail + 1) % xdmi->cmdq_ent;
 restart_head:
    head = xdmi->cmdq_head_shadow;
    if (next_tail == head) {  /* cmdq appears to be full */
        /* our cmdq_head_shadow might be out-of-date - read HW */
        xdmi->cmdq_head_shadow =
            xdm_qcm_read(xdmi->hw_qcm_addr,
                         ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
        if (head != xdmi->cmdq_head_shadow)
            goto restart_head;
        ret = -EBUSY;
    } else if (xdmi->active_cmds + 1 >= xdmi->cmplq_ent) {
        do {  /* process completions */
            cmpl_ret = _msg_xdm_get_cmpl(xdmi, &cq_entry);
            if (cmpl_ret == -EBUSY && more == 0) {
                ret = -EBUSY;
                break;
            }
            /* Revisit: examine status */
            if (cq_entry.status)
                debug(DEBUG_MSG, "idx 0x%x status 0x%0x\n",
                      xdmi->cmplq_head, cq_entry.status);
            more = cmpl_ret;
        } while (more);
    }
    if (ret == -EBUSY) {
        /* Revisit: add to workqueue for later processing */
        goto out;
    }
    cmd->hdr.cmp_index = tail;
    cpu_addr = xdmi->cmdq_zpage->dma.cpu_addr;
    xdm_entry = &(((union zhpe_hw_wq_entry *)cpu_addr)[tail]);
    *xdm_entry = *cmd;
    xdmi->active_cmds++;
    /* update cmdq_tail_shadow & write to HW */
    xdmi->cmdq_tail_shadow = next_tail;
    xdm_qcm_write_val(next_tail, xdmi->hw_qcm_addr,
                      ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    ret = tail;

 out:
    spin_unlock(&xdmi->xdm_info_lock);
    return ret;
}

static int msg_rdm_get_cmpl(struct rdm_info *rdmi, struct zhpe_rdm_hdr *hdr,
                            union zhpe_msg *msg)
{
    int ret = 0;
    uint head, next_head;
    struct zhpe_rdm_entry *rdm_entry, *next_entry;
    void *cpu_addr;

    spin_lock(&rdmi->rdm_info_lock);
    head = rdmi->cmplq_head_shadow;
    cpu_addr = rdmi->cmplq_zpage->dma.cpu_addr;
    rdm_entry = &(((struct zhpe_rdm_entry *)cpu_addr)[head]);

    /* check valid bit */
    if (rdm_entry->hdr.valid != rdmi->cur_valid) {
        ret = -EBUSY;
        goto out;
    }
    /* copy RDM completion entry to caller */
    *hdr = rdm_entry->hdr;
    memcpy(msg, &rdm_entry->payload, sizeof(*msg));
    /* do mod-add to compute next head value */
    next_head = (head + 1) % rdmi->cmplq_ent;
    /* toggle cur_valid on wrap */
    if (next_head < head)
        rdmi->cur_valid = !rdmi->cur_valid;
    /* update cmplq_head_shadow & write to HW */
    rdmi->cmplq_head_shadow = next_head;
    rdm_qcm_write_val(next_head, rdmi->hw_qcm_addr,
                      ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
    /* peek at next entry to determine if it is valid */
    next_entry = &(((struct zhpe_rdm_entry *)cpu_addr)[next_head]);
    ret = (next_entry->hdr.valid == rdmi->cur_valid);

 out:
    spin_unlock(&rdmi->rdm_info_lock);
    return ret;
}

static inline void msg_setup_req_hdr(union zhpe_msg *msg,
                                     uint8_t opcode, uint32_t rspctxid)
{
    msg->hdr.version  = ZHPE_MSG_VERSION;
    msg->hdr.status   = ZHPE_MSG_OK;
    msg->hdr.msgid    = msg_alloc_msgid();
    msg->hdr.opcode   = opcode;
    msg->hdr.rspctxid = rspctxid;
}

static inline void msg_setup_rsp_hdr(union zhpe_msg *rsp_msg,
                                     union zhpe_msg *req_msg,
                                     int8_t status, uint32_t rspctxid)
{
    rsp_msg->hdr.version  = ZHPE_MSG_VERSION;
    rsp_msg->hdr.status   = status;
    rsp_msg->hdr.msgid    = req_msg->hdr.msgid;
    rsp_msg->hdr.opcode   = req_msg->hdr.opcode | ZHPE_MSG_RESPONSE;
    rsp_msg->hdr.rspctxid = rspctxid;
}

static inline int msg_send_cmd(struct xdm_info *xdmi,
                               union zhpe_msg *msg,
                               uint32_t dgcid, uint32_t rspctxid)
{
    union zhpe_hw_wq_entry cmd = { 0 };
    size_t size;

    /* fill in cmd */
    cmd.hdr.opcode = ZHPE_HW_OPCODE_ENQA;
    cmd.enqa.dgcid = dgcid;
    cmd.enqa.rspctxid = rspctxid;
    size = min(sizeof(*msg), sizeof(cmd.enqa.payload));
    memcpy(&cmd.enqa.payload, msg, size);
    /* send cmd */
    return msg_xdm_queue_cmd(xdmi, &cmd);
}

static int msg_insert_send_cmd(struct xdm_info *xdmi,
                               struct zhpe_msg_state *state,
                               uint32_t dgcid, uint32_t rspctxid)
{
    int                     ret;
    union zhpe_msg          *req_msg;
    struct zhpe_msg_state   *found;

    state->dgcid = dgcid;
    state->rspctxid = rspctxid;
    req_msg = &state->req_msg;
    /* add state to msg state rbtree */
    found = msg_state_insert(state);
    if (found != state) {
        ret = -EEXIST;
        goto out;
    }
    /* send cmd */
    ret = msg_send_cmd(xdmi, req_msg, dgcid, rspctxid);

 out:
    return ret;
}

static int msg_wait_timeout(struct zhpe_msg_state *state, ktime_t timeout)
{
    int ret;

    debug(DEBUG_MSG, "waiting for reply to msgid=%u, timeout %lld\n",
          state->req_msg.hdr.msgid, ktime_to_ns(timeout));
    ret = wait_event_interruptible_hrtimeout(state->wq, state->ready,
                                             timeout);
    if (ret < 0) {  /* interrupted or timout expired */
        debug(DEBUG_MSG, "wait on msgid=%u returned ret=%d\n",
              state->req_msg.hdr.msgid, ret);
        goto out;
    }

    if (state->rsp_msg.hdr.status != 0) {
        debug(DEBUG_MSG, "response for msgid=%u returned status=%d\n",
              state->rsp_msg.hdr.msgid, state->rsp_msg.hdr.status);
        ret = -EINVAL;
    }

 out:
    return ret;
}

static int msg_wait(struct zhpe_msg_state *state)
{
    return msg_wait_timeout(state, get_timeout());
}

void zhpe_msg_list_wait(struct list_head *msg_wait_list, ktime_t start)
{
    int                     status = 0;
    ktime_t                 timeout = get_timeout();
    struct zhpe_msg_state   *state, *next;
    ktime_t                 now, remaining;

    list_for_each_entry_safe(state, next, msg_wait_list, msg_list) {
        if (status >= 0) {
            now = ktime_sub(ktime_get(), start);
            if (ktime_compare(timeout, now) > 0) {
                remaining = ktime_sub(timeout, now);
                status = msg_wait_timeout(state, remaining);
            } else
                status = -ETIME;
        }
        list_del(&state->msg_list);
        msg_state_free(state);
    }
}

static int msg_insert_send_cmd_wait(struct xdm_info *xdmi,
                                    struct zhpe_msg_state *state,
                                    uint32_t dgcid, uint32_t rspctxid)
{
    int                     ret;

    ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);
    if (ret < 0)
        goto out;

    ret = msg_wait(state);

 out:
    return ret;
}

static int msg_req_NOP(struct rdm_info *rdmi, struct xdm_info *xdmi,
                       struct zhpe_rdm_hdr *req_hdr,
                       union zhpe_msg *req_msg)
{
    uint32_t         rspctxid = req_msg->hdr.rspctxid;
    union zhpe_msg   rsp_msg = { 0 };
    uint64_t         seq;
    char             str[GCID_STRING_LEN+1];

    seq = req_msg->req.nop.seq;
    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
          zhpe_gcid_str(req_hdr->sgcid, str, sizeof(str)),
          req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid, seq);
    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, ZHPE_MSG_OK, rdmi->rspctxid);
    rsp_msg.rsp.nop.seq = req_msg->req.nop.seq;
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_NOP(struct zhpe_rdm_hdr *rsp_hdr,
                       union zhpe_msg *rsp_msg)
{
    int ret = 0;
    uint32_t rspctxid = rsp_msg->hdr.rspctxid;
    uint64_t seq;
    char str[GCID_STRING_LEN+1];

    seq = rsp_msg->rsp.nop.seq;
    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
          zhpe_gcid_str(rsp_hdr->sgcid, str, sizeof(str)),
          rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid, seq);
    return ret;
}

static int msg_req_UUID_IMPORT(struct rdm_info *rdmi, struct xdm_info *xdmi,
                       struct zhpe_rdm_hdr *req_hdr,
                       union zhpe_msg *req_msg)
{
    int                    status = ZHPE_MSG_OK;
    uint32_t               rspctxid = req_msg->hdr.rspctxid;
    uint32_t               ro_rkey = 0, rw_rkey = 0;
    uuid_t                 *src_uuid = &req_msg->req.uuid_import.src_uuid;
    uuid_t                 *tgt_uuid = &req_msg->req.uuid_import.tgt_uuid;
    struct uuid_tracker    *suu, *tuu;
    struct file_data       *fdata;
    struct uuid_node       *node;
    union zhpe_msg         rsp_msg = { 0 };
    char                   gcstr[GCID_STRING_LEN+1];
    char                   suustr[UUID_STRING_LEN+1];
    char                   tuustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s, tgt_uuid=%s\n",
          zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
          req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));
    if (req_hdr->sgcid != zhpe_gcid_from_uuid(src_uuid)) {
        status = ZHPE_MSG_ERR_UUID_GCID_MISMATCH;
        debug(DEBUG_MSG, "src_uuid=%s GCID mismatch (%s)\n",
              suustr, zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
        goto respond;
    }
    if (!zhpe_uuid_is_local(rdmi->br, tgt_uuid)) {
        status = ZHPE_MSG_ERR_UUID_NOT_LOCAL;
        debug(DEBUG_MSG, "tgt_uuid=%s not local\n", tuustr);
        goto respond;
    }
    tuu = zhpe_uuid_search(tgt_uuid);
    if (!tuu) {
        status = ZHPE_MSG_ERR_NO_UUID;
        debug(DEBUG_MSG, "tgt_uuid=%s not found\n", tuustr);
        goto respond;
    }
    /* we now hold a reference to tuu */
    fdata = tuu->local->fdata;
    suu = zhpe_uuid_tracker_alloc_and_insert(src_uuid, UUID_TYPE_REMOTE, 0,
                                             fdata, GFP_ATOMIC, &status);
    if (status == -EEXIST) {  /* duplicates ok */
        status = 0;
    } else if (status < 0) {
        status = ZHPE_MSG_ERR_NO_MEMORY;
        goto tuu_remove;
    }
    /* and we hold a reference to suu */
    node = zhpe_remote_uuid_alloc_and_insert(suu, &fdata->uuid_lock,
                                             &tuu->local->uu_remote_uuid_tree,
                                             GFP_ATOMIC, &status);
    if (status < 0) {
        status = (status == -EEXIST) ?
            ZHPE_MSG_ERR_UUID_ALREADY_THERE : ZHPE_MSG_ERR_NO_MEMORY;
        zhpe_uuid_remove(suu);
        goto tuu_remove;
    }

    ro_rkey = fdata->ro_rkey;
    rw_rkey = fdata->rw_rkey;

 tuu_remove:
    zhpe_uuid_remove(tuu);

 respond:
    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
    uuid_copy(&rsp_msg.rsp.uuid_import.src_uuid, src_uuid);
    uuid_copy(&rsp_msg.rsp.uuid_import.tgt_uuid, tgt_uuid);
    rsp_msg.rsp.uuid_import.ro_rkey = ro_rkey;
    rsp_msg.rsp.uuid_import.rw_rkey = rw_rkey;
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_IMPORT(struct zhpe_rdm_hdr *rsp_hdr,
                               union zhpe_msg *rsp_msg)
{
    int                    ret = 0;
    uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
    uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_import.src_uuid;
    uuid_t                 *tgt_uuid = &rsp_msg->rsp.uuid_import.tgt_uuid;
    char                   gcstr[GCID_STRING_LEN+1];
    char                   suustr[UUID_STRING_LEN+1];
    char                   tuustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s, tgt_uuid=%s, ro_rkey=0x%08x, rw_rkey=0x%08x\n",
          zhpe_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
          rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          rsp_msg->rsp.uuid_import.ro_rkey, rsp_msg->rsp.uuid_import.rw_rkey);

    return ret;
}

static int msg_req_UUID_FREE(struct rdm_info *rdmi, struct xdm_info *xdmi,
                       struct zhpe_rdm_hdr *req_hdr,
                       union zhpe_msg *req_msg)
{
    int                    status = ZHPE_MSG_OK;
    uint32_t               rspctxid = req_msg->hdr.rspctxid;
    uuid_t                 *src_uuid = &req_msg->req.uuid_free.src_uuid;
    uuid_t                 *tgt_uuid = &req_msg->req.uuid_free.tgt_uuid;
    struct uuid_tracker    *tuu;
    struct file_data       *fdata;
    union zhpe_msg         rsp_msg = { 0 };
    char                   gcstr[GCID_STRING_LEN+1];
    char                   suustr[UUID_STRING_LEN+1];
    char                   tuustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s, tgt_uuid=%s\n",
          zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
          req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));
    if (req_hdr->sgcid != zhpe_gcid_from_uuid(src_uuid)) {
        status = ZHPE_MSG_ERR_UUID_GCID_MISMATCH;
        debug(DEBUG_MSG, "src_uuid=%s GCID mismatch (%s)\n",
              suustr, zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
        goto respond;
    }
    if (!zhpe_uuid_is_local(rdmi->br, tgt_uuid)) {
        status = ZHPE_MSG_ERR_UUID_NOT_LOCAL;
        debug(DEBUG_MSG, "tgt_uuid=%s not local\n", tuustr);
        goto respond;
    }
    tuu = zhpe_uuid_search(tgt_uuid);
    if (!tuu) {
        status = ZHPE_MSG_ERR_NO_UUID;
        debug(DEBUG_MSG, "tgt_uuid=%s not found\n", tuustr);
        goto respond;
    }
    /* we now hold a reference to tuu */
    fdata = tuu->local->fdata;
    status = zhpe_free_uuid_node(fdata, &fdata->uuid_lock,
                                 &tuu->local->uu_remote_uuid_tree,
                                 src_uuid, false);
    if (status < 0) {
        status = ZHPE_MSG_ERR_NO_UUID;  /* Revisit: unique error? */
        goto tuu_remove;
    }

 tuu_remove:
    zhpe_uuid_remove(tuu);

 respond:
    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
    uuid_copy(&rsp_msg.rsp.uuid_free.src_uuid, src_uuid);
    uuid_copy(&rsp_msg.rsp.uuid_free.tgt_uuid, tgt_uuid);
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_FREE(struct zhpe_rdm_hdr *rsp_hdr,
                             union zhpe_msg *rsp_msg)
{
    int                    ret = 0;
    uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
    uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_free.src_uuid;
    uuid_t                 *tgt_uuid = &rsp_msg->rsp.uuid_free.tgt_uuid;
    char                   gcstr[GCID_STRING_LEN+1];
    char                   suustr[UUID_STRING_LEN+1];
    char                   tuustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s, tgt_uuid=%s\n",
          zhpe_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
          rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));

    return ret;
}

static int msg_req_UUID_TEARDOWN(struct rdm_info *rdmi, struct xdm_info *xdmi,
                       struct zhpe_rdm_hdr *req_hdr,
                       union zhpe_msg *req_msg)
{
    int                    status = ZHPE_MSG_OK;
    uint32_t               rspctxid = req_msg->hdr.rspctxid;
    uuid_t                 *src_uuid = &req_msg->req.uuid_teardown.src_uuid;
    union zhpe_msg         rsp_msg = { 0 };
    char                   gcstr[GCID_STRING_LEN+1];
    char                   uustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s\n",
          zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
          req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, uustr, sizeof(uustr)));
    if (req_hdr->sgcid != zhpe_gcid_from_uuid(src_uuid)) {
        status = ZHPE_MSG_ERR_UUID_GCID_MISMATCH;
        debug(DEBUG_MSG, "src_uuid=%s GCID mismatch (%s)\n",
              uustr, zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
        goto respond;
    }
    status = zhpe_teardown_remote_uuid(src_uuid);

 respond:
    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
    uuid_copy(&rsp_msg.rsp.uuid_teardown.src_uuid, src_uuid);
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_TEARDOWN(struct zhpe_rdm_hdr *rsp_hdr,
                             union zhpe_msg *rsp_msg)
{
    int                    ret = 0;
    uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
    uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_teardown.src_uuid;
    char                   gcstr[GCID_STRING_LEN+1];
    char                   uustr[UUID_STRING_LEN+1];

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u,"
          " src_uuid=%s\n",
          zhpe_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
          rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
          zhpe_uuid_str(src_uuid, uustr, sizeof(uustr)));

    return ret;
}

static int msg_req_ERROR(struct rdm_info *rdmi, struct xdm_info *xdmi,
                         struct zhpe_rdm_hdr *req_hdr,
                         union zhpe_msg *req_msg, int status)
{
    uint32_t               rspctxid;
    uint                   msgid;
    union zhpe_msg         rsp_msg = { 0 };
    char                   gcstr[GCID_STRING_LEN+1];

    if (status == ZHPE_MSG_ERR_UNKNOWN_VERSION) {
        rspctxid = rdmi->rspctxid;
        msgid    = 0;
    } else {
        rspctxid = req_msg->hdr.rspctxid;
        msgid    = req_msg->hdr.msgid;
    }

    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u\n",
          zhpe_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
          req_hdr->reqctxid, rspctxid, msgid);

    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static irqreturn_t msg_rdm_interrupt_handler(int irq_index, void *data)
{
    struct bridge *br = (struct bridge *)data;

    schedule_work(&br->msg_work);

    return IRQ_HANDLED;
}

void zhpe_msg_worker(struct work_struct *work)
{
    struct bridge *br = container_of(work, struct bridge, msg_work);
    struct xdm_info *xdmi = &br->msg_xdm;
    struct rdm_info *rdmi = &br->msg_rdm;
    int ret;
    bool more, response;
    uint handled = 0, tail, opcode;
    uint32_t rspctxid;
    struct zhpe_rdm_hdr msg_hdr;
    union zhpe_msg msg;
    struct zhpe_msg_state  *state;
    char sgstr[GCID_STRING_LEN+1];
    char dgstr[GCID_STRING_LEN+1];

    do {
        do {
            ret = msg_rdm_get_cmpl(rdmi, &msg_hdr, &msg);
            if (ret == -EBUSY) {  /* no cmpl - spurious interrupt */
                debug(DEBUG_MSG, "spurious, ret=%d\n", ret);
                goto out;
            } else if (ret < 0) {
                debug(DEBUG_MSG, "unknown error, ret=%d\n", ret);
                goto out;
            }
            more = ret;
            handled++;

            rspctxid = msg.hdr.rspctxid;
            debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, version=%u, opcode=0x%x,"
                  " status=%d, rspctxid=%u, handled=%u, more=%u\n",
                  zhpe_gcid_str(msg_hdr.sgcid, sgstr, sizeof(sgstr)),
                  msg_hdr.reqctxid, msg.hdr.version, msg.hdr.opcode,
                  msg.hdr.status, rspctxid, handled, more);
            /* Revisit: verify that msg came from reqctxid 0? */
            if (msg.hdr.version != ZHPE_MSG_VERSION) {
                /* if we don't recognize the version, we can't know
                 * anything else about the message (status, opcode,
                 * rspctxid), so we can't do anything
                 */
                ret = -EINVAL;
                debug(DEBUG_MSG, "UNKNOWN_VERSION, ret=%d\n", ret);
                continue;
            }
            response = (msg.hdr.opcode & ZHPE_MSG_RESPONSE) != 0;
            opcode   = msg.hdr.opcode & ~ZHPE_MSG_RESPONSE;
            if (response) {
                state = msg_state_search(msg.hdr.msgid);
                if (!state) {
                    debug(DEBUG_MSG, "msg_state_search for msgid=%u failed\n",
                          msg.hdr.msgid);
                    continue;
                }
                switch (opcode) {
                case ZHPE_MSG_NOP:
                    ret = msg_rsp_NOP(&msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_IMPORT:
                    ret = msg_rsp_UUID_IMPORT(&msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_FREE:
                    ret = msg_rsp_UUID_FREE(&msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_TEARDOWN:
                    ret = msg_rsp_UUID_TEARDOWN(&msg_hdr, &msg);
                    break;
                default:
                    debug(DEBUG_MSG, "unknown opcode 0x%x for msgid=%u\n",
                          msg.hdr.opcode, msg.hdr.msgid);
                    continue;
                }
                if (msg_hdr.sgcid != state->dgcid) {
                    debug(DEBUG_MSG,
                          "msg SGCID (%s) != state DGCID (%s) for msgid=%u\n",
                          zhpe_gcid_str(msg_hdr.sgcid, sgstr, sizeof(sgstr)),
                          zhpe_gcid_str(state->dgcid, dgstr, sizeof(dgstr)),
                          msg.hdr.msgid);
                    continue;
                }
                state->rsp_msg = msg;
                state->ready = true;
                wake_up_interruptible(&state->wq);
            } else {  /* request */
                switch (opcode) {
                case ZHPE_MSG_NOP:
                    ret = msg_req_NOP(rdmi, xdmi, &msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_IMPORT:
                    ret = msg_req_UUID_IMPORT(rdmi, xdmi, &msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_FREE:
                    ret = msg_req_UUID_FREE(rdmi, xdmi, &msg_hdr, &msg);
                    break;
                case ZHPE_MSG_UUID_TEARDOWN:
                    ret = msg_req_UUID_TEARDOWN(rdmi, xdmi, &msg_hdr, &msg);
                    break;
                default:
                    ret = msg_req_ERROR(rdmi, xdmi, &msg_hdr, &msg,
                                        ZHPE_MSG_ERR_UNKNOWN_OPCODE);
                    break;
                }
            }
        } while (more);
        /* read tail to prevent race with HW writing new completions */
        tail = rdm_qcm_read(rdmi->hw_qcm_addr,
                            ZHPE_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET) &
            ZHPE_MAX_RDM_QLEN;
    } while (rdmi->cmplq_head_shadow != tail);

 out:
    return;
}

int zhpe_msg_send_UUID_IMPORT(struct bridge *br,
                              uuid_t *src_uuid, uuid_t *tgt_uuid,
                              uint32_t *ro_rkey, uint32_t *rw_rkey)
{
    struct xdm_info         *xdmi = &br->msg_xdm;
    struct rdm_info         *rdmi = &br->msg_rdm;
    int                     ret = 0;
    uint32_t                dgcid = zhpe_gcid_from_uuid(tgt_uuid);
    uint32_t                rspctxid = rdmi->rspctxid;
    struct zhpe_msg_state   *state;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
              zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
              zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));
        ret = -ENOMEM;
        goto out;
    }
    /* fill in req_msg */
    req_msg = &state->req_msg;
    msg_setup_req_hdr(req_msg, ZHPE_MSG_UUID_IMPORT, rspctxid);
    uuid_copy(&req_msg->req.uuid_import.src_uuid, src_uuid);
    uuid_copy(&req_msg->req.uuid_import.tgt_uuid, tgt_uuid);
    debug(DEBUG_MSG,
          "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    /* send cmd and wait for reply */
    ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
    if (ret < 0)
        goto state_free;

    *ro_rkey = state->rsp_msg.rsp.uuid_import.ro_rkey;
    *rw_rkey = state->rsp_msg.rsp.uuid_import.rw_rkey;

 state_free:
    msg_state_free(state);
 out:
    return ret;
}
struct zhpe_msg_state *zhpe_msg_send_UUID_FREE(struct bridge *br,
                                               uuid_t *src_uuid,
                                               uuid_t *tgt_uuid, bool wait)
{
    struct xdm_info         *xdmi = &br->msg_xdm;
    struct rdm_info         *rdmi = &br->msg_rdm;
    int                     ret = 0;
    uint32_t                dgcid = zhpe_gcid_from_uuid(tgt_uuid);
    uint32_t                rspctxid = rdmi->rspctxid;
    struct zhpe_msg_state   *state;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
              zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
              zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));
        ret = -ENOMEM;
        goto out;
    }
    /* fill in req_msg */
    req_msg = &state->req_msg;
    msg_setup_req_hdr(req_msg, ZHPE_MSG_UUID_FREE, rspctxid);
    uuid_copy(&req_msg->req.uuid_free.src_uuid, src_uuid);
    uuid_copy(&req_msg->req.uuid_free.tgt_uuid, tgt_uuid);
    debug(DEBUG_MSG,
          "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    if (wait) {
        /* send cmd and wait for reply */
        ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
        msg_state_free(state);
        state = NULL;
    } else {
        /* send cmd (no wait) */
        ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);
    }

 out:
    if (ret < 0 && state)
        msg_state_free(state);
    return (ret < 0) ? ERR_PTR(ret) : state;
}

struct zhpe_msg_state *zhpe_msg_send_UUID_TEARDOWN(struct bridge *br,
                                                   uuid_t *src_uuid,
                                                   uuid_t *tgt_uuid)
{
    struct xdm_info         *xdmi = &br->msg_xdm;
    struct rdm_info         *rdmi = &br->msg_rdm;
    int                     ret = 0;
    uint32_t                dgcid = zhpe_gcid_from_uuid(tgt_uuid);
    uint32_t                rspctxid = rdmi->rspctxid;
    struct zhpe_msg_state   *state;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
              zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
              zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)));
        ret = -ENOMEM;
        goto out;
    }
    /* fill in req_msg */
    req_msg = &state->req_msg;
    msg_setup_req_hdr(req_msg, ZHPE_MSG_UUID_TEARDOWN, rspctxid);
    uuid_copy(&req_msg->req.uuid_teardown.src_uuid, src_uuid);
    uuid_copy(&req_msg->req.uuid_teardown.tgt_uuid, tgt_uuid);
    debug(DEBUG_MSG,
          "dgcid=%s, rspctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    /* send cmd (no wait) */
    ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);

 out:
    if (ret < 0 && state)
        msg_state_free(state);
    return (ret < 0) ? ERR_PTR(ret) : state;
}

int zhpe_msg_qalloc(struct bridge *br)
{
    int ret = 0;
    struct xdm_info *xdmi = &br->msg_xdm;
    struct rdm_info *rdmi = &br->msg_rdm;

    /* Set up the XDM info structure */
    xdmi->br = br;
    xdmi->cmdq_ent = 64;
    xdmi->cmplq_ent = 64;
    xdmi->traffic_class = ZHPE_TC_0;
    xdmi->priority = 0;
    xdmi->slice_mask = ALL_SLICES;
    xdmi->cur_valid = 1;
    ret = zhpe_kernel_XQALLOC(xdmi);
    if (ret)
        goto done;

    /* Set up the RDM info structure */
    rdmi->br = br;
    rdmi->cmplq_ent = 128;
    rdmi->slice_mask = SLICE_DEMAND|0x1;  /* slice 0 only */
    rdmi->cur_valid = 1;
    ret = zhpe_kernel_RQALLOC(rdmi);
    if (ret)
        goto xqfree;
    if (rdmi->rspctxid != 0) { /* must be 0 for driver-driver msg RDM */
        ret = -EBUSY;
        goto rqfree;
    }

    ret = zhpe_register_rdm_interrupt(rdmi->sl, rdmi->queue,
                                      msg_rdm_interrupt_handler, br);
    if (ret)
        goto rqfree;

    /* clear stop bits - queues are now ready */
    xdm_qcm_write_val(0, xdmi->hw_qcm_addr, XDM_STOP_OFFSET);
    rdm_qcm_write_val(0, rdmi->hw_qcm_addr, RDM_STOP_OFFSET);

    return 0;

 rqfree:
    zhpe_kernel_RQFREE(rdmi);

 xqfree:
    zhpe_kernel_XQFREE(xdmi);

 done:
    return ret;
}

int zhpe_msg_qfree(struct bridge *br)
{
    int ret = 0;

    ret |= zhpe_kernel_XQFREE(&br->msg_xdm);
    ret |= zhpe_kernel_RQFREE(&br->msg_rdm);

    return ret;
}

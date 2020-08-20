/*
 * Copyright (C) 2018-2020 Hewlett Packard Enterprise Development LP.
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

static bool msg_xdm_get_cmpl(struct xdm_info *xdmi);
static void print_cmd(union zhpe_hw_wq_entry *cmd, uint status);

static inline ktime_t get_timeout(void)
{
    return ktime_set((zhpe_kmsg_timeout > 0 ? zhpe_kmsg_timeout : 10), 0);
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

char *msg_names[] = {"zero", "NOP", "UUID_IMPORT",
                     "UUID_FREE", "UUID_TEARDOWN"};

static inline char *msg_name(uint cmd)
{
    cmd &= ~ZHPE_MSG_RESPONSE;
    if (cmd < ZHPE_NR_MSG_CMDS)
        return msg_names[cmd];
    else
        return "unknown";
}

static void print_cmd(union zhpe_hw_wq_entry *cmd, uint status)
{
    struct zhpe_hw_wq_enqa *enqa;
    struct zhpe_msg_hdr *hdr;
    char                gcstr[GCID_STRING_LEN+1];
    char                *cmd_name;
    bool                rsp;

    if (cmd->hdr.opcode == ZHPE_HW_OPCODE_ENQA) {
        enqa = &cmd->enqa;
        hdr = (struct zhpe_msg_hdr *)&enqa->payload;
        rsp = (hdr->opcode & ZHPE_MSG_RESPONSE) != 0;
        cmd_name = msg_name(hdr->opcode);
        zprintk(KERN_WARNING, "cmd=%s%s, cmp_index=%hu,"
                " status=0x%02hx, msgid=%hu, rspctxid=0x%x, dgcid=%s\n",
                cmd_name, rsp ? "_RSP" : "", cmd->hdr.cmp_index, status,
                hdr->msgid, enqa->rspctxid,
                zhpe_gcid_str(enqa->dgcid, gcstr, sizeof(gcstr)));
    } else
        zprintk(KERN_ERR, "XDM opcode=0x%04hx, cmp_index=%hu, status=0x%02hx\n",
                cmd->hdr.opcode, cmd->hdr.cmp_index, status);
}

static void msg_q0_dump(struct xdm_info *xdmi)
{
    uint32_t            qmask = xdmi->cmdq_ent - 1;
    uint                slot;

    spin_lock(&xdmi->xdm_info_lock);
    while (msg_xdm_get_cmpl(xdmi));
    for (slot = find_first_bit(xdmi->cmdq_free_bitmap, qmask);
         slot != qmask;
         slot = find_next_bit(xdmi->cmdq_free_bitmap, qmask, slot + 1))
        print_cmd(&xdmi->cmdq_shadow[slot], 0);
    spin_unlock(&xdmi->xdm_info_lock);
}

void msg_state_dump(struct xdm_info *xdmi)
{
    struct zhpe_msg_state *ms;
    struct zhpe_msg_state *tmp;
    char                gcstr[GCID_STRING_LEN+1];
    char                *cmd_name;
    bool                rsp;

    msg_q0_dump(xdmi);

    spin_lock(&zhpe_msg_rbtree_lock);
    rbtree_postorder_for_each_entry_safe(ms, tmp, &msg_rbtree, node) {
        rsp = (ms->req_msg.hdr.opcode & ZHPE_MSG_RESPONSE) != 0;
        cmd_name = msg_name(ms->req_msg.hdr.opcode);
        zprintk(KERN_WARNING, "cmd=%s%s, msgid=%hu, rspctxid=%u, dgcid=%s\n",
                cmd_name, rsp ? "_RSP" : "",
                ms->req_msg.hdr.msgid, ms->rspctxid,
                zhpe_gcid_str(ms->dgcid, gcstr, sizeof(gcstr)));
    }
    spin_unlock(&zhpe_msg_rbtree_lock);
}

static void xdm_cmd_error(struct xdm_info *xdmi, uint slot, uint status)
{
    union zhpe_hw_wq_entry *cmd;

    cmd = &xdmi->cmdq_shadow[slot];
    if (cmd->hdr.opcode != ZHPE_HW_OPCODE_ENQA ||
        status != ZHPE_HW_CQ_STATUS_GENZ_UNSUPPORTED_SVC ||
        cmd->enqa.rspctxid >= ZHPE_MAX_SLICES)
        print_cmd(cmd, status);
}

static bool msg_xdm_get_cmpl(struct xdm_info *xdmi)
{
    uint32_t            qmask = xdmi->cmplq_ent - 1;
    union zhpe_hw_cq_entry *hw_entries = xdmi->cmplq_zpage->dma.cpu_addr;
    struct zhpe_cq_entry *cmplq_entry;
    uint32_t            head;
    uint                status;
    uint                slot;

    /* Caller must hold xdm_info_lock */
    head = xdmi->cmplq_head & qmask;
    cmplq_entry = &hw_entries[head].entry;

    if (!zhpe_cqe_valid(cmplq_entry, head, qmask))
        return false;

    /* Revisit: retry handling. */
    slot = cmplq_entry->hdr.index;
    status = cmplq_entry->hdr.status;
    if (unlikely(!test_bit(slot, xdmi->cmdq_free_bitmap))) {
        zprintk(KERN_ERR, "slot %u already free\n", slot);
        /* Set status to a reserved value if no error. */
        if (likely(!status))
            status = 0xFF;
    } else
        __clear_bit(slot, xdmi->cmdq_free_bitmap);
    xdmi->cmplq_head++;
    xdmi->active_cmds--;
    if (unlikely(status))
        xdm_cmd_error(xdmi, slot, status);

    return true;
}

static bool msg_rdm_get_cmpl(struct rdm_info *rdmi, struct zhpe_rdm_hdr *hdr,
                             union zhpe_msg *msg)
{
    int                 ret = false;
    uint32_t            qmask = rdmi->cmplq_ent - 1;
    union zhpe_hw_rdm_entry *hw_entries = rdmi->cmplq_zpage->dma.cpu_addr;
    uint32_t            head;
    uint32_t            tail;
    struct zhpe_rdm_entry *rdm_entry;

    spin_lock(&rdmi->rdm_info_lock);

    /* Get the pointer to the current entry. */
    head = rdmi->cmplq_head_shadow & qmask;
    rdm_entry = &hw_entries[head].entry;

    /* Check valid bit and exit if nothing available. */
    for (;;) {
        if (likely(zhpe_rqe_valid(rdm_entry, rdmi->cmplq_head_shadow, qmask)))
            break;
        /* Commit the head, if needed, to enable interrupts. */
        if (unlikely(rdmi->cmplq_head_shadow == rdmi->cmplq_head_commit))
            goto out;
        rdmi->cmplq_head_commit = rdmi->cmplq_head_shadow;
        rdm_qcm_write_val(head, rdmi->hw_qcm_addr,
                          ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
        /* An interrupt race exists when writing the head, so check the tail. */
        tail = rdm_qcm_read(rdmi->hw_qcm_addr,
                            ZHPE_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET) & qmask;
        if (likely((head == tail)))
            goto out;
        rmb();
    }

    /* Copy RDM completion entry to caller. */
    ret = true;
    *hdr = rdm_entry->hdr;
    memcpy(msg, &rdm_entry->payload, sizeof(*msg));

    /* Update cmplq_head_shadow & write head, if necessary. */
    rdmi->cmplq_head_shadow++;
    if  (likely(rdmi->cmplq_head_shadow - rdmi->cmplq_head_commit <
                (qmask + 1) / 4))
         goto out;

    /* Keep head one back to prevent extra interrupts. */
    rdmi->cmplq_head_commit = rdmi->cmplq_head_shadow - 1;
    head = rdmi->cmplq_head_commit & qmask;
    rdm_qcm_write_val(head, rdmi->hw_qcm_addr,
                      ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);

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
    int                 ret;
    uint32_t            qmask = xdmi->cmdq_ent - 1;
    union zhpe_hw_wq_entry *hw_entries = xdmi->cmdq_zpage->dma.cpu_addr;
    union zhpe_hw_wq_entry *cmdq_shadow;
    union zhpe_hw_wq_entry *cmdq_entry;
    uint                slot;
    uint32_t            tail;
    size_t              size;
    int                 i;

    if (!xdmi->sl)
        return -ENXIO;

    spin_lock(&xdmi->xdm_info_lock);
    /* Try to process two completions, a bias towards completions. */
    for (i = 0; i < 2 && msg_xdm_get_cmpl(xdmi); i++);
    /* Find a free slot. */
    slot = find_first_zero_bit(xdmi->cmdq_free_bitmap, qmask);
    if (slot == qmask) {
        ret = -EBUSY;
        goto out;
    }
    __set_bit(slot, xdmi->cmdq_free_bitmap);
    xdmi->active_cmds++;
    tail = xdmi->cmdq_tail_shadow++ & qmask;

    /* fill in cmd */
    cmdq_shadow = &xdmi->cmdq_shadow[slot];
    cmdq_shadow->hdr.opcode = ZHPE_HW_OPCODE_ENQA;
    cmdq_shadow->hdr.cmp_index = slot;
    cmdq_shadow->enqa.dgcid = dgcid;
    cmdq_shadow->enqa.rspctxid = rspctxid;
    size = min(sizeof(*msg), sizeof(cmdq_shadow->enqa.payload));
    memcpy(&cmdq_shadow->enqa.payload, msg, size);

    /* send cmd */
    cmdq_entry = &hw_entries[tail];
    memcpy(cmdq_entry, cmdq_shadow, sizeof(*cmdq_entry));
    dma_wmb();
    xdm_qcm_write_val((tail + 1) & qmask, xdmi->hw_qcm_addr,
                      ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    ret = slot;

 out:
    spin_unlock(&xdmi->xdm_info_lock);

    return ret;
}

static int msg_insert_send_cmd(struct xdm_info *xdmi,
                               struct zhpe_msg_state *state,
                               uint32_t dgcid, uint32_t rspctxid)
{
    int                 ret;
    union zhpe_msg      *req_msg;
    struct zhpe_msg_state *found;

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
    /*
     * Used to be interruptible and this was mistake that caused hangs
     * in the "remote" thread in the loopback case. This is probably
     * needs reference counting of some form, but I'm just going to
     * step on the signals for now.
     */
    ret = wait_event_hrtimeout(state->wq, state->ready, timeout);
    if (ret < 0) {  /* interrupted or timeout expired */
        debug(DEBUG_MSG, "wait on msgid=%u returned ret=%d\n",
              state->req_msg.hdr.msgid, ret);
        goto out;
    }
    if (state->rsp_msg.hdr.status != 0)
        debug(DEBUG_MSG, "response for msgid=%u returned status=%d\n",
              state->rsp_msg.hdr.msgid, state->rsp_msg.hdr.status);

 out:
    return ret;
}

static int msg_wait(struct zhpe_msg_state *state)
{
    return msg_wait_timeout(state, get_timeout());
}

void zhpe_msg_list_wait(struct list_head *msg_wait_list, ktime_t start)
{
    ktime_t                 timeout = get_timeout();
    struct zhpe_msg_state   *state, *next;
    ktime_t                 now, remaining;

    list_for_each_entry_safe(state, next, msg_wait_list, msg_list) {
        now = ktime_sub(ktime_get(), start);
        if (ktime_compare(timeout, now) > 0)
            remaining = ktime_sub(timeout, now);
        else
            remaining = ktime_set(0, 0);
        /* We force everyone though msg_wait_timeout() for diagnostics. */
        (void)msg_wait_timeout(state, remaining);
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

static struct zhpe_msg_id *msg_rspctxid_search(struct bridge *br,
                                               uint32_t dgcid)
{
    struct zhpe_msg_id *id;
    struct rb_node *node;
    struct rb_root *root = &br->rspctxid_rbtree;

    spin_lock(&br->rspctxid_rbtree_lock);
    node = root->rb_node;

    while (node) {
        int result;

        id = container_of(node, struct zhpe_msg_id, node);
        result = arithcmp(dgcid, id->dgcid);
        if (result < 0) {
            node = node->rb_left;
        } else if (result > 0) {
            node = node->rb_right;
        } else {
            goto out;
        }
    }

    id = NULL;

 out:
    spin_unlock(&br->rspctxid_rbtree_lock);
    return id;
}

static struct zhpe_msg_id *msg_rspctxid_insert(struct bridge *br,
                                               uint32_t dgcid,
                                               uint32_t rspctxid)
{
    struct rb_root *root = &br->rspctxid_rbtree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct zhpe_msg_id *id;
    int ret = 0;

    id = do_kmalloc(sizeof(*id), GFP_KERNEL, true);
    if (!id) {
        ret = -ENOMEM;
        goto out;
    }
    id->dgcid = dgcid;
    id->rspctxid = rspctxid;

    spin_lock(&br->rspctxid_rbtree_lock);

    /* figure out where to put new node */
    while (*new) {
        struct zhpe_msg_id *this =
            container_of(*new, struct zhpe_msg_id, node);
        int result = arithcmp(id->dgcid, this->dgcid);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {  /* already there */
            do_kfree(id);
            id = this;
            goto unlock;
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&id->node, parent, new);
    rb_insert_color(&id->node, root);

 unlock:
    spin_unlock(&br->rspctxid_rbtree_lock);
 out:
    return (ret < 0) ? ERR_PTR(ret) : id;
}

static void msg_rspctxid_free(struct bridge *br)
{
    struct zhpe_msg_id *id, *next;

    spin_lock(&br->rspctxid_rbtree_lock);
    rbtree_postorder_for_each_entry_safe(id, next, &br->rspctxid_rbtree, node) {
        do_kfree(id);
    }
    br->rspctxid_rbtree = RB_ROOT;
    spin_unlock(&br->rspctxid_rbtree_lock);
}

static int msg_lookup_rspctxid(struct bridge *br, uint32_t dgcid,
                               uint32_t *rspctxid)
{
    struct zhpe_msg_id      *id;
    struct list_head        nop_msg_list;
    ktime_t                 start;
    uint32_t                tryctxid;
    struct zhpe_msg_state   *state;
    int                     sl, status, ret = 0;

    id = msg_rspctxid_search(br, dgcid);
    if (id != NULL)
        goto found;

    INIT_LIST_HEAD(&nop_msg_list);
    start = ktime_get();
    for (sl = 0; sl < SLICES; sl++) {
        tryctxid = zhpe_ctxid(sl, 0);
        state = zhpe_msg_send_NOP(br, dgcid, tryctxid, sl);
        if (IS_ERR(state)) {
            status = PTR_ERR(state);
            debug(DEBUG_MSG, "zhpe_msg_send_NOP to sl=%d, I/O error=%d\n",
                  sl, status);
            continue;
        }
        list_add_tail(&state->msg_list, &nop_msg_list);
    }

    /* wait for replies to all NOP messages - can sleep */
    zhpe_msg_list_wait(&nop_msg_list, start);

    id = msg_rspctxid_search(br, dgcid);
    if (id != NULL)
        goto found;
    ret = -ETIMEDOUT;
    *rspctxid = 0;
    return ret;

 found:
    *rspctxid = id->rspctxid;
    return ret;
}

static int msg_req_NOP(struct rdm_info *rdmi, struct xdm_info *xdmi,
                       struct zhpe_rdm_hdr *req_hdr,
                       union zhpe_msg *req_msg)
{
    uint32_t           rspctxid = req_msg->hdr.rspctxid;
    union zhpe_msg     rsp_msg = { 0 };
    uint64_t           seq;
    struct zhpe_msg_id *id;
    int8_t             status = ZHPE_MSG_OK;
    char               str[GCID_STRING_LEN+1];

    seq = req_msg->req.nop.seq;
    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
          zhpe_gcid_str(req_hdr->sgcid, str, sizeof(str)),
          req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid, seq);
    /* insert source rspctxid in our tracker */
    id = msg_rspctxid_insert(rdmi->br, req_hdr->sgcid, rspctxid);
    if (IS_ERR(id)) {
        status = ZHPE_MSG_ERR_NO_MEMORY;  /* this is the only error */
    }
    /* fill in rsp_msg */
    msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
    rsp_msg.rsp.nop.seq = req_msg->req.nop.seq;
    /* send cmd */
    return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_NOP(struct rdm_info *rdmi, struct zhpe_rdm_hdr *rsp_hdr,
                       union zhpe_msg *rsp_msg)
{
    int                ret = 0;
    uint32_t           rspctxid = rsp_msg->hdr.rspctxid;
    uint64_t           seq;
    struct zhpe_msg_id *id;
    char               str[GCID_STRING_LEN+1];

    seq = rsp_msg->rsp.nop.seq;
    debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
          zhpe_gcid_str(rsp_hdr->sgcid, str, sizeof(str)),
          rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid, seq);
    /* insert rspctxid in our tracker */
    id = msg_rspctxid_insert(rdmi->br, rsp_hdr->sgcid, rspctxid);
    if (IS_ERR(id)) {
        ret = PTR_ERR(id);
    }
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

static void process_msg(struct rdm_info *rdmi, struct xdm_info *xdmi,
                        struct zhpe_rdm_hdr *msg_hdr, union zhpe_msg *msg)
{
    int                 rc;
    struct zhpe_msg_state *state;
    uint                opcode;
    bool                response;
    char sgstr[GCID_STRING_LEN+1];
    char dgstr[GCID_STRING_LEN+1];

    response = !!(msg->hdr.opcode & ZHPE_MSG_RESPONSE);
    opcode = msg->hdr.opcode & ~ZHPE_MSG_RESPONSE;

    if (response) {
        state = msg_state_search(msg->hdr.msgid);
        if (!state) {
            debug(DEBUG_MSG, "msg_state_search for msgid=%u failed\n",
                  msg->hdr.msgid);
            return;
        }

        switch (opcode) {

        case ZHPE_MSG_NOP:
            rc = msg_rsp_NOP(rdmi, msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_IMPORT:
            rc = msg_rsp_UUID_IMPORT(msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_FREE:
            rc = msg_rsp_UUID_FREE(msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_TEARDOWN:
            rc = msg_rsp_UUID_TEARDOWN(msg_hdr, msg);
            break;

        default:
            debug(DEBUG_MSG, "unknown opcode 0x%x for msgid=%u\n",
                  msg->hdr.opcode, msg->hdr.msgid);
            return;
        }

        if (msg_hdr->sgcid != state->dgcid) {
            debug(DEBUG_MSG,
                  "msg SGCID (%s) != state DGCID (%s) for msgid=%u\n",
                  zhpe_gcid_str(msg_hdr->sgcid, sgstr, sizeof(sgstr)),
                  zhpe_gcid_str(state->dgcid, dgstr, sizeof(dgstr)),
                  msg->hdr.msgid);
            return;
        }
        debug(DEBUG_MSG, "wake up %u\n", msg->hdr.msgid);
        state->rsp_msg = *msg;
        state->ready = true;
        wake_up(&state->wq);

    } else {

        /* request */
        switch (opcode) {

        case ZHPE_MSG_NOP:
            rc = msg_req_NOP(rdmi, xdmi, msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_IMPORT:
            rc = msg_req_UUID_IMPORT(rdmi, xdmi, msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_FREE:
            rc = msg_req_UUID_FREE(rdmi, xdmi, msg_hdr, msg);
            break;

        case ZHPE_MSG_UUID_TEARDOWN:
            rc = msg_req_UUID_TEARDOWN(rdmi, xdmi, msg_hdr, msg);
            break;

        default:
            rc = msg_req_ERROR(rdmi, xdmi, msg_hdr, msg,
                               ZHPE_MSG_ERR_UNKNOWN_OPCODE);
            break;
        }

    }

    debug(DEBUG_MSG, "opcode 0x%x rc %d\n", opcode, rc);
}

void zhpe_msg_worker(struct work_struct *work)
{
    struct bridge       *br = container_of(work, struct bridge, msg_work);
    struct xdm_info     *xdmi = &br->msg_xdm;
    struct rdm_info     *rdmi = &br->msg_rdm;
    uint                handled = 0;
    uint32_t            rspctxid;
    struct zhpe_rdm_hdr msg_hdr;
    union zhpe_msg      msg;
    char                sgstr[GCID_STRING_LEN+1];

    while (likely(msg_rdm_get_cmpl(rdmi, &msg_hdr, &msg))) {
        rspctxid = msg.hdr.rspctxid;
        handled++;
        debug(DEBUG_MSG, "sgcid=%s, reqctxid=%u, version=%u, msgid=%u,"
              " opcode=0x%x, status=%d, rspctxid=%u, handled=%u\n",
              zhpe_gcid_str(msg_hdr.sgcid, sgstr, sizeof(sgstr)),
              msg_hdr.reqctxid, msg.hdr.version, msg.hdr.msgid,
              msg.hdr.opcode, msg.hdr.status, rspctxid, handled);
        /* Revisit: verify that msg came from reqctxid 0? */
        if (msg.hdr.version != ZHPE_MSG_VERSION) {
            /* if we don't recognize the version, we can't know
             * anything else about the message (status, opcode,
             * rspctxid), so we can't do anything
             */
            debug(DEBUG_MSG, "UNKNOWN_VERSION %d\n", msg.hdr.version);
            continue;
        }
        process_msg(rdmi, xdmi, &msg_hdr, &msg);
    }
}

struct zhpe_msg_state *zhpe_msg_send_NOP(struct bridge *br, uint32_t dgcid,
                                         uint32_t tgtctxid, uint64_t seq)
{
    struct xdm_info         *xdmi = &br->msg_xdm;
    struct rdm_info         *rdmi = &br->msg_rdm;
    uint32_t                rspctxid = rdmi->rspctxid;
    struct zhpe_msg_state   *state;
    union zhpe_msg          *req_msg;
    int                     ret = 0;
    char                    gcstr[GCID_STRING_LEN+1];

    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, dgcid=%s, tgtctxid=%u\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid);
        ret = -ENOMEM;
        goto out;
    }

    /* fill in req_msg */
    req_msg = &state->req_msg;
    msg_setup_req_hdr(req_msg, ZHPE_MSG_NOP, rspctxid);
    req_msg->req.nop.seq = seq;
    debug(DEBUG_MSG,
          "dgcid=%s, tgtctxid=%u, seq=%llu, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
          seq, req_msg->hdr.msgid);
    /* send cmd (no wait) */
    ret = msg_insert_send_cmd(xdmi, state, dgcid, tgtctxid);

 out:
    if (ret < 0 && state)
        msg_state_free(state);
    return (ret < 0) ? ERR_PTR(ret) : state;
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
    uint32_t                tgtctxid;
    struct zhpe_msg_state   *state;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    ret = msg_lookup_rspctxid(br, dgcid, &tgtctxid);
    if (ret < 0)
        goto out;
    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
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
          "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    /* send cmd and wait for reply */
    ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, tgtctxid);
    if (ret < 0)
        goto state_free;
    if (state->rsp_msg.hdr.status != 0) {
        ret = -EINVAL;
        goto state_free;
    }

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
    uint32_t                tgtctxid;
    struct zhpe_msg_state   *state = NULL;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    ret = msg_lookup_rspctxid(br, dgcid, &tgtctxid);
    if (ret < 0)
        goto out;
    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
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
          "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    if (wait) {
        /* send cmd and wait for reply */
        ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, tgtctxid);
        if (ret >= 0 && state->rsp_msg.hdr.status) {
            /* No UUID can happen if the remote process exits first. */
            if (state->rsp_msg.hdr.status == ZHPE_MSG_ERR_NO_UUID)
                ret = -ENOENT;
            else
                /* I can't think of a better errno for the rest. */
                ret = -EINVAL;
        }
        msg_state_free(state);
        state = NULL;
    } else {
        /* send cmd (no wait) */
        ret = msg_insert_send_cmd(xdmi, state, dgcid, tgtctxid);
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
    uint32_t                tgtctxid;
    struct zhpe_msg_state   *state = NULL;
    union zhpe_msg          *req_msg;
    char                    gcstr[GCID_STRING_LEN+1];
    char                    suustr[UUID_STRING_LEN+1];
    char                    tuustr[UUID_STRING_LEN+1];

    ret = msg_lookup_rspctxid(br, dgcid, &tgtctxid);
    if (ret < 0)
        goto out;
    state = msg_state_alloc();
    if (!state) {
        debug(DEBUG_MSG, "msg_state_alloc failed, "
              "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s\n",
              zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
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
          "dgcid=%s, tgtctxid=%u, src_uuid=%s, tgt_uuid=%s, msgid=%u\n",
          zhpe_gcid_str(dgcid, gcstr, sizeof(gcstr)), tgtctxid,
          zhpe_uuid_str(src_uuid, suustr, sizeof(suustr)),
          zhpe_uuid_str(tgt_uuid, tuustr, sizeof(tuustr)),
          req_msg->hdr.msgid);
    /* send cmd (no wait) */
    ret = msg_insert_send_cmd(xdmi, state, dgcid, tgtctxid);

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
    xdmi->cmdq_ent = msg_qsize;
    xdmi->cmplq_ent = msg_qsize;
    xdmi->traffic_class = ZHPE_TC_0;
    xdmi->priority = 0;
    xdmi->slice_mask = ALL_SLICES;
    ret = zhpe_kernel_XQALLOC(xdmi);
    if (ret)
        goto done;

    /* Set up the RDM info structure */
    rdmi->br = br;
    rdmi->cmplq_ent = msg_qsize;
    rdmi->slice_mask = SLICE_Q0|0x1;  /* require q0; slice 0 if possible */
    ret = zhpe_kernel_RQALLOC(rdmi);
    if (ret)
        goto xqfree;

    ret = zhpe_register_rdm_interrupt(rdmi->sl, rdmi->queue,
                                      msg_rdm_interrupt_handler, br);
    if (ret)
        goto rqfree;

    /* clear stop bits - queues are now ready */
    xdm_qcm_write_val(0, xdmi->hw_qcm_addr, ZHPE_XDM_QCM_STOP_OFFSET);
    rdm_qcm_write_val(0, rdmi->hw_qcm_addr, ZHPE_RDM_QCM_STOP_OFFSET);

    return 0;

 rqfree:
    zhpe_kernel_RQFREE(rdmi);

 xqfree:
    zhpe_kernel_XQFREE(xdmi);

 done:
    return ret;
}

int zhpe_msg_qfree(struct slice *sl)
{
    struct bridge   *br = BRIDGE_FROM_SLICE(sl);
    struct xdm_info *xdmi = &br->msg_xdm;
    struct rdm_info *rdmi = &br->msg_rdm;
    int             ret = 0;

    if (sl == xdmi->sl) {
        ret |= zhpe_kernel_XQFREE(xdmi);
        msg_rspctxid_free(br);
    }
    if (sl == rdmi->sl)
        ret |= zhpe_kernel_RQFREE(rdmi);

    return ret;
}

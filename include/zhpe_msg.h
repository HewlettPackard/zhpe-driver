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

#ifndef _ZHPE_MSG_H_
#define _ZHPE_MSG_H_

enum {
    ZHPE_MSG_NOP = 1,
    ZHPE_MSG_UUID_IMPORT,
    ZHPE_MSG_UUID_FREE,
    ZHPE_MSG_UUID_TEARDOWN,
    ZHPE_MSG_RESPONSE = 0x80,
    ZHPE_MSG_VERSION = 1,
};

enum {
    /* range limited to -128..127 by int8_t */
    ZHPE_MSG_OK                      =  0,
    ZHPE_MSG_ERR_NO_MEMORY           = -1,
    ZHPE_MSG_ERR_UNKNOWN_VERSION     = -2,
    ZHPE_MSG_ERR_UNKNOWN_OPCODE      = -3,
    ZHPE_MSG_ERR_NO_UUID             = -4,
    ZHPE_MSG_ERR_UUID_NOT_LOCAL      = -5,
    ZHPE_MSG_ERR_UUID_GCID_MISMATCH  = -6,
    ZHPE_MSG_ERR_UUID_ALREADY_THERE  = -7,
};

struct zhpe_msg_hdr {  /* the first 8 bytes of the payload */
    uint8_t             version;
    int8_t              status;
    uint16_t            msgid;
    uint32_t            opcode   :  8;
    uint32_t            rspctxid : 24;
} __attribute__ ((packed));

struct zhpe_msg_req_NOP {
    struct zhpe_msg_hdr     hdr;
    uint64_t                seq;
} __attribute__ ((packed));

struct zhpe_msg_rsp_NOP {
    struct zhpe_msg_hdr     hdr;
    uint64_t                seq;
} __attribute__ ((packed));

struct zhpe_msg_req_UUID_IMPORT {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;
    uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct zhpe_msg_rsp_UUID_IMPORT {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;  /* Revisit: do we need UUIDs? */
    uuid_t                  tgt_uuid;
    uint32_t                ro_rkey;
    uint32_t                rw_rkey;
} __attribute__ ((packed));

struct zhpe_msg_req_UUID_FREE {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;
    uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct zhpe_msg_rsp_UUID_FREE {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;  /* Revisit: do we need UUIDs? */
    uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct zhpe_msg_req_UUID_TEARDOWN {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;
} __attribute__ ((packed));

struct zhpe_msg_rsp_UUID_TEARDOWN {
    struct zhpe_msg_hdr     hdr;
    uuid_t                  src_uuid;  /* Revisit: do we need UUID? */
} __attribute__ ((packed));

union zhpe_msg_req {
    struct zhpe_msg_hdr             hdr;
    struct zhpe_msg_req_NOP         nop;
    struct zhpe_msg_req_UUID_IMPORT uuid_import;
    struct zhpe_msg_req_UUID_FREE   uuid_free;
    struct zhpe_msg_req_UUID_FREE   uuid_teardown;
};

union zhpe_msg_rsp {
    struct zhpe_msg_hdr             hdr;
    struct zhpe_msg_rsp_NOP         nop;
    struct zhpe_msg_rsp_UUID_IMPORT uuid_import;
    struct zhpe_msg_rsp_UUID_FREE   uuid_free;
    struct zhpe_msg_rsp_UUID_FREE   uuid_teardown;
};

union zhpe_msg {
    struct zhpe_msg_hdr             hdr;
    union zhpe_msg_req              req;
    union zhpe_msg_rsp              rsp;
};

struct zhpe_msg_state {
    uint32_t               dgcid;
    uint32_t               rspctxid;
    union zhpe_msg         req_msg;
    union zhpe_msg         rsp_msg;
    bool                   ready;
    wait_queue_head_t      wq;
    struct rb_node         node;
    struct list_head       msg_list;
};

extern uint zhpe_kmsg_timeout;

/* Function Prototypes */
void zhpe_msg_list_wait(struct list_head *msg_wait_list, ktime_t start);
int zhpe_msg_send_UUID_IMPORT(struct bridge *br,
                              uuid_t *src_uuid, uuid_t *tgt_uuid,
                              uint32_t *ro_rkey, uint32_t *rw_rkey);
struct zhpe_msg_state *zhpe_msg_send_UUID_FREE(struct bridge *br,
                                               uuid_t *src_uuid,
                                               uuid_t *tgt_uuid, bool wait);
struct zhpe_msg_state *zhpe_msg_send_UUID_TEARDOWN(struct bridge *br,
                                uuid_t *src_uuid, uuid_t *tgt_uuid);
int zhpe_msg_qalloc(struct bridge *br);
int zhpe_msg_qfree(struct bridge *br);

#endif /* _ZHPE_MSG_H_ */

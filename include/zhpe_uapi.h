/*
 * Copyright (C) 2017-2018 Hewlett Packard Enterprise Development LP.
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

#ifndef _ZHPE_UAPI_H_
#define _ZHPE_UAPI_H_

#ifndef __KERNEL__

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#endif

/* Do extern "C" without goofing up emacs. */
#ifndef _EXTERN_C_SET
#define _EXTERN_C_SET
#ifdef  __cplusplus
#define _EXTERN_C_BEG extern "C" {
#define _EXTERN_C_END }
#else
#define _EXTERN_C_BEG
#define _EXTERN_C_END
#endif
#endif

_EXTERN_C_BEG

struct zhpe_timing_stamp {
    uint64_t            time;
    uint32_t		cpu;
} __attribute__ ((packed));

#define ZHPE_IMM_MAX           (32)
#define ZHPE_ENQA_MAX          (52)

#define ZHPE_MR_GET            ((uint32_t)1 << 0)
#define ZHPE_MR_PUT            ((uint32_t)1 << 1)
#define ZHPE_MR_SEND           ZHPE_MR_PUT
#define ZHPE_MR_RECV           ZHPE_MR_GET
#define ZHPE_MR_GET_REMOTE     ((uint32_t)1 << 2)
#define ZHPE_MR_PUT_REMOTE     ((uint32_t)1 << 3)
#define ZHPE_MR_KEY_ONESHOT    ((uint32_t)1 << 7)
#define ZHPE_MR_REQ_CPU        ((uint32_t)1 << 27) /* CPU visible mapping */
#define ZHPE_MR_REQ_CPU_CACHE  ((uint32_t)3 << 28) /* CPU cache mode */
#define ZHPE_MR_REQ_CPU_WB     ((uint32_t)0 << 28)
#define ZHPE_MR_REQ_CPU_WC     ((uint32_t)1 << 28)
#define ZHPE_MR_REQ_CPU_WT     ((uint32_t)2 << 28)
#define ZHPE_MR_REQ_CPU_UC     ((uint32_t)3 << 28)
#define ZHPE_MR_INDIVIDUAL     ((uint32_t)1 << 30) /* individual rsp ZMMU */
#define ZHPE_MR_KEY_VALID      ((uint32_t)1 << 31)

enum zhpe_hw_atomic {
    ZHPE_HW_ATOMIC_RETURN 	= 0x01,
    ZHPE_HW_ATOMIC_SIZE_32      = 0x02,
    ZHPE_HW_ATOMIC_SIZE_64      = 0x04,
    ZHPE_HW_ATOMIC_SIZE_MASK 	= 0x0E,
};

union zhpe_atomic {
    int32_t             s32;
    int64_t             s64;
    uint32_t            u32;
    uint64_t            u64;
};

enum zhpe_hw_cq {
    ZHPE_HW_CQ_STATUS_SUCCESS               = 0x00,
    ZHPE_HW_CQ_STATUS_CMD_TRUNCATED         = 0x01,
    ZHPE_HW_CQ_STATUS_BAD_CMD               = 0x02,
    ZHPE_HW_CQ_STATUS_LOCAL_UNRECOVERABLE   = 0x11,
    ZHPE_HW_CQ_STATUS_FABRIC_UNRECOVERABLE  = 0x21,
    ZHPE_HW_CQ_STATUS_FABRIC_NO_RESOURCES   = 0x22,
    ZHPE_HW_CQ_STATUS_FABRIC_ACCESS         = 0x23,

    ZHPE_HW_CQ_VALID                        = 0x01,
};

struct zhpe_result {
    char                data[ZHPE_IMM_MAX];
};

struct zhpe_cq_entry {
    uint8_t             valid;
    uint8_t             status;
    uint16_t            index;
    uint8_t             filler1[4];
    void                *context;
    struct zhpe_timing_stamp timestamp;
    uint8_t             filler2[4];
    struct zhpe_result  result;
};

#define ZHPE_HW_ENTRY_LEN (64)

enum zhpe_hw_opcode {
    ZHPE_HW_OPCODE_NOP 		= 0x0,
    ZHPE_HW_OPCODE_ENQA 	= 0x1,
    ZHPE_HW_OPCODE_PUT 		= 0x2,
    ZHPE_HW_OPCODE_GET		= 0x3,
    ZHPE_HW_OPCODE_PUTIMM	= 0x4,
    ZHPE_HW_OPCODE_GETIMM	= 0x5,
    ZHPE_HW_OPCODE_SYNC 	= 0x1f,
    ZHPE_HW_OPCODE_ATM_SWAP 	= 0x20,
    ZHPE_HW_OPCODE_ATM_ADD 	= 0x22,
    ZHPE_HW_OPCODE_ATM_AND 	= 0x24,
    ZHPE_HW_OPCODE_ATM_OR 	= 0x25,
    ZHPE_HW_OPCODE_ATM_XOR 	= 0x26,
    ZHPE_HW_OPCODE_ATM_SMIN 	= 0x28,
    ZHPE_HW_OPCODE_ATM_SMAX 	= 0x29,
    ZHPE_HW_OPCODE_ATM_UMIN 	= 0x2a,
    ZHPE_HW_OPCODE_ATM_UMAX 	= 0x2b,
    ZHPE_HW_OPCODE_ATM_CAS 	= 0x2c,
    ZHPE_HW_OPCODE_FENCE 	= 0x100,
};

/* Timestamps are for SW timing use. */

struct zhpe_hw_wq_hdr {
    uint16_t            opcode;
    uint16_t            cmp_index;
};

struct zhpe_hw_wq_nop {
    struct zhpe_hw_wq_hdr hdr;
    struct zhpe_timing_stamp timestamp;
};

struct zhpe_hw_wq_dma {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            rd_addr;
    uint64_t            wr_addr;
    struct zhpe_timing_stamp timestamp;
};

struct zhpe_hw_wq_imm {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            rem_addr;
    struct zhpe_timing_stamp timestamp;
    uint8_t             filler[4];
    uint8_t             data[ZHPE_IMM_MAX];
};

struct zhpe_hw_wq_atomic {
    struct zhpe_hw_wq_hdr hdr;
    uint8_t             size;
    uint8_t             filler1[3];
    uint64_t            rem_addr;
    struct zhpe_timing_stamp timestamp;
    uint8_t             filler2[4];
    union zhpe_atomic  operands[2];
};

union zhpe_hw_wq_entry {
    struct zhpe_hw_wq_hdr hdr;
    struct zhpe_hw_wq_nop nop;
    struct zhpe_hw_wq_dma dma;
    struct zhpe_hw_wq_imm imm;
    struct zhpe_hw_wq_atomic atm;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

union zhpe_hw_cq_entry {
    struct zhpe_cq_entry entry;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

enum zhpe_backend {
    ZHPE_BACKEND_ZHPE = 1,
    ZHPE_BACKEND_LIBFABRIC,
    ZHPE_BACKEND_MAX,
};

struct zhpe_attr {
    enum zhpe_backend   backend;
    uint32_t            max_tx_queues;
    uint32_t            max_rx_queues;
    uint32_t            max_hw_qlen;
    uint32_t            max_sw_qlen;
    uint64_t            max_dma_len;
};

struct zhpe_key_data {
    uint64_t            vaddr;
    uint64_t            zaddr;
    uint64_t            len;
    uint64_t            key;
    uint8_t             access;
};

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _ZHPE_UAPI_H_ */

/*
 * Copyright (C) 2017-2020 Hewlett Packard Enterprise Development LP.
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

#include <zhpe_externc.h>

_EXTERN_C_BEG

#define ZHPE_MAX_SLICES         ((size_t)4)
#define ZHPE_MAX_IRQS_PER_SLICE ((size_t)32)
#define ZHPE_MAX_RDMQS_PER_SLICE ((size_t)256)
#define ZHPE_MAX_XDMQS_PER_SLICE ((size_t)256)

#define ZHPE_MAX_IRQS           (ZHPE_MAX_IRQS_PER_SLICE * ZHPE_MAX_SLICES)
#define ZHPE_MAX_RDMQS          (ZHPE_MAX_RDMQS_PER_SLICE * ZHPE_MAX_SLICES)
#define ZHPE_MAX_XDMQS          (ZHPE_MAX_XDMQS_PER_SLICE * ZHPE_MAX_SLICES)

#define ZHPE_MAX_IMM            ((size_t)32)
#define ZHPE_MAX_ENQA           ((size_t)52)

/* XDM QCM access macros and structures. Reads and writes must be 64 bits */

struct zhpe_xdm_active_status_error {
    uint64_t active_cmd_cnt   : 11;
    uint64_t rv1              : 4;
    uint64_t active           : 1;
    uint64_t status           : 3;
    uint64_t rv2              : 12;
    uint64_t error            : 1;
    uint64_t rv3              : 32;
};
#define ZHPE_XDM_QCM_STATUS_CMD_ERROR           0x1
#define ZHPE_XDM_QCM_MASTER_STOP_OFFSET         0x20
#define ZHPE_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET 0x28
#define ZHPE_XDM_QCM_STOP_OFFSET                0x40
#define ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET      0x80
#define ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET      0xc0
#define ZHPE_XDM_QCM_CMD_BUF_OFFSET             0x800
#define ZHPE_XDM_QCM_CMD_BUF_CLEAR              0x800
#define ZHPE_XDM_QCM_CMD_BUF_COUNT              0x10

#define ZHPE_RDM_QCM_MASTER_STOP_OFFSET         0x10
#define ZHPE_RDM_QCM_STOP_OFFSET                0x40
#define ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET      0xc0
/*
 * XDM command buffers should be written with as two 32 AVX ops, byte 0 is
 * is the trigger, so write the second half, first.
 */
struct zhpe_xdm_cmpl_queue_tail_toggle {
    uint64_t cmpl_q_tail_idx  : 16;
    uint64_t rv1              : 15;
    uint64_t toggle_valid     : 1;
    uint64_t rv2              : 32;
};
#define ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET 0x100

/* RDM QCM access macros and structures. Reads and writes must be 64 bits */
struct zhpe_rdm_active {
    uint64_t active : 1;
};
#define ZHPE_RDM_QCM_ACTIVE_OFFSET              0x18

struct zhpe_rdm_rcv_queue_tail_toggle {
    uint64_t rcv_q_tail_idx   : 20;
    uint64_t rv1              : 11;
    uint64_t toggle_valid     : 1;
    uint64_t rv2              : 32;
};
#define ZHPE_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET 0x80


#define ZHPE_MR_GET             ((uint32_t)1 << 0)
#define ZHPE_MR_PUT             ((uint32_t)1 << 1)
#define ZHPE_MR_GET_REMOTE      ((uint32_t)1 << 2)
#define ZHPE_MR_PUT_REMOTE      ((uint32_t)1 << 3)
#define ZHPE_MR_SEND            ZHPE_MR_GET_REMOTE
#define ZHPE_MR_RECV            ZHPE_MR_GET
#define ZHPE_MR_FLAG0           ((uint32_t)1 << 4)  /* Usable by zhpeq */
#define ZHPE_MR_FLAG1           ((uint32_t)1 << 5)
#define ZHPE_MR_FLAG2           ((uint32_t)1 << 6)
#define ZHPE_MR_INDIVIDUAL      ((uint32_t)1 << 7)  /* individual ZMMU entry */
#define ZHPE_MR_REQ_CPU         ((uint32_t)1 << 27) /* CPU visible mapping */
#define ZHPE_MR_REQ_CPU_CACHE   ((uint32_t)3 << 28) /* CPU cache mode */
#define ZHPE_MR_REQ_CPU_WB      ((uint32_t)0 << 28)
#define ZHPE_MR_REQ_CPU_WC      ((uint32_t)1 << 28)
#define ZHPE_MR_REQ_CPU_WT      ((uint32_t)2 << 28)
#define ZHPE_MR_REQ_CPU_UC      ((uint32_t)3 << 28)
#define ZHPE_MR_ZMMU_ONLY       ((uint32_t)1 << 31) /* rsp ZMMU only entry */

/* Mask off user flags */
#define ZHPE_MR_USER_MASK \
    (~(ZHPE_MR_FLAG0 | ZHPE_MR_FLAG1 | ZHPE_MR_FLAG2))

enum zhpe_hw_atomic {
    ZHPE_HW_ATOMIC_RETURN       = 0x01,
    ZHPE_HW_ATOMIC_SIZE_32      = 0x04,
    ZHPE_HW_ATOMIC_SIZE_64      = 0x06,
    ZHPE_HW_ATOMIC_SIZE_MASK    = 0x0E,
};

enum zhpe_hw_cq_status {
    ZHPE_HW_CQ_STATUS_SUCCESS                   = 0x00,
    ZHPE_HW_CQ_STATUS_XDM_PUT_READ_ERROR        = 0x01,
    ZHPE_HW_CQ_STATUS_XDM_BAD_COMMAND           = 0x02,
    ZHPE_HW_CQ_STATUS_GENZ_UNSUPPORTED_REQ      = 0x82,
    ZHPE_HW_CQ_STATUS_GENZ_MALFORMED_PKT        = 0x83,
    ZHPE_HW_CQ_STATUS_GENZ_PKT_EXECUTION_ERROR  = 0x85,
    ZHPE_HW_CQ_STATUS_GENZ_INVALID_PERMISSION   = 0x87,
    ZHPE_HW_CQ_STATUS_GENZ_COMP_CONTAINMENT     = 0x88,
    ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL       = 0x93,
    ZHPE_HW_CQ_STATUS_GENZ_UNSUPPORTED_SVC      = 0x95,
    ZHPE_HW_CQ_STATUS_GENZ_RETRIES_EXCEEDED     = 0xA2,
};

/*
 * Traffic class abstraction for user space. Used in zhpe_req_XQALLOC
 * traffic_class field. Mapping to actual Gen-Z traffic class is
 * undefined to user space.
 */
enum {
    ZHPE_TC_0           = 0,
    ZHPE_TC_1           = 1,
    ZHPE_TC_2           = 2,
    ZHPE_TC_3           = 3,
    ZHPE_TC_4           = 4,
    ZHPE_TC_5           = 5,
    ZHPE_TC_6           = 6,
    ZHPE_TC_7           = 7,
    ZHPE_TC_8           = 8,
    ZHPE_TC_9           = 9,
    ZHPE_TC_10          = 10,
    ZHPE_TC_11          = 11,
    ZHPE_TC_12          = 12,
    ZHPE_TC_13          = 13,
    ZHPE_TC_14          = 14,
    ZHPE_TC_15          = 15,
    ZHPE_MAX_TC         = ZHPE_TC_15,
};

enum {
    ZHPE_PRIO_LO        = 0,
    ZHPE_PRIO_HI        = 1,
    ZHPE_MAX_PRIO       = ZHPE_PRIO_HI,
};

union zhpe_result {
    char                data[ZHPE_MAX_IMM];
    uint32_t            atomic32;
    uint64_t            atomic64;
};

/*
 * Both XDM and RDM completion queues have their valid bit in bit 0 of the
 * first byte; the meaning of the bit flips with each traversal of the ring.
 */
#define ZHPE_CMP_ENT_VALID_MASK (1U)

struct zhpe_cq_entry {
    uint8_t             valid : 1;
    uint8_t             rv1   : 4;
    uint8_t             qd    : 3;      /* EnqA only */
    uint8_t             status;
    uint16_t            index;
    uint8_t             filler1[4];
    void                *context;       /* Borrowed by SW to return context. */
    uint8_t             filler2[16];
    union zhpe_result   result;
};

#define ZHPE_HW_ENTRY_LEN       ((size_t)64)

enum zhpe_hw_opcode {
    ZHPE_HW_OPCODE_NOP          = 0x0,
    ZHPE_HW_OPCODE_ENQA         = 0x1,
    ZHPE_HW_OPCODE_PUT          = 0x2,
    ZHPE_HW_OPCODE_GET          = 0x3,
    ZHPE_HW_OPCODE_PUTIMM       = 0x4,
    ZHPE_HW_OPCODE_GETIMM       = 0x5,
    ZHPE_HW_OPCODE_SYNC         = 0x1f,
    ZHPE_HW_OPCODE_ATM_SWAP     = 0x20,
    ZHPE_HW_OPCODE_ATM_ADD      = 0x22,
    ZHPE_HW_OPCODE_ATM_AND      = 0x24,
    ZHPE_HW_OPCODE_ATM_OR       = 0x25,
    ZHPE_HW_OPCODE_ATM_XOR      = 0x26,
    ZHPE_HW_OPCODE_ATM_SMIN     = 0x28,
    ZHPE_HW_OPCODE_ATM_SMAX     = 0x29,
    ZHPE_HW_OPCODE_ATM_UMIN     = 0x2a,
    ZHPE_HW_OPCODE_ATM_UMAX     = 0x2b,
    ZHPE_HW_OPCODE_ATM_CAS      = 0x2c,
    ZHPE_HW_OPCODE_MASK         = 0xFF,
    ZHPE_HW_OPCODE_FENCE        = 0x100,
};

struct zhpe_hw_wq_hdr {
    uint16_t            opcode;
    uint16_t            cmp_index;
};

struct zhpe_hw_wq_nop {
    struct zhpe_hw_wq_hdr hdr;
};

struct zhpe_hw_wq_dma {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            rd_addr;
    uint64_t            wr_addr;
};

struct zhpe_hw_wq_imm {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            rem_addr;
    uint8_t             filler[16];
    uint8_t             data[ZHPE_MAX_IMM];
};

struct zhpe_hw_wq_atomic {
    struct zhpe_hw_wq_hdr hdr;
    uint8_t             size;
    uint8_t             filler1[3];
    uint64_t            rem_addr;
    uint8_t             filler2[16];
    union {
        uint32_t        operands32[2];
        uint64_t        operands64[2];
    };
};

#define ZHPE_GCID_BITS          (28U)
#define ZHPE_GCID_SID_SHIFT     (12U)
#define ZHPE_GCID_SID_MASK      (0xFFFFU)
#define ZHPE_GCID_CID_MASK      (0xFFFU)
#define ZHPE_CTXID_BITS         (24U)

struct zhpe_enqa_payload {
    uint8_t             data[ZHPE_MAX_ENQA];
};

struct zhpe_hw_wq_enqa {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            rv1      :  4;
    uint32_t            dgcid    : ZHPE_GCID_BITS;
    uint32_t            rspctxid : ZHPE_CTXID_BITS;
    uint32_t            rv2      :  8;
    struct zhpe_enqa_payload payload;
};

union zhpe_hw_wq_entry {
    struct zhpe_hw_wq_hdr hdr;
    struct zhpe_hw_wq_nop nop;
    struct zhpe_hw_wq_dma dma;
    struct zhpe_hw_wq_imm imm;
    struct zhpe_hw_wq_atomic atm;
    struct zhpe_hw_wq_enqa enqa;
    uint64_t            bytes8[8];
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

union zhpe_hw_cq_entry {
    struct zhpe_cq_entry entry;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

struct zhpe_rdm_hdr {
    uint64_t            valid     :  1;
    uint64_t            rv1       :  3;
    uint64_t            sgcid     : ZHPE_GCID_BITS;
    uint64_t            reqctxid  : ZHPE_CTXID_BITS;
    uint64_t            rv2       :  8;
};

struct zhpe_rdm_entry {
    struct zhpe_rdm_hdr hdr;
    uint8_t             filler1[4];
    struct zhpe_enqa_payload payload;
};

union zhpe_hw_rdm_entry {
    struct zhpe_rdm_entry entry;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

struct zhpe_attr {
    uint32_t            max_tx_queues;
    uint32_t            max_rx_queues;
    uint32_t            max_tx_qlen;
    uint32_t            max_rx_qlen;
    uint64_t            max_dma_len;
    uint32_t            num_slices;
};

struct zhpe_key_data {
    uint64_t            vaddr;
    uint64_t            zaddr;
    uint64_t            len;
    uint64_t            key;
    uint32_t            access;
};

static inline void mcommit(void)
{
    asm volatile(".byte 0xf3,0x0f,0x01,0xfa" ::: "memory");
}

#define CPUID_8000_0008                 (0x80000008)
#define CPUID_8000_0008_EBX_MCOMMIT     (0x100)

struct zhpe_qcm {
    uint32_t           size;   /* Bytes allocated for the QCM */
    uint64_t           off;    /* File descriptor offset to the QCM */
};

struct zhpe_queue {
    uint32_t           ent;    /* Number of entries in the queue */
    uint32_t           size;   /* Bytes allocated for the queue */
    uint64_t           off;    /* File descriptor offset to the queue */
};

/* Defines for the XQALLOC/RQALLOC slice_mask */
#define SLICE_DEMAND 0x80
#define ALL_SLICES 0x0f

struct zhpe_xqinfo {
    struct zhpe_qcm     qcm;   /* XDM Queue Control Memory */
    struct zhpe_queue   cmdq;  /* XDM Command Queue */
    struct zhpe_queue   cmplq; /* XDM Completion Queue */
    uint8_t             slice; /* HW slice number which allocated the queues */
    uint8_t             queue; /* HW queue number */
};

struct zhpe_rqinfo {
    struct zhpe_qcm     qcm;   /* XDM Queue Control Memory */
    struct zhpe_queue   cmplq; /* XDM Completion Queue */
    uint8_t             slice; /* HW slice number which allocated the queues */
    uint8_t             queue; /* HW queue number */
    uint16_t            clump; /* irq clump size (can be 256) */
    uint32_t            rspctxid; /* RSPCTXID to use with EnqA */
    uint32_t            irq_vector; /* interrupt vector that maps to poll dev */
};

_EXTERN_C_END

#endif /* _ZHPE_UAPI_H_ */

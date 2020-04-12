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

#ifndef _ZHPE_H_
#define _ZHPE_H_

#ifdef __KERNEL__

#include <linux/uio.h>
#include <linux/uuid.h>
#include <linux/socket.h>
#include <asm/byteorder.h>

#define htobe64 cpu_to_be64
#define be64toh be64_to_cpu
#define htobe32 cpu_to_be32
#define be32toh be32_to_cpu

typedef long long       llong;
typedef unsigned long long ullong;

#else

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <uuid/uuid.h>

#endif

#include <zhpe_uapi.h>

_EXTERN_C_BEG

#define DRIVER_NAME     "zhpe"

enum {
    ZHPE_OP_INIT,
    ZHPE_OP_MR_REG,
    ZHPE_OP_MR_FREE,
    ZHPE_OP_NOP,
    ZHPE_OP_RMR_IMPORT,
    ZHPE_OP_RMR_FREE,
    ZHPE_OP_UUID_IMPORT,
    ZHPE_OP_UUID_FREE,
    ZHPE_OP_XQALLOC,
    ZHPE_OP_XQFREE,
    ZHPE_OP_RQALLOC,
    ZHPE_OP_RQFREE,
    ZHPE_OP_RQALLOC_SPECIFIC,
    ZHPE_OP_RESPONSE = 0x80,
    ZHPE_OP_VERSION = 1,
};

enum {
    DEBUG_TESTMODE      = 0x00000001,
    DEBUG_MEM           = 0x00000002,
    DEBUG_COUNT         = 0x00000004,
    DEBUG_IO            = 0x00000008,
    DEBUG_RELEASE       = 0x00000010,
    DEBUG_PCI           = 0x00000020,
    DEBUG_ZMMU          = 0x00000040,
    DEBUG_MEMREG        = 0x00000080,
    DEBUG_XQUEUE        = 0x00000100,
    DEBUG_UUID          = 0x00000200,
    DEBUG_MMAP          = 0x00000400,
    DEBUG_RQUEUE        = 0x00000800,
    DEBUG_RKEYS         = 0x00001000,
    DEBUG_MSG           = 0x00002000,
    DEBUG_INTR          = 0x00004000,
};

/* ZHPE_MAGIC == 'ZHPE' */
#define ZHPE_MAGIC      ((uint32_t)0x47454E5A)

#define ZHPE_ENTRY_LEN  (64U)

struct zhpe_info {
    uint32_t            qlen;
    uint32_t            rsize;
    uint32_t            qsize;
    uint64_t            reg_off;
    uint64_t            wq_off;
    uint64_t            cq_off;
};

struct zhpe_common_hdr {
    uint8_t             version;
    uint8_t             opcode;
    uint16_t            index;
    int                 status;
};

struct zhpe_req_INIT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_rsp_INIT {
    struct zhpe_common_hdr hdr;
    uint32_t            magic;
    struct zhpe_attr    attr;
    uuid_t              uuid;
    uint64_t            global_shared_offset; /* triggered counters */
    uint32_t            global_shared_size;
    uint64_t            local_shared_offset;  /* handled counters */
    uint32_t            local_shared_size;
};

struct zhpe_req_MR_REG {
    struct zhpe_common_hdr hdr;
    uint64_t               vaddr;
    uint64_t               len;
    uint64_t               access;
};

struct zhpe_rsp_MR_REG {
    struct zhpe_common_hdr hdr;
    uint64_t               rsp_zaddr;
    uint32_t               pg_ps;
    uint64_t               physaddr;  /* Revisit: remove when IOMMU works */
};

struct zhpe_req_MR_FREE {
    struct zhpe_common_hdr hdr;
    uint64_t               vaddr;
    uint64_t               len;
    uint64_t               access;
    uint64_t               rsp_zaddr;
};

struct zhpe_rsp_MR_FREE {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_RMR_IMPORT {
    struct zhpe_common_hdr hdr;
    uuid_t                 uuid;
    uint64_t               rsp_zaddr;
    uint64_t               len;
    uint64_t               access;
};

struct zhpe_rsp_RMR_IMPORT {
    struct zhpe_common_hdr hdr;
    uint64_t               req_addr;
    off_t                  offset;  /* if cpu-visible */
    uint32_t               pg_ps;
};

struct zhpe_req_RMR_FREE {
    struct zhpe_common_hdr hdr;
    uuid_t                 uuid;
    uint64_t               rsp_zaddr;
    uint64_t               len;
    uint64_t               access;
    uint64_t               req_addr;
};

struct zhpe_rsp_RMR_FREE {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

struct zhpe_rsp_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

enum {
    UUID_IS_FAM = 0x1,
};

struct zhpe_req_UUID_IMPORT {
    struct zhpe_common_hdr  hdr;
    uuid_t                  uuid;
    uuid_t                  mgr_uuid;
    uint32_t                uu_flags;
};

struct zhpe_rsp_UUID_IMPORT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_UUID_FREE {
    struct zhpe_common_hdr hdr;
    uuid_t                 uuid;
};

struct zhpe_rsp_UUID_FREE {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_XQALLOC {
     struct zhpe_common_hdr hdr;
     uint32_t            cmdq_ent;           /* Minimum entries in the cmdq */
     uint32_t            cmplq_ent;          /* Minimum entries in the cmplq */
     uint8_t             traffic_class;      /* Traffic class for this queue */
     uint8_t             priority;           /* Priority for this queue */
     uint8_t             slice_mask;         /* Control HW slice allocation */
};

struct zhpe_rsp_XQALLOC {
    struct zhpe_common_hdr hdr;
    struct zhpe_xqinfo  info;
};

struct zhpe_req_XQFREE {
    struct zhpe_common_hdr hdr;
    struct zhpe_xqinfo	info;
};

struct zhpe_rsp_XQFREE {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_RQALLOC {
    struct zhpe_common_hdr hdr;
    uint32_t            cmplq_ent;           /* Minimum entries the queue. */
    uint8_t             slice_mask;          /* Control HW slice allocation */
};

struct zhpe_rsp_RQALLOC {
    struct zhpe_common_hdr hdr;
    struct zhpe_rqinfo  info;
};

struct zhpe_req_RQALLOC_SPECIFIC {
    struct zhpe_common_hdr hdr;
    uint32_t            cmplq_ent;           /* Minimum entries the queue. */
    uint32_t            qspecific;           /* Specific queue, 0 => any. */
};

struct zhpe_req_RQFREE {
    struct zhpe_common_hdr hdr;
    struct zhpe_rqinfo  info;
};

struct zhpe_rsp_RQFREE {
    struct zhpe_common_hdr hdr;
};

union zhpe_req {
    struct zhpe_common_hdr hdr;
    struct zhpe_req_INIT        init;
    struct zhpe_req_MR_REG      mr_reg;
    struct zhpe_req_MR_FREE     mr_free;
    struct zhpe_req_RMR_IMPORT  rmr_import;
    struct zhpe_req_RMR_FREE    rmr_free;
    struct zhpe_req_NOP         nop;
    struct zhpe_req_UUID_IMPORT uuid_import;
    struct zhpe_req_UUID_FREE   uuid_free;
    struct zhpe_req_XQALLOC     xqalloc;
    struct zhpe_req_XQFREE      xqfree;
    struct zhpe_req_RQALLOC     rqalloc;
    struct zhpe_req_RQFREE      rqfree;
    struct zhpe_req_RQALLOC_SPECIFIC rqalloc_specific;
};

union zhpe_rsp {
    struct zhpe_common_hdr hdr;
    struct zhpe_rsp_INIT        init;
    struct zhpe_rsp_MR_REG      mr_reg;
    struct zhpe_rsp_MR_FREE     mr_free;
    struct zhpe_rsp_RMR_IMPORT  rmr_import;
    struct zhpe_rsp_RMR_FREE    rmr_free;
    struct zhpe_rsp_NOP         nop;
    struct zhpe_rsp_UUID_IMPORT uuid_import;
    struct zhpe_rsp_UUID_FREE   uuid_free;
    struct zhpe_rsp_XQALLOC     xqalloc;
    struct zhpe_rsp_XQFREE      xqfree;
    struct zhpe_rsp_RQALLOC     rqalloc;
    struct zhpe_rsp_RQFREE      rqfree;
};

union zhpe_op {
    struct zhpe_common_hdr hdr;
    union zhpe_req     req;
    union zhpe_rsp     rsp;
};

#define SLICES                        ZHPE_MAX_SLICES
#define VECTORS_PER_SLICE             ZHPE_MAX_IRQS_PER_SLICE
#define MAX_IRQ_VECTORS               (VECTORS_PER_SLICE * SLICES)

struct zhpe_global_shared_data {
    uint32_t            triggered_counter[MAX_IRQ_VECTORS];
};

struct zhpe_local_shared_data {
    uint32_t            handled_counter[MAX_IRQ_VECTORS];
};

_EXTERN_C_END

#endif /* _ZHPE_H_ */

/*
 * Copyright (C) 2018, 2020 Hewlett Packard Enterprise Development LP.
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

#ifndef _ZHPE_QUEUE_H_
#define _ZHPE_QUEUE_H_

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/pci.h>

#ifndef ioread64
#ifdef readq
#define ioread64 readq
#else
#error Platform has no useable ioread64
#endif
#endif

#ifndef iowrite64
#ifdef writeq
#define iowrite64 writeq
#else
#error Platform has no useable iowrite64
#endif
#endif

#define XDM_CMD_ADDR_OFFSET     0x00
#define XDM_CMPL_ADDR_OFFSET    0x08
#define XDM_SIZE_OFFSET         0x10
#define XDM_PASID_OFFSET        0x18
#define XDM_PASID_QVIRT_FLAG    (1ULL << 31)
#define XDM_A_OFFSET 		0x28
#define XDM_DUMP_08_START       0x10
#define XDM_DUMP_08_END         0x28
#define XDM_DUMP_40_START       0x40
#define XDM_DUMP_40_END         0x100

#define RDM_CMPL_ADDR_OFFSET    0x00
#define RDM_SIZE_OFFSET         0x08
#define RDM_SIZE_QVIRT_FLAG     (1ULL << 63)
#define RDM_A_OFFSET		0x18
#define RDM_DUMP_08_START       0x08
#define RDM_DUMP_08_END         0x18
#define RDM_DUMP_40_START       0x40
#define RDM_DUMP_40_END         0xC0

static inline uint64_t qcm_val(void *qcm, int offset)
{
    return *((uint64_t *)(qcm + offset));
}

static inline uint64_t *qcm_ptr(void *hw_qcm_addr, int offset)
{
    return ((uint64_t *)(hw_qcm_addr + offset));
}

static inline void xdm_qcm_write(struct xdm_qcm_header *qcm,
                                 struct xdm_qcm *hw_qcm_addr,
                                 int offset)
{
    iowrite64(qcm_val(qcm, offset), qcm_ptr(hw_qcm_addr, offset));
}

static inline void xdm_qcm_write_val(uint64_t val,
                                     struct xdm_qcm *hw_qcm_addr,
                                     int offset)
{
    iowrite64(val, qcm_ptr(hw_qcm_addr, offset));
}

static inline uint64_t xdm_qcm_read(struct xdm_qcm *hw_qcm_addr,
                                    int offset)
{
    return ioread64(qcm_ptr(hw_qcm_addr, offset));
}

static inline void rdm_qcm_write(struct rdm_qcm_header *qcm,
                                 struct rdm_qcm *hw_qcm_addr,
                                 int offset)
{
    iowrite64(qcm_val(qcm, offset), qcm_ptr(hw_qcm_addr, offset));
}

static inline void rdm_qcm_write_val(uint64_t val,
                                     struct rdm_qcm *hw_qcm_addr,
                                     int offset)
{
    iowrite64(val, qcm_ptr(hw_qcm_addr, offset));
}

static inline uint64_t rdm_qcm_read(struct rdm_qcm *hw_qcm_addr,
                                    int offset)
{
    return ioread64(qcm_ptr(hw_qcm_addr, offset));
}

/* Function Prototypes */
int zhpe_user_req_XQFREE(struct io_entry *entry);
int zhpe_user_req_XQALLOC(struct io_entry *entry);
int zhpe_user_req_RQFREE(struct io_entry *entry);
int zhpe_user_req_RQALLOC(struct io_entry *entry);
int zhpe_user_req_RQALLOC_SPECIFIC(struct io_entry *entry);
int zhpe_req_XQALLOC(struct zhpe_req_XQALLOC *req,
                     struct zhpe_rsp_XQALLOC *rsp, struct file_data *fdata);
int zhpe_req_XQFREE(union zhpe_req *req,
                    union zhpe_rsp *rsp, struct file_data *fdata);
int zhpe_req_RQALLOC(uint32_t cmpq_ent, uint8_t slice_mask, uint32_t qspecific,
                     struct zhpe_rsp_RQALLOC *rsp, struct file_data *fdata);
int zhpe_req_RQFREE(struct zhpe_req_RQFREE *req, struct zhpe_rsp_RQFREE *rsp,
                    struct file_data *fdata);
int zhpe_kernel_XQALLOC(struct xdm_info *xdmi);
int zhpe_kernel_RQALLOC(struct rdm_info *rdmi);
int zhpe_kernel_XQFREE(struct xdm_info *xdmi);
int zhpe_kernel_RQFREE(struct rdm_info *rdmi);
void zhpe_xqueue_init(struct slice *sl);
void zhpe_rqueue_init(struct slice *sl);
int free_xqueue(
	struct io_entry *entry,
	struct zhpe_req_XQFREE * free_req,
	struct zhpe_rsp_XQFREE * free_rsp);
int zhpe_clear_xdm_qcm(struct bridge *bridge, struct slice *sl);
int zhpe_clear_rdm_qcm(struct bridge *bridge, struct slice *sl);
void zhpe_stop_owned_xdm_queues(struct file_data *fdata);
void zhpe_release_owned_xdm_queues(struct file_data *fdata);
void zhpe_release_owned_rdm_queues(struct file_data *fdata);
int zhpe_rdm_queue_to_irq(int queue, struct slice *sl);
int zhpe_rdm_queue_to_vector(int queue, struct slice *sl);
void zhpe_debug_xdm_qcm(const char *func, uint line, const void *cqcm);
void zhpe_debug_rdm_qcm(const char *func, uint line, const void *cqcm);
uint32_t zhpe_ctxid(int slice, int queue);

#endif /* _ZHPE_DRIVER_H_ */

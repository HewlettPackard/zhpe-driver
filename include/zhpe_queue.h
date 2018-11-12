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

/* Hardware limits */
#define MAX_TX_QUEUES      1024
#define MAX_RX_QUEUES      1024
#define MAX_SW_XDM_QLEN    BIT(16)
#define MAX_HW_XDM_QLEN    (MAX_SW_XDM_QLEN-1)
#define MAX_SW_RDM_QLEN    BIT(20)
#define MAX_HW_RDM_QLEN    (MAX_SW_RDM_QLEN-1)
#define MAX_DMA_LEN        (1U << 31)

#define XDM_MASTER_STOP_OFFSET 	0x20
#define XDM_STOP_OFFSET		0x40
#define XDM_A_OFFSET 		0x28

#define RDM_MASTER_STOP_OFFSET 	0x10
#define RDM_STOP_OFFSET		0x40
#define RDM_A_OFFSET		0x18

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
int zhpe_req_XQALLOC(struct zhpe_req_XQALLOC *req,
			struct zhpe_rsp_XQALLOC	*rsp,
			struct file_data *fdata);
int zhpe_req_XQFREE(union zhpe_req *req, 
			union zhpe_rsp *rsp, struct file_data *fdata);
int zhpe_req_RQALLOC(struct zhpe_req_RQALLOC *req,
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
int zhpe_clear_xdm_qcm(struct xdm_qcm * xdm_qcm_base);
int zhpe_clear_rdm_qcm(struct rdm_qcm * rdm_qcm_base);
void zhpe_release_owned_xdm_queues(struct file_data *fdata);
void zhpe_release_owned_rdm_queues(struct file_data *fdata);
int zhpe_rdm_queue_to_irq(int queue, struct slice *sl);
int zhpe_rdm_queue_to_vector(int queue, struct slice *sl);

#endif /* _ZHPE_DRIVER_H_ */
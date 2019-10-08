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

#ifndef _ZHPE_MEMREG_H_
#define _ZHPE_MEMREG_H_

#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>

/* tentative definitions */
struct sw_page_grid;
struct zhpe_uuid_tracker;

struct zhpe_pte_info {
    struct kref           refcount; /* only used when owned by a zhpe_rmr */
    uint32_t              dgcid; /* only used when owned by a zhpe_rmr */
    uint64_t              addr;
    uint64_t              access;
    size_t                length;
    uint64_t              addr_aligned;    /* rounded down to pg page size */
    uint64_t              length_adjusted; /* rounded up to pg page size */
    struct sw_page_grid   *pg;
    unsigned int          pte_index;
    unsigned int          zmmu_pages;
    uint8_t               space_type;
    struct rb_node        node;  /* within pgi->pte_tree */
};

struct zhpe_umem {
    struct zhpe_pte_info  pte_info;
    struct file_data      *fdata;
    struct rb_node        node;  /* within fdata->mr_tree */
    struct kref           refcount;
    uint64_t              vaddr;
    uint64_t              physaddr; /* Revisit: temporary */
    int                   page_shift;
    bool                  writable;
    bool                  hugetlb;
    bool                  need_release;
    bool                  dirty;
    struct pid            *pid;
    struct work_struct    work;  /* Revisit: these next 3 were copied from */
    struct mm_struct      *mm;   /* ib_umem and are currently unused */
    unsigned long         diff;
    struct sg_table       sg_head;
    int                   nmap;
    int                   npages;
};

struct zhpe_rmr {
    struct zhpe_pte_info  *pte_info;
    struct file_data      *fdata;
    struct rb_node        fd_node;  /* within fdata->fd_rmr_tree */
    struct rb_node        un_node;  /* within fdata->fd_remote_uuid_tree->un_rmr_tree */
    struct kref           refcount;
    struct uuid_tracker   *uu;    /* the remote UUID this rmr belongs to */
    struct uuid_node      *unode; /* the local unode this rmr belongs to */
    struct zmap           *zmap;
    uint64_t              rsp_zaddr;
    uint64_t              req_addr;
    uint32_t              dgcid;
    uint32_t              rkey;
    bool                  writable;
    bool                  fd_erase;
    bool                  un_erase;
};

void zhpe_rmr_remove_unode(struct file_data *fdata, struct uuid_node *unode);
void zhpe_rmr_free_all(struct file_data *fdata);
void zhpe_umem_free_all(struct file_data *fdata);
int zhpe_user_req_MR_REG(struct io_entry *entry);
int zhpe_user_req_MR_FREE(struct io_entry *entry);
int zhpe_user_req_RMR_IMPORT(struct io_entry *entry);
int zhpe_user_req_RMR_FREE(struct io_entry *entry);
void zhpe_pte_info_dbg(uint debug_flag, const char *callf, uint line,
                       struct zhpe_pte_info *info);

static inline bool zhpe_umem_empty(struct file_data *fdata)
{
    return RB_EMPTY_ROOT(&fdata->mr_tree);
}

static inline bool zhpe_rmr_empty(struct file_data *fdata)
{
    return RB_EMPTY_ROOT(&fdata->fd_rmr_tree);
}
#endif /* _ZHPE_MEMREG_H_ */

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

#ifndef _ZHPE_DRIVER_H_
#define _ZHPE_DRIVER_H_

#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/interrupt.h>
#include <linux/mmu_notifier.h>
#include <linux/sched.h>

extern uint zhpe_debug_flags;
extern const char zhpe_driver_name[];
extern uint no_iommu;
extern uint signal_mr_overlap;
extern struct zhpe_global_shared_data *global_shared_data;
extern bool zhpe_mcommit;

#define zprintk_caller(_lvl, _callf, _line, _fmt, ...)                  \
    printk(_lvl "%s:%s,%u,%d: " _fmt,                                   \
           zhpe_driver_name, _callf, _line, task_pid_nr(current),       \
           ##__VA_ARGS__)
#define zprintk(_lvl, _fmt, ...)                                        \
    zprintk_caller(_lvl, __func__, __LINE__, _fmt, ##__VA_ARGS__)

#if defined(NDEBUG)
#define debug_printk(_lvl, _func, _line, _pid, _fmt, ...)               \
   do {} while (0)
#define debug_cond_action(_mask, _cond, _action)                        \
   do {} while (0)
#else
#define debug_printk(_lvl, _func, _line, _pid, _fmt, ...)               \
    printk(_lvl "%s:%s,%u,%d: " _fmt, zhpe_driver_name,                 \
           _func, _line, _pid, ##__VA_ARGS__)
#define debug_cond_action(_mask, _cond, _action)                        \
do {                                                                    \
    if ((zhpe_debug_flags & (_mask)) && (_cond)) {                      \
        _action;                                                        \
    }                                                                   \
} while (0)
#endif /* defined(NDEBUG) */

#define debug_cond(_mask, _cond, _fmt, ...)                             \
    debug_cond_action(_mask, _cond,                                     \
                      zprintk(KERN_DEBUG, _fmt, ##__VA_ARGS__))
#define debug(_mask, _fmt, ...)                                         \
    debug_cond(_mask, true, _fmt, ##__VA_ARGS__)
#define debug_caller(_mask, _callf, _line,  _fmt, ...)                  \
    debug_cond_action(_mask, true,                                      \
                      zprintk_caller(KERN_DEBUG, _callf, _line,         \
                                     _fmt, ##__VA_ARGS__))

#define DEBUG_TRACKER_SANE (0)

#define GB(_x)            ((_x)*BIT_ULL(30))
#define TB(_x)            ((_x)*BIT_ULL(40))

/* platforms that the zhpe driver supports */
enum {
    ZHPE_UNKNOWN         = 0x0,
    ZHPE_CARBON          = 0x1,
    ZHPE_PFSLICE         = 0x2,
    ZHPE_WILDCAT         = 0x3,
};

extern int zhpe_platform;

struct xdm_qcm_header {
    uint64_t cmd_q_base_addr  : 64; /* byte 0 */
    uint64_t cmpl_q_base_addr : 64;
    uint64_t cmd_q_size       : 16;
    uint64_t rv2              : 16;
    uint64_t cmpl_q_size      : 16;
    uint64_t rv3              : 16;
    uint64_t local_pasid      : 20;
    uint64_t traffic_class    : 4;
    uint64_t priority         : 1;
    uint64_t rv4              : 5;
    uint64_t virt_addr        : 1;
    uint64_t q_virt_addr      : 1;
    uint64_t fabric_pasid     : 20;
    uint64_t rv5              : 12;
    uint64_t master_stop      : 1;
    uint64_t rv6              : 63;
    uint64_t active_cmd_cnt   : 11;
    uint64_t rv7              : 4;
    uint64_t active           : 1;
    uint64_t status           : 3;
    uint64_t rv8              : 12;
    uint64_t error            : 1;
    uint64_t rv9              : 32;
    uint64_t rv10[2];
    uint64_t stop             : 1;
    uint64_t rv11             : 63;
    uint64_t rv12[7];
    uint64_t cmd_q_tail_idx   : 16;
    uint64_t rv13             : 48;
    uint64_t rv14[7];
    uint64_t cmd_q_head_idx   : 16;
    uint64_t rv15             : 48;
    uint64_t rv16[7];
    uint64_t cmpl_q_tail_idx  : 16;
    uint64_t rv17             : 15;
    uint64_t toggle_valid     : 1;
    uint64_t rv18             : 32;
};

struct xdm_qcm_cmd_buf {
    uint64_t                  bytes8[8];
};

struct xdm_qcm {
    struct xdm_qcm_header     hdr;
    uint64_t                  rv19[223];
    struct xdm_qcm_cmd_buf    buf[16];
    uint64_t                  rv20[7808];
};

struct rdm_qcm_header {
    uint64_t cmpl_q_base_addr : 64;
    uint64_t cmpl_q_size      : 20;
    uint64_t rv1              : 12;
    uint64_t pasid            : 20;
    uint64_t rv2              : 10;
    uint64_t intr_enable      : 1;
    uint64_t q_virt_addr      : 1;
    uint64_t master_stop      : 1;
    uint64_t rv3              : 63;
    uint64_t active           : 1;
    uint64_t rv4              : 63;
    uint64_t rv5[4];		   /* end of first 64 bytes */
    uint64_t stop             : 1;
    uint64_t rv6              : 63;
    uint64_t rv7[7];
    uint64_t rcv_q_tail_idx   : 20;
    uint64_t rv8              : 11;
    uint64_t toggle_valid     : 1;
    uint64_t rv9              : 32;
    uint64_t rv10[7];
    uint64_t rcv_q_head_idx   : 20;
    uint64_t rv11             : 44;
};

struct rdm_qcm {
    struct rdm_qcm_header     hdr;
    uint64_t rv12[8167];
};

struct req_pte {
    uint64_t pasid         : 20;  /* byte  0 */
    uint64_t space_type    :  3;
    uint64_t rke           :  1;
    uint64_t traffic_class :  4;
    uint64_t dc_grp        :  2;
    uint64_t rv0           :  6;
    uint64_t dgcid         : ZHPE_GCID_BITS;  /* in HW, dsid:16, dcid:12 */
    uint64_t ctn           :  2;  /* byte  8 */
    uint64_t rv8           : 10;
    uint64_t addr          : 52;
    uint64_t rkey          : 32;  /* byte 16 */
    uint64_t rv20          : 32;
    uint64_t rv24          : 32;  /* byte 24 */
    uint64_t rv28          : 31;
    uint64_t v             :  1;
} __attribute__ ((aligned (32)));

struct rsp_pte {
    uint64_t pasid         : 20;  /* byte  0 */
    uint64_t space_type    :  3;  /* only DATA (0) allowed */
    uint64_t rke           :  1;
    uint64_t rv0           : 40;
    uint64_t va            : 48;  /* byte  8 */
    uint64_t rv12          : 16;
    uint64_t ro_rkey       : 32;  /* byte 16 */
    uint64_t rw_rkey       : 32;
    uint64_t window_sz     : 48;  /* byte 24 */
    uint64_t rv28          : 15;
    uint64_t v             :  1;
} __attribute__ ((aligned (32)));

struct page_grid {
    uint64_t base_addr     : 64;  /* byte 0 */
    uint64_t page_count    : 18;  /* byte 8 */  /* 0 disables grid */
    uint64_t rv8a          :  6;
    uint64_t page_size     :  6;  /* min 12 (4KiB), max 48 (256TiB) */
    uint64_t rv8b          :  2;
    uint64_t base_pte_idx  : 17;  /* byte 12 */
    uint64_t rv12a         :  7;
    uint64_t smo           :  1;  /* secure mode only */
    uint64_t rv12b         :  7;
} __attribute__ ((aligned (16)));

struct containment_counter {
    uint64_t counter       : 16;  /* byte  0 */
    uint64_t rv0           : 48;
    uint64_t rv1[7];              /* bytes 8 - 63 */
} __attribute__ ((aligned (64)));

struct big_hammer_containment {
    uint64_t bhc           :  1;  /* byte  0 */
    uint64_t rv0           : 63;
    uint64_t rv1[3];              /* bytes 8 - 31 */
} __attribute__ ((aligned (32)));

/* Platform dependent values */

/* Global platform specific variables */
extern unsigned int zhpe_req_zmmu_entries;
extern unsigned int zhpe_rsp_zmmu_entries;
extern unsigned int zhpe_xdm_queues_per_slice;
extern unsigned int zhpe_rdm_queues_per_slice;
extern uint64_t zhpe_reqz_min_cpuvisible_addr;
extern uint64_t zhpe_reqz_max_cpuvisible_addr;
extern uint64_t zhpe_reqz_phy_cpuvisible_off;

/* Carbon Simulator Platform */
#define CARBON_REQ_ZMMU_ENTRIES             (128*1024)
#define CARBON_RSP_ZMMU_ENTRIES             (64*1024)
#define CARBON_XDM_QUEUES_PER_SLICE         (256)
#define CARBON_RDM_QUEUES_PER_SLICE         (256)
#define CARBON_REQZ_MIN_CPUVISIBLE_ADDR     (GB(4)+TB(1))
#define CARBON_REQZ_MAX_CPUVISIBLE_ADDR     (GB(13312) - 1)
#define CARBON_REQZ_PHY_CPUVISIBLE_OFF      (GB(0))

/* PFslice FPGA Platform */
#define PFSLICE_REQ_ZMMU_ENTRIES            (1024)
#define PFSLICE_RSP_ZMMU_ENTRIES            (1024)
#define PFSLICE_XDM_QUEUES_PER_SLICE        (256)
#define PFSLICE_RDM_QUEUES_PER_SLICE        (256)
#define PFSLICE_REQZ_MIN_CPUVISIBLE_ADDR    (GB(0))
#define PFSLICE_REQZ_MAX_CPUVISIBLE_ADDR    (GB(13312) - 1)

/* Wildcat Hardware Platform */
#define WILDCAT_REQ_ZMMU_ENTRIES            (128*1024)
#define WILDCAT_RSP_ZMMU_ENTRIES            (64*1024)
#define WILDCAT_XDM_QUEUES_PER_SLICE        (256)
#define WILDCAT_RDM_QUEUES_PER_SLICE        (256)
#define WILDCAT_REQZ_MIN_CPUVISIBLE_ADDR    (GB(0))
#define WILDCAT_REQZ_MAX_CPUVISIBLE_ADDR    (GB(13312) - 1)
#define WILDCAT_SLINK_SLICE_MASK            (0xc)

/* Platform values common to all platforms */
#define ZHPE_MAX_XDM_QLEN                 (BIT(16)-1)
#define ZHPE_MAX_RDM_QLEN                 (BIT(20)-1)
#define ZHPE_MAX_DMA_LEN                  (1U << 31)
#define MAX_REQ_ZMMU_ENTRIES              (128*1024)
#define MAX_RSP_ZMMU_ENTRIES              (64*1024)
#define CONTAINMENT_COUNTER_ALIASES       (128*1024)
#define PAGE_GRID_ENTRIES                 (16)

#define REQ_PTE_SZ   (MAX_REQ_ZMMU_ENTRIES*sizeof(struct req_pte))
#define PAGE_GRID_SZ (PAGE_GRID_ENTRIES*sizeof(struct page_grid))
#define REQ_RV1_SZ       (0x500000 - (REQ_PTE_SZ + PAGE_GRID_SZ))
#define REQ_BHC_SZ       (sizeof(struct big_hammer_containment))
#define REQ_RV2_SZ       (0x800000 - 0x500000 - REQ_BHC_SZ)
#define REQ_RV3_SZ       (0x2000000 - 0x1000000)

#define PAGE_GRID_MIN_PAGESIZE       12
#define PAGE_GRID_MAX_PAGESIZE       48

#define MAX_RDM_QUEUES_PER_SLICE        ZHPE_MAX_RDMQS_PER_SLICE
#define MAX_XDM_QUEUES_PER_SLICE        ZHPE_MAX_XDMQS_PER_SLICE

struct req_zmmu {
    struct req_pte                pte[MAX_REQ_ZMMU_ENTRIES];
    struct page_grid              page_grid[PAGE_GRID_ENTRIES];
    uint8_t                       rv1[REQ_RV1_SZ];
    struct big_hammer_containment bhc;
    uint8_t                       rv2[REQ_RV2_SZ];
    struct containment_counter    contain_cntr[CONTAINMENT_COUNTER_ALIASES];
    uint8_t                       rv3[REQ_RV3_SZ];
};

#define RSP_RV1_SZ       (0x400000 - 0x200000)
#define RSP_RV2_SZ       (0x600000 - (0x400000 + PAGE_GRID_SZ))
#define RSP_RV3_SZ       (0x2000000 - 0x600008)
#define RSP_TAKE_SNAPSHOT_MASK (0x3FF)

struct rsp_zmmu {
    struct rsp_pte                pte[MAX_RSP_ZMMU_ENTRIES];
    uint8_t                       rv1[RSP_RV1_SZ];
    struct page_grid              page_grid[PAGE_GRID_ENTRIES];
    uint8_t                       rv2[RSP_RV2_SZ];
    uint64_t                      take_snapshot;
    uint8_t                       rv3[RSP_RV3_SZ];
};

struct sw_page_grid {
    struct page_grid page_grid;
    struct rb_node   base_pte_node;  /* rbtree ordered on base_pte_idx */
    struct rb_node   base_addr_node; /* and another on base_addr */
    struct rb_root   pte_tree;       /* rbtree root of allocated ptes */
    bool             cpu_visible;    /* only for requester page_grids */
};

#define PAGE_GRID_PS_BITS      (64)

struct page_grid_info {
    struct sw_page_grid pg[PAGE_GRID_ENTRIES];
    DECLARE_BITMAP(pg_bitmap, PAGE_GRID_ENTRIES);
    DECLARE_BITMAP(pg_cpu_visible_ps_bitmap, PAGE_GRID_PS_BITS); /* req only */
    DECLARE_BITMAP(pg_non_visible_ps_bitmap, PAGE_GRID_PS_BITS);
    struct radix_tree_root pg_pagesize_tree;
    uint                pte_entries;
    struct rb_root      base_pte_tree;
    struct rb_root      base_addr_tree;
};

struct rdm_vector_list {
    struct list_head list;
    int              irq_index;
    int              queue;
    irqreturn_t      (*handler)(int, void *);
    void             *data;
};

struct rdm_vector_list_head {
    spinlock_t       list_lock;
    struct list_head list_head;
};

struct slice {
    struct func1_bar0   *bar;        /* kernel mapping of BAR */
    phys_addr_t         phys_base;   /* physical address of BAR */
    spinlock_t          zmmu_lock;   /* per-slice zmmu lock */
    bool                valid;       /* slice is fully initialized */
    unsigned int        id;          /* zero based, unique slice id */
    unsigned int        phys_id;     /* zero based, unique physical slice id */
    struct pci_dev	*pdev;
    struct iommu_domain	*dom;
    /* Revisit: add s_link boolean */
    spinlock_t           xdm_slice_lock; /* locks alloc_count, alloced_bitmap */
    int                  xdm_alloc_count;
    DECLARE_BITMAP(xdm_alloced_bitmap, MAX_XDM_QUEUES_PER_SLICE);
    spinlock_t           rdm_slice_lock; /* locks alloc_count, alloced_bitmap */
    int                  rdm_alloc_count;
    DECLARE_BITMAP(rdm_alloced_bitmap, MAX_RDM_QUEUES_PER_SLICE);
    uint16_t             irq_vectors_count; /* number of interrupt vectors */
    uint16_t             stuck_xdm_queues;
    uint16_t             stuck_rdm_queues;
    /* per vector list of queues sharing a vector */
    struct rdm_vector_list_head irq_vectors[VECTORS_PER_SLICE];
};

#define SLICE_VALID(s) ((s)->valid) /* bool SLICE_VALID(struct slice *s) */

struct bridge;  /* tentative declaration */

struct xdm_info {
    struct bridge  *br;
    uint32_t       cmdq_ent, cmplq_ent;
    uint8_t        slice_mask, traffic_class, priority;
    size_t         cmdq_size, cmplq_size, qcm_size;
    struct slice   *sl;
    struct xdm_qcm *hw_qcm_addr;
    union zpages   *cmdq_zpage, *cmplq_zpage;
    union zhpe_hw_wq_entry *cmdq_shadow;
    ulong          *cmdq_free_bitmap;
    ulong          *cmdq_retry_bitmap;
    int            slice, queue;
    uint32_t       reqctxid;
    uint           cmdq_tail_shadow;                   /* shadow of HW reg */
    uint           cmplq_head;                         /* SW-only */
    uint           active_cmds;                        /* SW-only */
    uint           retry_cmds;                         /* SW-only */
    uint           retry_last;                         /* SW-only */
    spinlock_t     xdm_info_lock;
};

struct rdm_info {
    struct bridge  *br;
    uint32_t       cmplq_ent;
    uint8_t        slice_mask;
    size_t         cmplq_size, qcm_size;
    struct slice   *sl;
    struct rdm_qcm *hw_qcm_addr;
    union zpages   *cmplq_zpage;
    int            slice, queue, vector;
    uint32_t       rspctxid;
    uint           cmplq_head_shadow;                  /* shadow of HW reg */
    uint32_t       cmplq_head_commit;
    spinlock_t     rdm_info_lock;
};

struct bridge {
    int                   probe_error;
    uint32_t              gcid;
    uint8_t               expected_slices;
    uint8_t               num_slices;
    uint8_t               slice_mask;
    struct slice          slice[SLICES];
    spinlock_t            zmmu_lock;  /* global bridge zmmu lock */
    struct page_grid_info req_zmmu_pg;
    struct page_grid_info rsp_zmmu_pg;
    struct xdm_info       msg_xdm;
    struct rdm_info       msg_rdm;
    struct mutex          probe_mutex; /* one probe at a time; also CSRs */
    spinlock_t            fdata_lock;  /* protects fdata_list */
    struct list_head      fdata_list;
    struct work_struct    msg_work;
    wait_queue_head_t     zhpe_poll_wq[MAX_IRQ_VECTORS];
    spinlock_t            snap_lock;
    wait_queue_head_t     snap_wqh[2];
    uint                  snap_group;
    uint8_t               snap_wait_idx;
    bool                  snap_active;
    bool                  snap_failed;
    spinlock_t            rspctxid_rbtree_lock; /* protects rspctxid_rbtree */
    struct rb_root        rspctxid_rbtree;
};

struct queue_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	void		*pages[];
};

struct hsr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	phys_addr_t	base_addr;
};

struct dma_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	struct device   *dev;
	void 		*cpu_addr;
	dma_addr_t	dma_addr;
};

struct rmr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	struct zhpe_rmr *rmr;
};

struct hdr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
};

union zpages {
    struct hdr_zpage	hdr;
    struct queue_zpage	queue;
    struct hsr_zpage    hsr;
    struct dma_zpage    dma;
    struct rmr_zpage    rmrz;
};

struct zmap {
    struct list_head    list;
    struct file_data    *owner;
    ulong               offset;
    union zpages       *zpages;
};

#define ZMAP_BAD_OWNER  (ERR_PTR(-EACCES))

/* struct bridge *BRIDGE_FROM_SLICE(struct slice *s) */
#define BRIDGE_FROM_SLICE(s) ((struct bridge *)(((void *)((s) - (s)->id)) - \
                                                offsetof(struct bridge, slice)))
struct file_data {
    void                (*free)(const char *callf, uint line, void *ptr);
    atomic_t            count;
    uint8_t             state;
    unsigned int        pasid;
    unsigned int        fabric_pasid;
    uint32_t            ro_rkey;
    uint32_t            rw_rkey;
    spinlock_t          io_lock;
    wait_queue_head_t   io_wqh;
    struct list_head    fdata_list;
    struct list_head    rd_list;
    struct bridge       *bridge;
    spinlock_t          uuid_lock;  /* protects local_uuid, remote_uuid_tree */
    struct uuid_tracker *local_uuid;
    struct rb_root      fd_remote_uuid_tree;  /* UUIDs imported by this fdata */
    spinlock_t          mr_lock;    /* protects mr_tree, fd_rmr_tree */
    struct rb_root      mr_tree;
    struct rb_root      fd_rmr_tree;
    spinlock_t          zmap_lock;  /* protects zmap_list */
    struct list_head    zmap_list;
    struct zmap         *shared_zmap;
    union zpages        *local_shared_zpage;
    struct zmap         *local_shared_zmap;
    struct zmap         *global_shared_zmap;
    struct mutex        xdm_queue_mutex;
    DECLARE_BITMAP(xdm_queues, MAX_XDM_QUEUES_PER_SLICE*SLICES);
    spinlock_t          rdm_queue_lock;
    DECLARE_BITMAP(rdm_queues, MAX_RDM_QUEUES_PER_SLICE*SLICES);
    pid_t               pid;        /* pid that allocated this file_data */
    struct zhpe_umem    *big_rsp_umem;
    struct mm_struct    *mm;
    struct mmu_notifier mmun;
};

int zhpe_mmun_init(struct file_data *fdata);
void zhpe_mmun_exit(struct file_data *fdata);

struct io_entry {
    void                (*free)(const char *callf, uint line, void *ptr);
    atomic_t            count;
    bool                nonblock;
    struct zhpe_common_hdr hdr;
    struct file_data    *fdata;
    struct list_head    list;
    size_t              data_len;
    union {
        uint8_t         data[0];
        union zhpe_op   op;
    };
};

enum {
    STATE_CLOSED                = 0x01,
    STATE_READY                 = 0x02,
    STATE_INIT                  = 0x04,
    STATE_MR_OVERLAP_CHECKING   = 0x08,
    STATE_MR_LOCKED_DOWN        = 0x10,
};

/* Globals */
extern struct bridge    zhpe_bridge;
extern uint genz_loopback;

#define CHECK_INIT_STATE(_entry, _ret, _label)              \
    do {                                                    \
        spin_lock(&(_entry)->fdata->io_lock);               \
        if (!((_entry)->fdata->state & STATE_INIT)) {       \
            (_ret) = -EBADRQC;                              \
            spin_unlock(&(_entry)->fdata->io_lock);         \
            goto _label;                                    \
        }                                                   \
        spin_unlock(&(_entry)->fdata->io_lock);             \
    } while (0)


struct func1_bar0 {
    struct req_zmmu req_zmmu;
    struct rsp_zmmu rsp_zmmu;
    struct xdm_qcm  xdm[512];
    struct rdm_qcm  rdm[512];
};

#define REQZ_MIN_NONVISIBLE_ADDR     TB(256)
#define REQZ_MAX_NONVISIBLE_ADDR     (-1ull)
#define BASE_ADDR_ERROR              REQZ_MAX_NONVISIBLE_ADDR

#define do_kmalloc(...) \
    _do_kmalloc(__func__, __LINE__, __VA_ARGS__)
void *_do_kmalloc(const char *callf, uint line,
                         size_t size, gfp_t flags, bool zero);
#define do_kfree(...) \
    _do_kfree(__func__, __LINE__, __VA_ARGS__)
void _do_kfree(const char *callf, uint line, void *ptr);

#define do_free_pages(...) \
    _do_free_pages(__func__, __LINE__, __VA_ARGS__)
void _do_free_pages(const char *callf, uint line, void *ptr, int order);

#define do_free_page(_ptr) \
    _do_free_pages(__func__, __LINE__, (_ptr), 0)

#define do__get_free_pages(...) \
    _do__get_free_pages(__func__, __LINE__, __VA_ARGS__)
void *_do__get_free_pages(const char *callf, uint line,
                          int order, gfp_t flags, bool zero);

#define do__get_free_page(_flags, _zero)                        \
    _do__get_free_pages(__func__, __LINE__, 0, (_flags), (_zero))

int queue_io_rsp(struct io_entry *entry, size_t data_len, int status);


void _zpages_free(const char *callf, uint line, union zpages *zpages);
#define zpages_free(...) \
    _zpages_free(__func__, __LINE__, __VA_ARGS__)

enum {
	QUEUE_PAGE =           1,
	HSR_PAGE =             2,
	DMA_PAGE =             3,
	RMR_PAGE =             4,
	LOCAL_SHARED_PAGE =    5,
	GLOBAL_SHARED_PAGE =   6
};

struct zhpe_rmr;  /* tentative definition */

union zpages *_queue_zpages_alloc(const char *callf, uint line, 
	size_t size, bool contig);
#define queue_zpages_alloc(...) \
    _queue_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_dma_zpages_alloc(const char *callf, uint line, 
	struct slice * sl, size_t size);
#define dma_zpages_alloc(...) \
    _dma_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_hsr_zpage_alloc(const char *callf, uint line,
                               phys_addr_t base_addr);
#define hsr_zpage_alloc(...) \
    _hsr_zpage_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_rmr_zpages_alloc(const char *callf, uint line,
                                struct zhpe_rmr *rmr);
#define rmr_zpages_alloc(...) \
    _rmr_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

void _zmap_fdata_free(const char *callf, uint line, struct file_data *fdata,
                      struct zmap *zmap);
#define zmap_fdata_free(...)                    \
    _zmap_fdata_free(__func__, __LINE__, __VA_ARGS__)

struct zmap *_zmap_alloc(
	const char *callf,
	uint line,
	struct file_data *fdata,
	union zpages *zpages);
#define zmap_alloc(...) \
    _zmap_alloc(__func__, __LINE__, __VA_ARGS__)

void zhpe_disable_dbg_obs(struct bridge *br);

struct file_data *pid_to_fdata(struct bridge *br, pid_t pid);

#define arithcmp(_a, _b)        ((_a) < (_b) ? -1 : ((_a) > (_b) ? 1 : 0))

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

#ifndef UUID_STRING_LEN
#define UUID_STRING_LEN (36)
#endif

#ifdef HAVE_RHEL
static inline pgprot_t pgprot_writethrough(pgprot_t prot)
{
    return __pgprot(pgprot_val(prot) |
                    cachemode2protval(_PAGE_CACHE_MODE_WT));
}
#endif

#ifdef HAVE_RHEL
static inline void radix_tree_iter_delete(struct radix_tree_root *root,
                                          struct radix_tree_iter *iter,
                                          void __rcu **slot)
{
    /* REVISIT:May not be fully correct. */
    if (radix_tree_delete(root, iter->index))
        iter->index = iter->next_index;
}
#endif

static inline void _put_file_data(const char *callf, uint line,
                                  struct file_data *fdata)
{
    int                 count;

    if (fdata) {
        count = atomic_dec_return(&fdata->count);
        debug_caller(DEBUG_COUNT, callf, line, "%s:fdata 0x%px count %d\n",
                     __func__, fdata, count);
        if (!count && fdata->free)
            fdata->free(callf, line, fdata);
    }
}

#define put_file_data(...) \
    _put_file_data(__func__, __LINE__, __VA_ARGS__)

static inline struct file_data *_get_file_data(const char *callf, uint line,
                                               struct file_data *fdata)
{
    int                 count;

    if (!fdata)
        return NULL;

    count = atomic_inc_return(&fdata->count);
    /* Override unused variable warning. */
    (void)count;
    debug_caller(DEBUG_COUNT, callf, line, "%s:fdata 0x%px count %d\n",
                 __func__, fdata, count);

    return fdata;
}

#define get_file_data(...) \
    _get_file_data(__func__, __LINE__, __VA_ARGS__)

#include <zhpe_uuid.h>
#include <zhpe_zmmu.h>
#include <zhpe_memreg.h>
#include <zhpe_pasid.h>
#include <zhpe_queue.h>
#include <zhpe_rkey.h>
#include <zhpe_msg.h>
#include <zhpe_intr.h>
#endif /* _ZHPE_DRIVER_H_ */

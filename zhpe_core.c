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

#include <zhpe.h>
#include <zhpe_driver.h>
#include "zhpe_version.h"

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/amd-iommu.h>
#include <linux/cdev.h>
#include <linux/delay.h>

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#endif

#ifndef NDEBUG
module_param_named(debug, zhpe_debug_flags, uint, 0644);
MODULE_PARM_DESC(debug, "debug output bitmask");
#endif /* !NDEBUG */

module_param_named(kmsg_timeout, zhpe_kmsg_timeout, uint, 0444);
MODULE_PARM_DESC(kmsg_timeout,
                 "kernel-to-kernel message timeout in seconds (default: 10)");

/*
 * Write pusher default settings:
 *
 * physical address zero, zero byte reads, and
 * ctl_28:PBShift 4 << 20, MinDel 10 << 12, NumReq 16 << 4, En 1
 */

static ulong wr_pusher_phyaddr = 0;
static uint wr_pusher_dvsec_28 = 0x509101;

module_param(wr_pusher_phyaddr, ulong, 0444);
MODULE_PARM_DESC(wr_pusher_phyaddr, "Write-pusher physical address");
module_param(wr_pusher_dvsec_28, uint, 0444);
MODULE_PARM_DESC(wr_pusher_dvsec_28, "Write-pusher DVSEC offset 0x28");

/*
 * Driver CSR setting controls. Only fields and values the driver sets by
 * default are mentioned; other bits are preserved;.
 *
 * SKW_SHIM_INB_CFG: Set acks for write pusher.
 * [0:0] rspzmmu_write_ack_type, value 1
 * [1:1] rdm_write_ack_type, value 0
 * [2:2] xdm_write_ack_type, value 0
 * [3:3] xdm_sync_ack_type, value 1
 *
 *
 * XDM_REQUEST_CFG : disable queue stop on command-level error.
 * [11:11] dis_sqoce, value 1
 *
 * xdm_priority_cfg_enable : enable priority configuration changes.
 *
 * XDM_SIZE_CFG0: limit local/fabric move engine to two commands at a time.
 * [28:24] fab_recirc, value 1
 * [60:56] lcl_recirc, value 1
 *
 * XDM_PRIORITY_CFG0/1: limit prio to 200 command pool entries
 * [39:32] cmd_pool_cap, value 199
 *
 * XDM_PRIORITY_CFG0/1: limit local/fabric move engine to one command per prio
 * [44:40] lcl_recirc_cap, value 0
 * [52:48] fab_recirc_cap, value 0
 */

static bool xdm_priority_cfg_enable         = 0;

module_param(xdm_priority_cfg_enable, bool, 0444);
MODULE_PARM_DESC(xdm_priority_cfg_enable,
                 "1/Y/y => enable XDM priority configuration changes"
                 " (Default:0)");

static ulong skw_shim_inb_cfg_mask      = ~0x000000000000000FUL;
static ulong skw_shim_inb_cfg_bits      =  0x0000000000000009UL;

static ulong xdm_request_cfg_mask       = ~0x0000000000000800UL;
static ulong xdm_request_cfg_bits       =  0x0000000000000800UL;


struct xdm_priority {
    ulong       xdm_size_cfg0_mask;
    ulong       xdm_size_cfg0_bits;
    ulong       xdm_priority_cfg0_mask;
    ulong       xdm_priority_cfg0_bits;
    ulong       xdm_priority_cfg1_mask;
    ulong       xdm_priority_cfg1_bits;
};

static struct xdm_priority xdm_pri_off = {
    .xdm_size_cfg0_mask                 = ~0xFFFFFFFFFFFFFFFFUL,
    .xdm_size_cfg0_bits                 =  0x1F07F0FF1F3FF3FFUL,
    .xdm_priority_cfg0_mask             = ~0xFFFFFFFFFFFFFFFFUL,
    .xdm_priority_cfg0_bits             =  0x001F1FFF003F3F80UL,
    .xdm_priority_cfg1_mask             = ~0xFFFFFFFFFFFFFFFFUL,
    .xdm_priority_cfg1_bits             =  0x001F1FFF003F3F80UL,
};

static struct xdm_priority xdm_pri_on = {
    .xdm_size_cfg0_mask                 = ~0x1F0000001F000000UL,
    .xdm_size_cfg0_bits                 =  0x0100000001000000UL,
    .xdm_priority_cfg0_mask             = ~0x001F1FFF00000000UL,
    .xdm_priority_cfg0_bits             =  0x000000C700000000UL,
    .xdm_priority_cfg1_mask             = ~0x001F1FFF00000000UL,
    .xdm_priority_cfg1_bits             =  0x000000C700000000UL,
};

module_param(skw_shim_inb_cfg_mask, ulong, 0444);
MODULE_PARM_DESC(skw_shim_inb_cfg_mask,
                 "new = (current & mask) | (bits & ~mask)");
module_param(skw_shim_inb_cfg_bits, ulong, 0444);
MODULE_PARM_DESC(skw_shim_inb_cfg_bits,
                 "new = (current & mask) | (bits & ~mask)");

module_param(xdm_request_cfg_mask, ulong, 0444);
MODULE_PARM_DESC(xdm_request_cfg_mask,
                 "new = (current & mask) | (bits & ~mask)");
module_param(xdm_request_cfg_bits, ulong, 0444);
MODULE_PARM_DESC(xdm_request_cfg_bits,
                 "new = (current & mask) | (bits & ~mask)");

module_param_named(xdm_size_cfg0_mask, xdm_pri_on.xdm_size_cfg0_mask,
                   ulong, 0444);
MODULE_PARM_DESC(xdm_size_cfg0_mask, "new = (current & mask) | (bits & ~mask)");
module_param_named(xdm_size_cfg0, xdm_pri_on.xdm_size_cfg0_bits, ulong, 0444);
MODULE_PARM_DESC(xdm_size_cfg0_bits, "new = (current & mask) | (bits & ~mask)");

module_param_named(xdm_priority_cfg0_mask,
                   xdm_pri_on.xdm_priority_cfg0_mask, ulong, 0444);
MODULE_PARM_DESC(xdm_priority_cfg0_mask,
                 "new = (current & mask) | (bits & ~mask)");
module_param_named(xdm_priority_cfg0_bits,
                   xdm_pri_on.xdm_priority_cfg0_bits, ulong, 0444);
MODULE_PARM_DESC(xdm_priority_cfg0_bits,
                 "new = (current & mask) | (bits & ~mask)");

module_param_named(xdm_priority_cfg1_mask,
                   xdm_pri_on.xdm_priority_cfg1_mask, ulong, 0444);
MODULE_PARM_DESC(xdm_priority_cfg1_mask,
                 "new = (current & mask) | (bits & ~mask)");
module_param_named(xdm_priority_cfg1_bits,
                   xdm_pri_on.xdm_priority_cfg1_bits, ulong, 0444);
MODULE_PARM_DESC(xdm_priority_cfg1_bits,
                 "new = (current & mask) | (bits & ~mask)");

static bool allow_mmap = false;
module_param(allow_mmap, bool, 0444);
MODULE_PARM_DESC(allow_mmap, "Allow mmap when dangerous");

const char zhpe_driver_name[] = DRIVER_NAME;

static atomic64_t mem_total = ATOMIC64_INIT(0);

static union zpages            *global_shared_zpage;
struct zhpe_global_shared_data *global_shared_data;

static struct pci_device_id zhpe_id_table[] = {
    { PCI_VDEVICE(HP_3PAR, 0x028f), }, /* Function 0 */
    { PCI_VDEVICE(HP_3PAR, 0x0290), }, /* Function 1 */
    { 0 },
};

MODULE_DEVICE_TABLE(pci, zhpe_id_table);


/* Revisit Carbon: Workaround for Carbon simulator not having AVX instructions
 * and ymm registers, but also not requiring 16/32-byte accesses
 */
uint zhpe_no_avx = 0;

unsigned int zhpe_req_zmmu_entries;
unsigned int zhpe_rsp_zmmu_entries;
unsigned int zhpe_xdm_queues_per_slice;
unsigned int zhpe_rdm_queues_per_slice;
uint64_t zhpe_reqz_min_cpuvisible_addr;
uint64_t zhpe_reqz_max_cpuvisible_addr;
uint64_t zhpe_reqz_phy_cpuvisible_off;
int zhpe_platform = ZHPE_UNKNOWN;
static char *platform = "unknown";
module_param(platform, charp, 0444);
MODULE_PARM_DESC(platform,
                 "Platform the driver is running on: carbon|pfslice|wildcat"
                 " (ignored)");

uint zhpe_no_rkeys = 1;
module_param_named(no_rkeys, zhpe_no_rkeys, uint, S_IRUGO);
MODULE_PARM_DESC(no_rkeys, "Disable Gen-Z R-keys");

uint snap_dbg_obs = 1;
module_param(snap_dbg_obs, uint, S_IRUGO);
MODULE_PARM_DESC(snap_dbg_obs,
                 "Disable HW dbg_obs on TAKE_SNAPSHOT failure");

uint msg_qsize = 8192;
module_param(msg_qsize, uint, S_IRUGO);
MODULE_PARM_DESC(msg_qsize,
                 "Number of entries in driver-to-driver msg queues"
                 " (default: 8192");

static int __init zhpe_init(void);
static void zhpe_exit(void);

module_init(zhpe_init);
module_exit(zhpe_exit);

MODULE_VERSION(ZHPE_VERSION);
MODULE_LICENSE("GPL");

#define INVALID_GCID    (~0U)

struct bridge    zhpe_bridge;
struct sw_page_grid     sw_pg[PAGE_GRID_ENTRIES];

static DECLARE_WAIT_QUEUE_HEAD(poll_wqh);

uint no_iommu = 0;
module_param(no_iommu, uint, S_IRUGO);
MODULE_PARM_DESC(no_iommu, "System does not have an IOMMU (default=0)");

uint signal_mr_overlap = SIGBUS;
module_param(signal_mr_overlap, uint, S_IRUGO);
MODULE_PARM_DESC(signal_mr_overlap, "Signal MR overlap (default=SIGBUS)");

#define TRACKER_MAX     (256)

/* Revisit Carbon: Gen-Z Global CID should come from bridge Core
 * Structure, but for now, it's a module parameter
 */
static uint genz_gcid = INVALID_GCID;
module_param(genz_gcid, uint, S_IRUGO);
MODULE_PARM_DESC(genz_gcid, "Gen-Z bridge global CID");

uint genz_loopback = 1;
module_param(genz_loopback, uint, S_IRUGO);
MODULE_PARM_DESC(genz_loopback, "Gen-Z loopback mode (default=1)");

static char *req_page_grid = "default";
module_param(req_page_grid, charp, 0444);
MODULE_PARM_DESC(req_page_grid,
                 "requester page grid allocations - page_sz{*:}page_cnt[, ...]"
    );

static char *rsp_page_grid = "default";
module_param(rsp_page_grid, charp, 0444);
MODULE_PARM_DESC(rsp_page_grid,
                 "responder page grid allocations - page_sz:page_cnt[, ...]");

uint zhpe_debug_flags;

#define free_zmap_list(...) \
    _free_zmap_list(__func__, __LINE__, __VA_ARGS__)

#define zmap_free(...) \
    _zmap_free(__func__, __LINE__, __VA_ARGS__)

static bool _expected_saw(const char *callf, uint line,
                          const char *label, uintptr_t expected, uintptr_t saw)
{
    if (expected == saw)
        return true;

    zprintk_caller(KERN_ERR, callf, line, "%s:%s:expected 0x%lx saw 0x%lx\n",
                   __func__, label, expected, saw);

    return false;
}

#define expected_saw(...) \
    _expected_saw(__func__, __LINE__, __VA_ARGS__)

void _do_kfree(const char *callf, uint line, void *ptr)
{
    size_t              size;

    if (!ptr)
        return;

    ptr -= sizeof(void *);
    size = *(uintptr_t *)ptr;
    atomic64_sub(size, &mem_total);
    debug(DEBUG_MEM, "ptr 0x%px size %lu\n", ptr, size);
    kfree(ptr);
}

void *_do_kmalloc(const char *callf, uint line,
                  size_t size, gfp_t flags, bool zero)
{
    void                *ret, *ptr;

    /* kmalloc alignment is sizeof(void *) */
    ptr = kmalloc(size + sizeof(void *), flags);
    if (!ptr) {
        if (flags != GFP_ATOMIC)
            zprintk_caller(KERN_ERR, callf, line,
                           "%s:failed to allocate %lu bytes\n", __func__, size);
        return NULL;
    }
    ret = ptr + sizeof(void *);
    if (zero)
        memset(ret, 0, size);
    debug_caller(DEBUG_MEM, callf, line, "%s:ptr 0x%px ret 0x%px size %lu\n",
                 __func__, ptr, ret, size);
    atomic64_add(size, &mem_total);
    *(uintptr_t *)ptr = size;

    return ret;
}

void _do_free_pages(const char *callf, uint line, void *ptr, int order)
{
    size_t              size;
    struct page         *page;

    if (!ptr)
        return;

    size = 1UL << (order + PAGE_SHIFT);
    atomic64_sub(size, &mem_total);
    page = virt_to_page(ptr);
    (void)page;
    debug_caller(DEBUG_MEM, callf, line,
                 "%s:ptr/page/pfn 0x%px/0x%px/0x%lx size %lu\n",
                 __func__, ptr, page, page_to_pfn(page), size);
    free_pages((ulong)ptr, order);
}

void *_do__get_free_pages(const char *callf, uint line,
                          int order, gfp_t flags, bool zero)
{
    void                *ret;
    size_t              size = 1UL << (order + PAGE_SHIFT);
    struct page         *page;

    ret = (void *)__get_free_pages(flags, order);
    if (!ret) {
        if (flags != GFP_ATOMIC)
            zprintk_caller(KERN_ERR, callf, line,
                           "%s:failed to allocate %lu bytes\n", __func__, size);
        return NULL;
    }
    if (zero)
        memset(ret, 0, size);
    atomic64_add(size, &mem_total);
    page = virt_to_page(ret);
    (void)page;
    debug_caller(DEBUG_MEM, callf, line,
                 "%s:ret/page/pfn 0x%px/0x%px/0x%lx size %lu\n",
                 __func__, ret, page, page_to_pfn(page), size);

    return ret;
}

static inline void _put_io_entry(const char *callf, uint line,
                                 struct io_entry *entry)
{
    int                 count;

    if (entry) {
        count = atomic_dec_return(&entry->count);
        debug_caller(DEBUG_COUNT, callf, line, "%s:entry 0x%px count %d\n",
                     __func__, entry, count);
        if (!count && entry->free)
            entry->free(callf, line, entry);
    }
}

#define put_io_entry(...) \
    _put_io_entry(__func__, __LINE__, __VA_ARGS__)

static inline struct io_entry *_get_io_entry(const char *callf, uint line,
                                             struct io_entry *entry)
{
    int                 count;

    if (!entry)
        return NULL;

    count = atomic_inc_return(&entry->count);
    /* Override unused variable warning. */
    (void)count;
    debug_caller(DEBUG_COUNT, callf, line, "%s:entry 0x%px count %d\n",
                 __func__, entry, count);

    return entry;
}

#define get_io_entry(...) \
    _get_io_entry(__func__, __LINE__, __VA_ARGS__)

static void _free_io_lists(const char *callf, uint line,
                           struct file_data *fdata)
{
    struct io_entry     *next;
    struct io_entry     *entry;
    int i = 0;

    debug_caller(DEBUG_RELEASE, callf, line, "%s:fdata 0x%px\n",
                 __func__, fdata);

    list_for_each_entry_safe(entry, next, &fdata->rd_list, list) {
        debug(DEBUG_RELEASE, "i %d entry 0x%px idx 0x%04x\n",
              i, entry, entry->op.hdr.index);
        list_del_init(&entry->list);
        put_io_entry(entry);
        i++;
    }
}

#define free_io_lists(...) \
    _free_io_lists(__func__, __LINE__, __VA_ARGS__)

static void file_data_free(const char *callf, uint line, void *ptr)
{
    _do_kfree(callf, line, ptr);
}

void queue_zpages_free(union zpages *zpages)
{
    size_t              npages;
    size_t              i;
    struct page         *page;

    npages = zpages->queue.size >> PAGE_SHIFT;
    for (i = 0; i < npages; i++) {
        page = virt_to_page(zpages->queue.pages[i]);
        if (page_count(page) != 1 || page_mapcount(page) != 0)
            zprintk(KERN_WARNING,
                    "i %lu ptr/page/pfn 0x%p/0x%p/0x%lx c %d/%d\n",
                    i, zpages->queue.pages[i],
                    page, page_to_pfn(page), page_count(page),
                    page_mapcount(page));
        do_free_pages(zpages->queue.pages[i], 0);
    }
}

void _zpages_free(const char *callf, uint line, union zpages *zpages)
{
    if (!zpages)
        return;

    debug_caller(DEBUG_MEM, callf, line, "%s:zpages 0x%px\n", __func__, zpages);

    /* Revisit: most of these need zap_vma_ptes(vma, addr, size); */
    switch (zpages->hdr.page_type) {
    case QUEUE_PAGE:

    case LOCAL_SHARED_PAGE:
        queue_zpages_free(zpages);
        break;

    case GLOBAL_SHARED_PAGE:
        break;

    case HSR_PAGE:
    case RMR_PAGE:
        /* Nothing to do */
        break;

    case DMA_PAGE:
        dma_free_coherent(zpages->dma.dev, zpages->dma.size,
                          zpages->dma.cpu_addr, zpages->dma.dma_addr);
        break;
    }

    do_kfree(zpages);
}

/*
 * hsr_zpage_alloc - allocate a zpages structure for a single page of
 * HSR registers. This is used to map the QCM application data for queues.
 * The space for the HSRs is already allocated and mapped by the pci probe
 * function.
 *      base_addr - pointer to the start of the QCM app first 64 bytes
 */
union zpages *_hsr_zpage_alloc(
        const char  *callf,
        uint        line,
        phys_addr_t base_addr)
{
    union zpages       *ret = NULL;

    debug_caller(DEBUG_MEM, callf, line, "%s:page_type HSR_PAGE\n", __func__);

    /* kmalloc space for the return and an array of pages in the zpage struct */
    ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
    if (!ret)
        goto done;

    ret->hsr.page_type = HSR_PAGE;
    ret->hsr.size = PAGE_SIZE; /* always 1 page of HSRs */
    ret->hsr.base_addr = base_addr;

 done:
    debug_caller(DEBUG_MEM, callf, line, "%s:ret 0x%px\n", __func__, ret);

    return ret;
}

/*
 * dma_zpages_alloc - allocate a zpages structure that can be used for the
 * contiguous physical address space for queues. It uses dma_alloc_coherent()
 * to allocate the space.
 *      sl - slice structure for the pci_dev->device.
        size - size in bytes to be allocated for the dma
 */
union zpages *_dma_zpages_alloc(
        const char *callf, uint line,
        struct slice * sl,
        size_t size)
{
    union zpages       *ret = NULL;
    int                 order = 0;
    size_t              npages;

    debug_caller(DEBUG_MEM, callf, line, "%s:page_type DMA_PAGE\n", __func__);

    order = get_order(size);
    npages = 1UL << order;

    /* kmalloc space for the return structure. */
    ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
    if (!ret)
        goto done;

    ret->dma.cpu_addr = dma_alloc_coherent(&sl->pdev->dev, npages * PAGE_SIZE,
                        &ret->dma.dma_addr, GFP_KERNEL);
    debug(DEBUG_MEM,
          "dma_alloc_coherent(size = %u, pa returned = 0x%llu,"
          " va returned = 0x%px\n",
          (unsigned int)(npages * PAGE_SIZE), ret->dma.dma_addr,
          ret->dma.cpu_addr);
    /* RAM memory will always be WB unless you set the memory type. */
    ret->dma.page_type = DMA_PAGE;
    ret->dma.size = size;
    ret->dma.dev = &sl->pdev->dev;
    if (!ret->dma.cpu_addr) {
        do_kfree(ret);
        ret = NULL;
    }

 done:
    debug_caller(DEBUG_MEM, callf, line, "%s:ret 0x%px\n", __func__, ret);

    return ret;
}

/*
 * shared_zpage_alloc - allocate a single page for the shared data. It is
 * allocated at init and only free'ed at exit.
 */

union zpages *shared_zpage_alloc(
        size_t size, int type)
{
    union zpages       *ret = NULL;

    /* Use the queue type alloc to get a zpage */
    ret = queue_zpages_alloc(size, false);
    if (!ret)
        return ret;
    /* Mark this page as special SHARED_PAGE type. */
    ret->queue.page_type = type;

    return ret;
}

/*
 * queue_zpages_alloc - allocate a zpages structure that can be used for
 * simple kmalloced queues for early testing without hardware.
 */
union zpages *_queue_zpages_alloc(
        const char *callf, uint line,
        size_t size,
        bool contig)
{
    union zpages       *ret = NULL;
    int                 order = 0;
    size_t              npages;
    size_t              i;

    debug_caller(DEBUG_MEM, callf, line,
                 "%s:page_type QUEUE_PAGE size %lu contig %d\n",
                 __func__, size, contig);

    if  (contig) {
        order = get_order(size);
        npages = 1UL << order;
        size = npages << PAGE_SHIFT;
    } else {
        size = PAGE_ALIGN(size);
        npages = size >> PAGE_SHIFT;
    }

    /* kmalloc space for the return and an array of pages in the zpage struct */
    ret = do_kmalloc(sizeof(*ret) + npages * sizeof(ret->queue.pages[0]),
                     GFP_KERNEL, true);
    if (!ret || !npages)
        goto done;

    ret->queue.size = size;
    ret->queue.page_type = QUEUE_PAGE;
    if (contig) {
        ret->queue.pages[0] = _do__get_free_pages(callf, line,
                                           order, GFP_KERNEL | __GFP_ZERO,
                                           true);
        i = 1;
        if (ret->queue.pages[0]) {
                split_page(virt_to_page(ret->queue.pages[0]), order);
                for (; i < npages; i++)
                    ret->queue.pages[i] = ret->queue.pages[i - 1] + PAGE_SIZE;
        }
    } else {
        for (i = 0; i < npages; i++) {
                ret->queue.pages[i] = _do__get_free_pages(callf, line,
                                               0, GFP_KERNEL | __GFP_ZERO,
                                               true);
                if (!ret->queue.pages[i])
                        break;
        }
    }
    if (!ret->queue.pages[i-1]) {
        for (i = 0; i < npages; i++)
            do_free_pages(ret->queue.pages[i], 0);
        do_kfree(ret);
        ret = NULL;
    }

 done:
    debug_caller(DEBUG_MEM, callf, line,"%s:ret 0x%px\n", __func__, ret);

    return ret;
}

/*
 * rmr_zpages_alloc - allocate a zpages structure for a cpu-visible RMR_IMPORT.
 * This is used to map the requester ZMMU PTE.
 *      rmr - pointer to the corresponding rmr structure
 */
union zpages *_rmr_zpages_alloc(const char *callf, uint line,
                                struct zhpe_rmr *rmr)
{
    union zpages       *ret = NULL;

    debug_caller(DEBUG_MEM, callf, line, "%s:page_type RMR_PAGE\n", __func__);

    /* kmalloc space for the return struct */
    ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
    if (!ret)
        goto done;

    ret->rmrz.page_type = RMR_PAGE;
    ret->rmrz.size = rmr->pte_info->length;
    ret->rmrz.rmr = rmr;

 done:
    debug_caller(DEBUG_MEM, callf, line, "%s:ret 0x%px\n", __func__, ret);

    return ret;
}

static void _zmap_free(const char *callf, uint line, struct zmap *zmap)
{
    if (!zmap)
        return;

    debug_caller(DEBUG_MEM, callf, line,
                 "%s:zmap 0x%px offset 0x%lx inlist %d\n",
                 __func__, zmap, zmap->offset, !list_empty(&zmap->list));

    if (zmap->zpages)
        zpages_free(zmap->zpages);
    do_kfree(zmap);
}

void _zmap_fdata_free(const char *callf, uint line, struct file_data *fdata,
                      struct zmap *zmap)
{
    /*
     * If the zmap is not in the fdata->zmap_list or the fdata->zmap_lock
     * is held, the zmap must have been removed from the list with
     * list_del_init().
     */
    debug_caller(DEBUG_MEM, callf, line,
                 "%s:zmap 0x%px offset 0x%lx inlist %d\n",
                 __func__, zmap, zmap->offset, !list_empty(&zmap->list));

    if (!list_empty(&zmap->list)) {
        spin_lock(&fdata->zmap_lock);
        list_del_init(&zmap->list);
        spin_unlock(&fdata->zmap_lock);
    }
    zmap_free(zmap);
}

struct zmap *_zmap_alloc(
        const char *callf,
        uint line,
        struct file_data *fdata,
        union zpages *zpages)
{
    struct zmap         *ret;
    struct zmap         *cur;
    ulong               coff;
    size_t              size;

    debug_caller(DEBUG_MEM, callf, line, "%s:zpages 0x%px\n", __func__, zpages);

    ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
    if (!ret) {
        ret = ERR_PTR(-ENOMEM);
        goto done;
    }

    INIT_LIST_HEAD(&ret->list);
    ret->zpages = zpages;
    /* Set bad owner to keep entry from being used until ready. */
    ret->owner = ZMAP_BAD_OWNER;
    /*
     * Look for a hole in betwen entries; allow space for unmapped pages
     * between entries.
     */
    size = zpages->hdr.size + PAGE_SIZE;
    coff = 0;
    spin_lock(&fdata->zmap_lock);
    list_for_each_entry(cur, &fdata->zmap_list, list) {
        if (cur->offset - coff >= size)
            break;
        coff = cur->offset + cur->zpages->hdr.size;
    }
    /*
     * cur will either point to a real entry before which we want to insert
     * ret or &cur->list == head and we want to add ourselves at the tail.
     *
     * Can we wrap around in real life? Probably not.
     */
    if (coff < coff + size) {
        ret->offset = coff;
        if (coff)
            ret->offset += PAGE_SIZE;
        list_add_tail(&ret->list, &cur->list);
    }
    spin_unlock(&fdata->zmap_lock);
    if (list_empty(&ret->list)) {
        zmap_free(ret);
        zprintk(KERN_ERR, "Out of file space.\n");
        ret = ERR_PTR(-ENOSPC);
        goto done;
    }

 done:
    return ret;
}

static bool _free_zmap_list(const char *callf, uint line,
                            struct file_data *fdata)
{
    bool                ret = true;
    struct zmap         *zmap;
    struct zmap         *next;

    /* Only called from zhpe_release. */
    debug_caller(DEBUG_RELEASE, callf, line, "%s:fdata 0x%px\n",
                 __func__, fdata);

    spin_lock(&fdata->zmap_lock);
    list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
        list_del_init(&zmap->list);
        /* global_shared_zmap zpages are not freed until driver exit. */
        if (zmap == fdata->global_shared_zmap)
            do_kfree(zmap);
        else
            zmap_free(zmap);
    }
    spin_unlock(&fdata->zmap_lock);

    return ret;
}

static inline void queue_io_entry_locked(struct file_data *fdata,
                                         struct list_head *head,
                                         struct io_entry *entry)
{
    bool                wake = list_empty(head);

    list_add_tail(&entry->list, head);
    spin_unlock(&fdata->io_lock);
    wake_up(&fdata->io_wqh);
    if (wake)
        wake_up_all(&poll_wqh);
}

static inline int queue_io_entry(struct file_data *fdata,
                                 struct list_head *head,
                                 struct io_entry *entry)
{
    int                 ret = 0;

    spin_lock(&fdata->io_lock);
    if (fdata->state & STATE_CLOSED) {
        ret = -EIO;
        spin_unlock(&fdata->io_lock);
    } else
        queue_io_entry_locked(fdata, head, entry);

    return ret;
}

static void io_free(const char *callf, uint line, void *ptr)
{
    struct io_entry     *entry = ptr;

    _put_file_data(callf, line, entry->fdata);
    _do_kfree(callf, line, entry);
}

static inline struct io_entry *_io_alloc(
    const char *callf, uint line, size_t size, bool nonblock,
    struct file_data *fdata,
    void (*free)(const char *callf, uint line, void *ptr))
{
    struct io_entry     *ret = NULL;

    if (size < sizeof(ret->op))
        size = sizeof(ret->op);
    size += sizeof(*ret);
    ret = do_kmalloc(size, (nonblock ? GFP_ATOMIC : GFP_KERNEL), false);
    if (!ret)
        goto done;

    ret->free = free;
    atomic_set(&ret->count, 1);
    ret->nonblock = nonblock;
    ret->fdata = get_file_data(fdata);
    INIT_LIST_HEAD(&ret->list);

 done:

    return ret;
}

#define io_alloc(...) \
    _io_alloc(__func__, __LINE__, __VA_ARGS__)


int queue_io_rsp(struct io_entry *entry, size_t data_len, int status)
{
    int                 ret = 0;
    struct file_data    *fdata = entry->fdata;
    struct zhpe_common_hdr *op_hdr = &entry->op.hdr;

    op_hdr->version = ZHPE_OP_VERSION;
    op_hdr->opcode = entry->hdr.opcode | ZHPE_OP_RESPONSE;
    op_hdr->index = entry->hdr.index;
    op_hdr->status = status;
    if (!data_len)
        data_len = sizeof(*op_hdr);
    entry->data_len = data_len;

    if (fdata)
        ret = queue_io_entry(fdata, &fdata->rd_list, entry);

    return ret;
}

#ifndef PCI_EXT_CAP_ID_DVSEC
#define PCI_EXT_CAP_ID_DVSEC 0x23  /* Revisit: should be in pci.h */
#endif

#define ZHPE_DVSEC_WP_ADDR_LO_OFF (0x1C)
#define ZHPE_DVSEC_WP_ADDR_HI_OFF (0x20)
#define ZHPE_DVSEC_WP_CTL_24_OFF  (0x24)
#define ZHPE_DVSEC_WP_CTL_24_VAL  (0)           /* Physical addr zero. */
#define ZHPE_DVSEC_WP_CTL_28_OFF  (0x28)
#define ZHPE_DVSEC_SLICE_OFF      (0x2C)
#define ZHPE_DVSEC_PSLICE_SHIFT   (0xD)
#define ZHPE_DVSEC_SLICE_MASK     (0x3)
#define ZHPE_DVSEC_VSLICE_SHIFT   (0xF)
#define ZHPE_DVSEC_DBG_OBS_MASK   (0x10)
#define ZHPE_DVSEC_MBOX_CTRL_OFF  (0x30)
#define ZHPE_DVSEC_MBOX_CTRL_TRIG (0x1)
#define ZHPE_DVSEC_MBOX_CTRL_WR   (0x2)
#define ZHPE_DVSEC_MBOX_CTRL_ERR  (0x4)
#define ZHPE_DVSEC_MBOX_CTRL_BE   (0xFF00)
#define ZHPE_DVSEC_MBOX_ADDR_OFF  (0x34)
#define ZHPE_DVSEC_MBOX_DATAL_OFF (0x38)
#define ZHPE_DVSEC_MBOX_DATAH_OFF (0x3C)
#define ZHPE_DVSEC_SLINK_OFF      (0x40)
#define ZHPE_DVSEC_SLINK_BASE_MASK (0x000FFFFU)
#define ZHPE_DVSEC_SLINK_BASE_LSHIFT (30)
#define ZHPE_DVSEC_SLINK_SIZE_MASK (0xFFF0000U)
#define ZHPE_DVSEC_SLINK_SIZE_LSHIFT (18)

static const char *platform_name[] = {
    "unknown", "carbon", "pfslice", "wildcat"
};

static int autodetect_platform(void)
{
    struct pci_dev      *pdev = NULL;
    uint                slices_seen = 0;
    u32                 slink_val = 0;
    int                 pos = 0;

    while ((pdev = pci_get_device(PCI_VENDOR_ID_HP_3PAR, 0x0290, pdev))) {
        slices_seen++;
        pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DVSEC);
        if (!pos) { /* carbon has no DVSEC */
            zhpe_platform = ZHPE_CARBON;
        } else {
            pci_read_config_dword(pdev, pos + ZHPE_DVSEC_SLINK_OFF,
                                  &slink_val);
            if (slink_val & ZHPE_DVSEC_SLINK_SIZE_MASK) /* wildcat has size>0 */
                zhpe_platform = ZHPE_WILDCAT;
            else if (zhpe_platform == ZHPE_UNKNOWN)
                zhpe_platform = ZHPE_PFSLICE;
        }
    }
    platform = (char *)platform_name[zhpe_platform];
    zprintk(KERN_INFO, "platform %s, %u slices seen\n", platform, slices_seen);

    if (zhpe_platform == ZHPE_PFSLICE) {
        zhpe_bridge.expected_slices = 1;
        zhpe_req_zmmu_entries = PFSLICE_REQ_ZMMU_ENTRIES;
        zhpe_rsp_zmmu_entries = PFSLICE_RSP_ZMMU_ENTRIES;
        zhpe_xdm_queues_per_slice = PFSLICE_XDM_QUEUES_PER_SLICE;
        zhpe_rdm_queues_per_slice = PFSLICE_RDM_QUEUES_PER_SLICE;
        zhpe_reqz_min_cpuvisible_addr = PFSLICE_REQZ_MIN_CPUVISIBLE_ADDR;
        zhpe_reqz_max_cpuvisible_addr = PFSLICE_REQZ_MAX_CPUVISIBLE_ADDR;
        if (strcmp(req_page_grid, "default") == 0)
            req_page_grid =
                "1G*800,1G:16,128T:128";
        if (strcmp(rsp_page_grid, "default") == 0)
            rsp_page_grid = "1G:896,128T:128";
        zhpe_no_avx = 0;
    } else if (zhpe_platform == ZHPE_WILDCAT) {
        zhpe_bridge.expected_slices = SLICES;
        if (slices_seen < zhpe_bridge.expected_slices)
            zhpe_bridge.expected_slices = slices_seen;
        zhpe_req_zmmu_entries = WILDCAT_REQ_ZMMU_ENTRIES;
        zhpe_rsp_zmmu_entries = WILDCAT_RSP_ZMMU_ENTRIES;
        zhpe_xdm_queues_per_slice = WILDCAT_XDM_QUEUES_PER_SLICE;
        zhpe_rdm_queues_per_slice = WILDCAT_RDM_QUEUES_PER_SLICE;
        zhpe_reqz_min_cpuvisible_addr = WILDCAT_REQZ_MIN_CPUVISIBLE_ADDR;
        zhpe_reqz_max_cpuvisible_addr = WILDCAT_REQZ_MAX_CPUVISIBLE_ADDR;
        if (strcmp(req_page_grid, "default") == 0)
            req_page_grid = "128M*104K,1G:8K,128T:16K";
        if (strcmp(rsp_page_grid, "default") == 0)
            rsp_page_grid = "128T:1K,1G:63K";
        zhpe_no_avx = 0;
    } else if (zhpe_platform == ZHPE_CARBON) {
        zhpe_bridge.expected_slices = SLICES;
        zhpe_req_zmmu_entries = CARBON_REQ_ZMMU_ENTRIES;
        zhpe_rsp_zmmu_entries = CARBON_RSP_ZMMU_ENTRIES;
        zhpe_xdm_queues_per_slice = CARBON_XDM_QUEUES_PER_SLICE;
        zhpe_rdm_queues_per_slice = CARBON_RDM_QUEUES_PER_SLICE;
        zhpe_reqz_min_cpuvisible_addr = CARBON_REQZ_MIN_CPUVISIBLE_ADDR;
        zhpe_reqz_max_cpuvisible_addr = CARBON_REQZ_MAX_CPUVISIBLE_ADDR;
        zhpe_reqz_phy_cpuvisible_off = CARBON_REQZ_PHY_CPUVISIBLE_OFF;
        if (strcmp(req_page_grid, "default") == 0)
            req_page_grid = "1G*104K,1G:8K,128T:16K";
        if (strcmp(rsp_page_grid, "default") == 0)
            rsp_page_grid = "128T:1K,1G:63K";
        zhpe_no_avx = 1;
    } else {
        return -EINVAL;
    }

    return 0;
}

static int parse_page_grid_one(char *str, uint64_t max_page_count,
                               bool allow_cpu_visible,
                               struct sw_page_grid *pg)
{
    char     *orig = str;
    uint64_t page_size, page_count;

    page_size = memparse(str, &str);
    if (str == orig || !(*str == ':' || *str == '*'))
        goto err;
    if (!is_power_of_2(page_size))
        goto err;
    page_size = ilog2(page_size);
    if (page_size < PAGE_GRID_MIN_PAGESIZE ||
        page_size > PAGE_GRID_MAX_PAGESIZE)
        goto err;
    pg->page_grid.page_size = page_size;

    if (*str == '*' && !allow_cpu_visible)
        goto err;
    pg->cpu_visible = (*str++ == '*') ? true : false;

    orig = str;
    page_count = memparse(str, &str);
    if (str == orig || *str != '\0')
        goto err;
    if (page_count > max_page_count)
        goto err;
    pg->page_grid.page_count = page_count;

    return 0;

 err:
    return -EINVAL;
}

static uint parse_page_grid_opt(char *str, uint64_t max_page_count,
                                bool allow_cpu_visible,
                                struct sw_page_grid pg[])
{
    uint cnt = 0;
    int ret;
    char *str_copy, *s, *k;
    bool bit;
    DECLARE_BITMAP(non_visible_ps_bitmap, PAGE_GRID_MAX_PAGESIZE+1) = { 0 };
    DECLARE_BITMAP(cpu_visible_ps_bitmap, PAGE_GRID_MAX_PAGESIZE+1) = { 0 };

    /* make a writable copy of str */
    str_copy = do_kmalloc(strlen(str) + 1, GFP_KERNEL, false);
    strcpy(str_copy, str);

    for (s = str_copy; s; s = k) {
        k = strchr(s, ',');
        debug(DEBUG_ZMMU, "str=%px,s=%px,k=%px\n", str_copy, s, k);

        if (k)
            *k++ = 0;
        debug(DEBUG_ZMMU,
              "calling parse_page_grid_one"
              "(s=%s,max_page_count=%llu, &pg[cnt]=%px)\n",
              s, max_page_count, &pg[cnt]);
        ret = parse_page_grid_one(s, max_page_count, allow_cpu_visible,
                                  &pg[cnt]);
        debug(DEBUG_ZMMU,
              "ret=%d, page_size=%u, page_count=%u, cpu_visible=%d\n",
              ret, pg[cnt].page_grid.page_size, pg[cnt].page_grid.page_count,
              pg[cnt].cpu_visible);
        if (pg[cnt].cpu_visible) {
            bit = test_and_set_bit(pg[cnt].page_grid.page_size,
                                   cpu_visible_ps_bitmap);
        } else {
            bit = test_and_set_bit(pg[cnt].page_grid.page_size,
                                   non_visible_ps_bitmap);
        }
        if (!bit && ret == 0)
            cnt++;
        else
            zprintk(KERN_WARNING, "invalid page_grid parameter - %s\n", s);
        if (cnt == PAGE_GRID_ENTRIES)
            break;
    }

    do_kfree(str_copy);
    return cnt;
}

static int zhpe_user_req_INIT(struct io_entry *entry)
{
    union zhpe_rsp      *rsp = &entry->op.rsp;
    struct file_data    *fdata = entry->fdata;
    struct bridge       *br = fdata->bridge;
    int                 status = 0;
    struct uuid_tracker *uu;
    uint32_t            ro_rkey;
    uint32_t            rw_rkey;
    char                str[UUID_STRING_LEN+1];

    rsp->init.magic = ZHPE_MAGIC;

    rsp->init.attr.max_tx_queues = zhpe_xdm_queues_per_slice * br->num_slices;
    rsp->init.attr.max_rx_queues = zhpe_rdm_queues_per_slice * br->num_slices;
    rsp->init.attr.max_tx_qlen = ZHPE_MAX_XDM_QLEN;
    rsp->init.attr.max_rx_qlen = ZHPE_MAX_RDM_QLEN;
    rsp->init.attr.max_dma_len = ZHPE_MAX_DMA_LEN;
    rsp->init.attr.num_slices = br->num_slices;

    rsp->init.global_shared_offset = fdata->global_shared_zmap->offset;
    rsp->init.global_shared_size = fdata->global_shared_zmap->zpages->hdr.size;
    rsp->init.local_shared_offset = fdata->local_shared_zmap->offset;
    rsp->init.local_shared_size = fdata->local_shared_zmap->zpages->hdr.size;

    zhpe_generate_uuid(br, &rsp->init.uuid);
    uu = zhpe_uuid_tracker_alloc_and_insert(&rsp->init.uuid, UUID_TYPE_LOCAL,
                                            0, fdata, GFP_KERNEL, &status);
    if (!uu)
        goto out;

    status = zhpe_rkey_alloc(&ro_rkey, &rw_rkey);
    if (status < 0) {
        zhpe_uuid_remove(uu);
        goto out;
    }

    spin_lock(&fdata->io_lock);
    if (fdata->state & STATE_INIT) {  /* another INIT */
        status = -EBADRQC;
        spin_unlock(&fdata->io_lock);
        zhpe_rkey_free(ro_rkey, rw_rkey);
        zhpe_uuid_remove(uu);
        goto out;
    }
    fdata->state |= STATE_INIT;
    fdata->ro_rkey = ro_rkey;
    fdata->rw_rkey = rw_rkey;
    spin_unlock(&fdata->io_lock);

    spin_lock(&fdata->uuid_lock);
    fdata->local_uuid = uu;
    spin_unlock(&fdata->uuid_lock);

 out:
    debug(DEBUG_IO, "ret = %d uuid = %s, ro_rkey=0x%08x, rw_rkey=0x%08x\n",
          status, zhpe_uuid_str(&rsp->init.uuid, str, sizeof(str)),
          ro_rkey, rw_rkey);
    return queue_io_rsp(entry, sizeof(rsp->init), status);
}

static int zhpe_user_req_FEATURE(struct io_entry *entry)
{
    union zhpe_req      *req = &entry->op.req;
    union zhpe_rsp      *rsp = &entry->op.rsp;
    struct file_data    *fdata = entry->fdata;
    int                 status = 0;
    uint64_t            req_features, rsp_features = 0;

    req_features = req->feature.features;
    CHECK_INIT_STATE(entry, status, out);
    if (req_features & ~ZHPE_FEATURE_VALID_MASK) {
        status = -EINVAL;
        goto out;
    }
    if (req_features & ZHPE_FEATURE_MR_OVERLAP_CHECKING) {
        spin_lock(&fdata->io_lock);
        fdata->state |= STATE_MR_OVERLAP_CHECKING;
        spin_unlock(&fdata->io_lock);
        rsp_features |= ZHPE_FEATURE_MR_OVERLAP_CHECKING;
    }
    if (req_features & ZHPE_FEATURE_DUMP_Q0) {
        status = zhpe_dump_q0(fdata);
        rsp_features |= ZHPE_FEATURE_DUMP_Q0;
    }

 out:
    rsp->feature.features = rsp_features;
    debug(DEBUG_IO, "ret=%d, req_features=0x%016llx, rsp_features=0x%016llx\n",
          status, req_features, rsp_features);
    return queue_io_rsp(entry, sizeof(rsp->feature), status);
}

/* This function called by IOMMU driver on PPR failure */
static int iommu_invalid_ppr_cb(struct pci_dev *pdev, int pasid,
                                unsigned long address, u16 flags)

{
    zprintk(KERN_WARNING,
            "IOMMU PRR failure device = %s, pasid = %d address = 0x%lx"
            " flags = %ux\n", pci_name(pdev), pasid, address, flags);

    return AMD_IOMMU_INV_PRI_RSP_INVALID;
}

static int zhpe_bind_iommu(struct file_data *fdata)
{
    int s, ret = 0;
    struct pci_dev *pdev;

    /*
     * amd_iommu_bind_pasid() has a bug in it, to this day,
     * in that it doesn't check for an error return from
     * mmu_notifier_register() which occurs if there is a pending
     * signal on the process and then bad things can happen when
     * amd_iommu_unbind_pasid() is called and it calls
     * mmu_notifier_unregister() and can operation on a freed
     * mm_struct.
     *
     * Without fixing the kernel, there is no solid way to
     * fix this I'm aware of. So, I'm going to paper over it.
     */
    if (!no_iommu) {
        for (s=0; s<SLICES; s++) {
            if (!SLICE_VALID(&(fdata->bridge->slice[s])))
                continue;
            pdev = fdata->bridge->slice[s].pdev;
            if (signal_pending(current)) {
                ret = -EINTR;
                break;
            }
            ret = amd_iommu_bind_pasid(pdev, fdata->pasid, current);
            /* Do a mmgrab() to prevent failure case; memory leak. */
            if (signal_pending(current))
                mmgrab(current->mm);
            if (ret < 0) {
                debug(DEBUG_IO,
                      "amd_iommu_bind_pasid failed for slice %d with"
                      " return %d\n", s, ret);
                break;
            }
            amd_iommu_set_invalid_ppr_cb(pdev, iommu_invalid_ppr_cb);
        }
        if (ret < 0) {
            while (s > 0) {
                s--;
                if (!SLICE_VALID(&(fdata->bridge->slice[s])))
                    continue;
                pdev = fdata->bridge->slice[s].pdev;
                amd_iommu_unbind_pasid(pdev, fdata->pasid);
                amd_iommu_set_invalid_ppr_cb(pdev, NULL);
            }
        }
    }
    return (ret);
}

static void zhpe_unbind_iommu(struct file_data *fdata)
{
    int s;
    struct pci_dev *pdev;

    if (!no_iommu) {
        for (s=0; s<SLICES; s++) {
            if (!SLICE_VALID(&(fdata->bridge->slice[s])))
                continue;
            pdev = fdata->bridge->slice[s].pdev;
            amd_iommu_unbind_pasid(pdev, fdata->pasid);
            amd_iommu_set_invalid_ppr_cb(pdev, NULL);
        }
    }
    return;
}

static int zhpe_release(struct inode *inode, struct file *file)
{
    struct file_data    *fdata = file->private_data;

    spin_lock(&fdata->io_lock);
    fdata->state &= ~STATE_INIT;
    fdata->state |= STATE_CLOSED;
    spin_unlock(&fdata->io_lock);
    zhpe_release_owned_xdm_queues(fdata);
    zhpe_release_owned_rdm_queues(fdata);
    free_zmap_list(fdata);
    free_io_lists(fdata);
    zhpe_rmr_free_all(fdata);
    zhpe_notify_remote_uuids(fdata);
    zhpe_mmun_exit(fdata);
    zhpe_free_remote_uuids(fdata);
    spin_lock(&fdata->uuid_lock);
    (void)zhpe_free_local_uuid(fdata, true); /* also frees associated R-keys */
    spin_unlock(&fdata->uuid_lock);
    zhpe_unbind_iommu(fdata);
    zhpe_pasid_free(fdata->pasid);
    spin_lock(&fdata->bridge->fdata_lock);
    list_del(&fdata->fdata_list);
    spin_unlock(&fdata->bridge->fdata_lock);
    put_file_data(fdata);

    debug(DEBUG_IO, "ret = %d\n", 0);

    return 0;
}

static ssize_t zhpe_read(struct file *file, char __user *buf, size_t len,
                         loff_t *ppos)
{
    ssize_t             ret = 0;
    struct file_data    *fdata = file->private_data;
    struct io_entry     *entry;

    if (!len)
        goto done;

    /*
     * Weird semantics: read must be big enough to read entire packet
     * at once; if not, return -EINVAL;
     */
    for (;;) {
        entry = NULL;
        spin_lock(&fdata->io_lock);
        if (!list_empty(&fdata->rd_list)) {
            entry = list_first_entry(&fdata->rd_list, struct io_entry, list);
            if (len >= entry->data_len) {
                list_del_init(&entry->list);
                len = entry->data_len;
            } else {
                debug(DEBUG_IO, "zhpe_read: len %ld entry->data_len %ld\n",
                      len, entry->data_len);
                ret = -EINVAL;
            }
        }
        spin_unlock(&fdata->io_lock);
        if (ret < 0)
            goto done;
        if (entry)
            break;
        if (file->f_flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto done;
        }
        ret = wait_event_interruptible(fdata->io_wqh,
                                       !list_empty(&fdata->rd_list));
        if (ret < 0)
            goto done;
    }
    ret = copy_to_user(buf, entry->data, len);
    put_io_entry(entry);

 done:
    debug_cond(DEBUG_IO, (ret /* != -EAGAIN*/),
               "ret = %ld len = %ld\n", ret, len);

    return (ret < 0 ? ret : len);
}

static ssize_t zhpe_write(struct file *file, const char __user *buf,
                          size_t len, loff_t *ppos)
{
    ssize_t             ret = 0;
    struct file_data    *fdata = file->private_data;
    bool                nonblock = !!(file->f_flags & O_NONBLOCK);
    struct io_entry     *entry = NULL;
    struct zhpe_common_hdr *op_hdr;
    size_t              op_len;

    if (!len)
        goto done;

    /*
     * Weird semantics: requires write be a packet containing a single
     * request.
     */
    if (len < sizeof(*op_hdr)) {
        ret = -EINVAL;
        zprintk(KERN_ERR, "Unexpected short write %lu\n", len);
        goto done;
    }

    entry = io_alloc(0, nonblock, fdata, io_free);
    if (!entry) {
        ret = (nonblock ? -EAGAIN : -ENOMEM);
        goto done;
    }
    op_hdr = &entry->op.hdr;

    op_len = sizeof(union zhpe_req);
    if (op_len > len)
        op_len = len;
    ret = copy_from_user(op_hdr, buf, op_len);
    if (ret < 0)
        goto done;
    entry->hdr = *op_hdr;

    ret = -EINVAL;
    if (!expected_saw("version", ZHPE_OP_VERSION, op_hdr->version))
        goto done;

#define USER_REQ_HANDLER(_op)                           \
    case ZHPE_OP_ ## _op:                               \
        debug(DEBUG_IO, "ZHPE_OP_" # _op);              \
        op_len = sizeof(struct zhpe_req_ ## _op);       \
        if (len != op_len)                              \
            goto done;                                  \
        ret = zhpe_user_req_ ## _op(entry);             \
        break;

    switch (op_hdr->opcode) {

    USER_REQ_HANDLER(INIT);
    USER_REQ_HANDLER(MR_REG);
    USER_REQ_HANDLER(MR_REG_EXT);
    USER_REQ_HANDLER(MR_FREE);
    USER_REQ_HANDLER(RMR_IMPORT);
    USER_REQ_HANDLER(RMR_FREE);
    USER_REQ_HANDLER(UUID_IMPORT);
    USER_REQ_HANDLER(UUID_FREE);
    USER_REQ_HANDLER(XQALLOC);
    USER_REQ_HANDLER(XQFREE);
    USER_REQ_HANDLER(RQALLOC);
    USER_REQ_HANDLER(RQFREE);
    USER_REQ_HANDLER(RQALLOC_SPECIFIC);
    USER_REQ_HANDLER(FEATURE);

    default:
        zprintk(KERN_ERR, "Unexpected opcode 0x%02x\n", op_hdr->opcode);
        ret = -EIO;
        break;
    }

#undef USER_REQ_HANDLER

    /*
     * If handler accepts op, it is no longer our responsibility to free
     * the entry.
     */
    if (ret >= 0)
        entry = NULL;

 done:
    put_io_entry(entry);

    debug_cond(DEBUG_IO, (ret != -EAGAIN), "ret = %ld len = %ld\n", ret, len);

    return (ret < 0 ? ret : len);
}

static uint zhpe_poll(struct file *file, struct poll_table_struct *wait)
{
    uint                ret = 0;
    struct file_data    *fdata = file->private_data;

    poll_wait(file, &poll_wqh, wait);
    ret |= (list_empty(&fdata->rd_list) ? 0 : POLLIN | POLLRDNORM);

    return ret;
}

/* Revisit: if vma_set_page_prot was exported by mm/mmap.c, we'd just use
 * it, but it's not, so we do it ourselves here.
 */

#define vma_set_page_prot zhpe_vma_set_page_prot
#define vm_pgprot_modify zhpe_pgprot_modify
#define vma_wants_writenotify zhpe_vma_wants_writenotify

/* Revisit: copy actual vma_wants_writenotify? */
static inline int zhpe_vma_wants_writenotify(struct vm_area_struct *vma,
                                             pgprot_t vm_page_prot)
{
    return 0;
}

/* identical to vm_pgprot_modify, except for function name */
static pgprot_t zhpe_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
    return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/* identical to vma_set_page_prot, except for function name */
void zhpe_vma_set_page_prot(struct vm_area_struct *vma)
{
    unsigned long vm_flags = vma->vm_flags;
    pgprot_t vm_page_prot;

    vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);
    if (vma_wants_writenotify(vma, vm_page_prot)) {
        vm_flags &= ~VM_SHARED;
        vm_page_prot = vm_pgprot_modify(vm_page_prot, vm_flags);
    }
    /* remove_protection_ptes reads vma->vm_page_prot without mmap_sem */
    WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}

static int zhpe_vm_access(struct vm_area_struct *vma, unsigned long addr,
                          void *buf, int len, int write)
{
    int                 ret = -EFAULT;
    struct file_data    *fdata = vma->vm_file->private_data;
    struct zmap         *zmap = vma->vm_private_data;
    union zpages        *zpages = zmap->zpages;
    uintptr_t           off;
    uint64_t            *buf64;
    void                *barp;
    struct slice        *sl;
    size_t              i;

    if (write)
        goto done;

    off = addr - vma->vm_start;
    if (addr + len > vma->vm_end)
        len = vma->vm_end - addr;

    /* Have to support each type individually. */
    switch (zpages->hdr.page_type) {

    case DMA_PAGE:
        memcpy(buf, (char *)zpages->dma.cpu_addr + off, len);
        ret = len;
        break;

    case HSR_PAGE:
        /* Both vaddr and len on a 64-bit boundary. */
        if ((addr | len) & (sizeof(uint64_t) - 1))
            goto done;
        for (i = 0; i < SLICES; i++) {
            sl = &fdata->bridge->slice[i];
            if (!SLICE_VALID(sl))
                continue;
            if ((uintptr_t)sl->phys_base <= zpages->hsr.base_addr &&
                zpages->hsr.base_addr <
                ((uintptr_t)sl->phys_base + sizeof(*sl->bar)))
                break;
        }
        if (i == SLICES)
            goto done;
        addr -= vma->vm_start;
        addr += (zpages->hsr.base_addr - sl->phys_base);
        barp = (void *)sl->bar + addr;
        buf64 = buf;
        for (i = 0; i < len; i +=  sizeof(uint64_t), barp += sizeof(uint64_t))
            buf64[i] = ioread64(barp);
        ret = len;
        break;

    default:
        break;
    }

 done:
    return ret;
}

static const struct vm_operations_struct zhpe_vm_ops = {
    .access             = zhpe_vm_access,
};

static int zhpe_dma_mmap(struct device *dev, struct vm_area_struct *vma,
                         void *cpu_addr, dma_addr_t dma_addr, size_t size)
{
    int ret = -ENXIO;
    unsigned long user_count = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
    unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
    unsigned long pfn = page_to_pfn(virt_to_page(cpu_addr));

    if (user_count <= count) {
        ret = remap_pfn_range(vma, vma->vm_start, pfn,
                              user_count << PAGE_SHIFT, vma->vm_page_prot);
    }

    return ret;
}

static int zhpe_mmap(struct file *file, struct vm_area_struct *vma)
{
    int                 ret = -ENOENT;
    struct file_data    *fdata = file->private_data;
    struct zmap         *zmap;
    union zpages        *zpages;
    struct zhpe_rmr     *rmr;
    ulong               vaddr, offset, length, i, mmap_pfn;
    uint32_t            cache_flags;

    vma->vm_flags |= VM_MIXEDMAP | VM_DONTCOPY;
    vma->vm_private_data = NULL;

    offset = vma->vm_pgoff << PAGE_SHIFT;
    length = vma->vm_end - vma->vm_start;
    debug(DEBUG_MMAP, "vm_start=0x%lx, vm_end=0x%lx, offset=0x%lx\n",
          vma->vm_start, vma->vm_end, offset);
    spin_lock(&fdata->zmap_lock);
    list_for_each_entry(zmap, &fdata->zmap_list, list) {
        debug(DEBUG_MMAP, "zmap %px offset=0x%lx length=0x%lx\n",
              zmap, zmap->offset, zmap->zpages->hdr.size);
        if (offset == zmap->offset &&
            length == zmap->zpages->hdr.size) {
            if (!zmap->owner || zmap->owner == fdata)
                ret = 0;
            break;
        }
    }
    spin_unlock(&fdata->zmap_lock);
    if (ret < 0) {
        debug(DEBUG_MMAP, "ret < 0 - zmap not found in zmap_list\n");
        goto done;
    }
    ret = -EINVAL;
    if (!(vma->vm_flags & VM_SHARED)) {
        zprintk(KERN_ERR, "vm_flags !VM_SHARED\n");
        goto done;
    }
    if (vma->vm_flags & VM_EXEC) {
        zprintk(KERN_ERR, "vm_flags VM_EXEC\n");
        goto done;
    }
    vma->vm_flags &= ~VM_MAYEXEC;
    if (zmap == fdata->global_shared_zmap) {
        if (vma->vm_flags & VM_WRITE) {
            debug(DEBUG_MMAP, "vm_flags VM_WRITE\n");
            vma->vm_flags &= ~(VM_WRITE|VM_MAYWRITE);
        }
    }

    zpages = zmap->zpages;

    switch (zpages->hdr.page_type) {
    case LOCAL_SHARED_PAGE:
    case GLOBAL_SHARED_PAGE:
    case QUEUE_PAGE:
        for (vaddr = vma->vm_start, i = 0; vaddr < vma->vm_end;
             vaddr += PAGE_SIZE, i++) {
            ret = vm_insert_page(vma, vaddr,
                                 virt_to_page(zpages->queue.pages[i]));
            if (ret < 0) {
                zprintk(KERN_ERR, "vm_insert_page() returned %d\n", ret);
                goto done;
            }
        }
        ret = 0;
        break;
    case DMA_PAGE:
        ret = zhpe_dma_mmap(zpages->dma.dev, vma, zpages->dma.cpu_addr,
                            zpages->dma.dma_addr, length);
        if (ret < 0) {
            zprintk(KERN_ERR, "zhpe_dma_mmap() returned %d\n", ret);
            goto done; /* BUG to break */
        }
        break;
    case HSR_PAGE:
        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
        ret = io_remap_pfn_range(vma, vma->vm_start,
                                 zpages->hsr.base_addr >> PAGE_SHIFT,
                                 length,
                                 vma->vm_page_prot);
        if (ret) {
            zprintk(KERN_ERR, "HSR io_remap_pfn_range returned %d\n", ret);
            goto done;
        }
        break;
    case RMR_PAGE:
        if (!allow_mmap && zhpe_platform == ZHPE_WILDCAT &&
            fdata->bridge->slice_mask != WILDCAT_SLINK_SLICE_MASK) {
            zprintk(KERN_ERR, "RMR mmap requires slice_mask 0x%x, not 0x%x",
                    WILDCAT_SLINK_SLICE_MASK, fdata->bridge->slice_mask);
            ret = -ENODEV;
            goto done;
        }
        rmr = zpages->rmrz.rmr;
        cache_flags = rmr->pte_info->access & ZHPE_MR_REQ_CPU_CACHE;
        switch (cache_flags) {
            /* ZHPE_MR_REQ_CPU_WB is the default, so nothing to do */
        case ZHPE_MR_REQ_CPU_WC:
            vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
            break;
        case ZHPE_MR_REQ_CPU_WT:
            vma->vm_page_prot = pgprot_writethrough(vma->vm_page_prot);
            break;
        case ZHPE_MR_REQ_CPU_UC:
            vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
            break;
        }
        if (!rmr->writable) {
            vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
            vma_set_page_prot(vma);
        }
        mmap_pfn = (rmr->req_addr + zhpe_reqz_phy_cpuvisible_off) >> PAGE_SHIFT;
        debug(DEBUG_MMAP, "RMR mmap_pfn=0x%lx, vm_page_prot=0x%lx\n",
              mmap_pfn, pgprot_val(vma->vm_page_prot));
        ret = io_remap_pfn_range(vma, vma->vm_start, mmap_pfn, length,
                                 vma->vm_page_prot);
        if (ret) {
            zprintk(KERN_ERR, "RMR io_remap_pfn_range returned %d\n", ret);
            goto done;
        }
        break;
    }

 done:
    if (ret >= 0) {
        vma->vm_private_data = zmap;
        vma->vm_ops = &zhpe_vm_ops;
    } else
        zprintk(KERN_ERR, "ret = %d:start 0x%lx end 0x%lx off 0x%lx\n",
                ret, vma->vm_start, vma->vm_end, vma->vm_pgoff);

    return ret;
}

static int zhpe_open(struct inode *inode, struct file *file);

static const struct file_operations zhpe_fops = {
    .owner              =       THIS_MODULE,
    .open               =       zhpe_open,
    .release            =       zhpe_release,
    .read               =       zhpe_read,
    .write              =       zhpe_write,
    .poll               =       zhpe_poll,
    .mmap               =       zhpe_mmap,
    /* Revisit: implement get_unmapped_area to enforce pg_ps alignment */
    .llseek             =       no_llseek,
};

static int alloc_map_shared_data(struct file_data *fdata)
{
    int                 ret = 0;
    int                 i;
    struct zhpe_local_shared_data *local_shared_data;

    fdata->local_shared_zpage =
        shared_zpage_alloc(sizeof(*local_shared_data), LOCAL_SHARED_PAGE);
    if (!fdata->local_shared_zpage) {
        debug(DEBUG_IO, "queue_zpages_alloc failed.\n");
        ret = -ENOMEM;
        goto done;
    }
    /* Add shared data to the zmap_list */
    fdata->local_shared_zmap = zmap_alloc(fdata, fdata->local_shared_zpage);
    if (IS_ERR(fdata->local_shared_zmap)) {
        debug(DEBUG_IO, "zmap_alloc failed\n");
        ret = PTR_ERR(fdata->local_shared_zmap);
        fdata->local_shared_zmap = NULL;
        goto err_zpage_free;
    }
    /* Initialize the counters to 0 */
    local_shared_data = (void *)fdata->local_shared_zpage->queue.pages[0];
    for (i = 0; i < MAX_IRQ_VECTORS; i++)
        local_shared_data->handled_counter[i] = 0;

    fdata->local_shared_zmap->owner = NULL;
    smp_wmb();

    /* Map the global shared page for this process's address space. */
    fdata->global_shared_zmap = zmap_alloc(fdata, global_shared_zpage);
    if (IS_ERR(fdata->global_shared_zmap)) {
        debug(DEBUG_IO, "zmap_alloc failed\n");
        ret = PTR_ERR(fdata->global_shared_zmap);
        fdata->global_shared_zmap = NULL;
            goto err_zpage_free;
    }

    fdata->global_shared_zmap->owner = NULL;
    smp_wmb();

    goto done;

err_zpage_free:
    if (fdata->local_shared_zpage) {
        queue_zpages_free(fdata->local_shared_zpage);
        do_kfree(fdata->local_shared_zpage);
    }
done:
    return ret;
}

struct file_data *pid_to_fdata(struct bridge *br, pid_t pid)
{
    struct file_data *cur, *ret = NULL;

    spin_lock(&br->fdata_lock);
    list_for_each_entry(cur, &br->fdata_list, fdata_list) {
        if (cur->pid == pid) {
            ret = cur;
            break;
        }
    }
    spin_unlock(&br->fdata_lock);
    return ret;
}

static int zhpe_open(struct inode *inode, struct file *file)
{
    int                 ret = 0;
    struct file_data    *fdata = NULL;
    struct bridge       *br = &zhpe_bridge;
    size_t              size;

    mutex_lock(&br->probe_mutex);
    if (br->num_slices != br->expected_slices) {
        ret = -ENODEV;
        printk_once(KERN_ERR "%s:%s:num_slices (%u) != expected_slices (%u)\n",
                    zhpe_driver_name, __func__, br->num_slices,
                    br->expected_slices);
    }
    if (br->probe_error < 0) {
        ret = -ENODEV;
        printk_once(KERN_ERR "%s:%s:error during probe\n",
                    zhpe_driver_name, __func__);
    }
    mutex_unlock(&br->probe_mutex);
    if (ret < 0)
        goto done;

    ret = -ENOMEM;
    size = sizeof(*fdata);
    fdata = do_kmalloc(size, GFP_KERNEL, true);
    if (!fdata)
        goto done;

    fdata->pid = task_tgid_nr(current); /* Associate this fdata with pid */
    fdata->free = file_data_free;
    atomic_set(&fdata->count, 1);
    spin_lock_init(&fdata->io_lock);
    init_waitqueue_head(&fdata->io_wqh);
    INIT_LIST_HEAD(&fdata->rd_list);
    /* Revisit MultiBridge: support multiple bridges */
    fdata->bridge = &zhpe_bridge;
    spin_lock_init(&fdata->uuid_lock);
    fdata->local_uuid = NULL;
    fdata->fd_remote_uuid_tree = RB_ROOT;
    spin_lock_init(&fdata->mr_lock);
    fdata->mr_tree = RB_ROOT;
    fdata->fd_rmr_tree = RB_ROOT;
    INIT_LIST_HEAD(&fdata->zmap_list);
    spin_lock_init(&fdata->zmap_lock);
    mutex_init(&fdata->xdm_queue_mutex);
    /* xdm_queues tracks what queues are owned by this file_data */
    /* Revisit Perf: what is the tradeoff of size of bitmap vs. rbtree? */
    bitmap_zero(fdata->xdm_queues, zhpe_xdm_queues_per_slice*SLICES);
    spin_lock_init(&fdata->rdm_queue_lock);
    bitmap_zero(fdata->rdm_queues, zhpe_rdm_queues_per_slice*SLICES);
    /* we only allow one open per pid */
    if (pid_to_fdata(fdata->bridge, fdata->pid)) {
        ret = -EBUSY;
        goto done;
    }
    /* Allocate and map the local shared data page. Map the global page. */
    ret = alloc_map_shared_data(fdata);
    if (ret != 0) {
        debug(DEBUG_IO, "alloc_map_shared_data:failed with ret = %d\n", ret);
        goto done;
    }
    ret = zhpe_pasid_alloc(&fdata->pasid);
    if (ret < 0)
        goto free_shared_data;
    /* Bind the task to the PASID on the device, if there is an IOMMU. */
    ret = zhpe_bind_iommu(fdata);
    if (ret < 0)
        goto free_pasid;
    /*
     * Revisit: set fabric_pasid to 42
     * Sharing requester ZMMU entries requires having the same fabric_pasid
     * on all queues sharing the entry and there is no way to know what
     * processes are a part of the same job until sharing begins. To solve
     * this on the fly would require stopping queues and changing their
     * fabric_pasid and that of the requester ZMMU entries they are
     * sharing. This is a major pain, so we're not going to do it right now
     * and hope a better solution presents itself.
     */
    fdata->fabric_pasid = 42;
    /* Initialize our mmu notifier to handle cleanup */
    ret = zhpe_mmun_init(fdata);
    if (ret < 0)
        goto unbind_iommu;

    /* Add this fdata to the bridge's fdata_list */
    spin_lock(&fdata->bridge->fdata_lock);
    list_add(&fdata->fdata_list, &fdata->bridge->fdata_list);
    spin_unlock(&fdata->bridge->fdata_lock);

    ret = 0;
    goto done;

 unbind_iommu:
    zhpe_unbind_iommu(fdata);

 free_pasid:
    zhpe_pasid_free(fdata->pasid);

 free_shared_data:
    zmap_free(fdata->local_shared_zmap);
    /* global_shared_zmap zpages are not freed until driver exit. */
    do_kfree(fdata->global_shared_zmap);

 done:
    if (ret < 0 && fdata) {
        put_file_data(fdata);
        fdata = NULL;
    }
    file->private_data = fdata;

    debug(DEBUG_IO, "ret = %d, pasid = %d\n", ret, (fdata ? fdata->pasid : -1));

    return ret;
}

#define ZHPE_ZMMU_XDM_RDM_HSR_BAR 0

#define PCI_TPH_CTL_OFF         (0x08)
#define PCI_TPH_CTL_DEF         (0x100) /* Default enabled */

/*
 * pfslice: LARK1.SLOT1.PFS0.SKWGPSHIMINBOUND0.SKW_SHIM_INB_CFG
 * wildcat:
 * CHASSIS1.SEAHAWK1.WILDCAT0.SKYWAYx.SKWGPSHIMINBOUNDy.SKW_SHIM_INB_CFG
 * slice 0: x = 0
 * slice 1: x = 0
 * slice 2: x = 1
 * slice 3: x = 1
 * At the moment:
 * block_off +  chip_id * 0x800000 + y * block_size
 * OZS0: chip_id 0
 * SKW0: chip_id 1
 * SKW1: chip_id 2
 */

enum {
    CHIP_ID_OZS0,
    CHIP_ID_SKW0,
    CHIP_ID_SKW1,
};

struct zhpe_csr_block {
    uint16_t            block_size;
    uint8_t             blocks[2];      /* PFS, Wildcat */
};

struct zhpe_csr {
    uint32_t            addr[2];        /* PFS, Wildcat */
    const struct zhpe_csr_block *block;
};

/* OZS registers. */

static const struct zhpe_csr_block ozs_core_block = {
    .blocks             = { 1, 1 },
};

/* 16-bit SID at bit 0, if reg_24 SID_VALID flag set. */
static struct zhpe_csr ozs_core_reg_23 = {
    .addr               = { 0x40000B8, 0x40000B8 },
    .block              = &ozs_core_block,
};

/* 12-bit CID at bit 8. CID0 should always be valid, but we'll check anyway.  */
static struct zhpe_csr ozs_core_reg_24 = {
    .addr               = { 0x40000C0, 0x40000C0 },
    .block              = &ozs_core_block,
};

static const struct zhpe_csr_block skw_shim_inb_block = {
    .block_size         = 0x1000,
    .blocks             = { 1, 2 },
};

#define OZS_CORE_REG_24_CID0_VALID      (0x01)
#define OZS_CORE_REG_24_CID0_SHIFT      (0x08)
#define OZS_CORE_REG_24_SID_VALID       (0x80)

static struct zhpe_csr skw_shim_inb_cfg = {
    .addr               = { 0x073A908, 0x07BA908 },
    .block              = &skw_shim_inb_block,
};

static const struct zhpe_csr_block xdm_block = {
    .block_size         = 0x1000,
    .blocks             = { 1, 2 },
};

static struct zhpe_csr xdm_err_all_status = {
    .addr               = { 0x0705088, 0x0730088 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_err_pri_status = {
    .addr               = { 0x0705080, 0x0730080 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_err_hwa_all_status = {
    .addr               = { 0x0705820, 0x0730820 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_err_hwa_pri_status = {
    .addr               = { 0x0705818, 0x0730818 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_err_hwe_all_status = {
    .addr               = { 0x0705808, 0x0730808 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_err_hwe_pri_status = {
    .addr               = { 0x0705800, 0x0730800 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_request_cfg = {
    .addr               = { 0x0705200, 0x0730200 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_size_cfg0 = {
    .addr               = { 0x0705210, 0x0730210 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_priority_cfg0 = {
    .addr               = { 0x0705228, 0x0730228 },
    .block              = &xdm_block,
};

static struct zhpe_csr xdm_priority_cfg1 = {
    .addr               = { 0x0705230, 0x0730230 },
    .block              = &xdm_block,
};

static int csr_access(struct slice *sl, struct zhpe_csr *zcsr,
                      uint32_t chip_id, uint32_t blocknum,
                      uint64_t *data, bool read)
{
    int                 ret = -EIO;
    uint32_t            pidx = zhpe_platform - ZHPE_PFSLICE;
    uint32_t            off;
    uint32_t            val;
    uint32_t            cmd;
    uint32_t            csr;
    int                 pos;
    uint                i;

    off = blocknum * zcsr->block->block_size;

    switch (zhpe_platform) {

    case ZHPE_PFSLICE:
        /* No chip_id on slice. */
        break;

    case ZHPE_WILDCAT:
        off += chip_id * 0x800000U;
        break;

    default:
        return -EINVAL;

    }

    csr = zcsr->addr[pidx];
    if (blocknum >= zcsr->block->blocks[pidx])
        return -EINVAL;

    pos = pci_find_ext_capability(sl->pdev, PCI_EXT_CAP_ID_DVSEC);
    if (!pos)
        goto out;
    pci_read_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_CTRL_OFF, &val);
    if (val & ZHPE_DVSEC_MBOX_CTRL_TRIG) {
        debug(DEBUG_PCI, "Mailbox busy\n");
        goto out;
    }
    pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_ADDR_OFF, csr + off);
    cmd = ZHPE_DVSEC_MBOX_CTRL_BE | ZHPE_DVSEC_MBOX_CTRL_TRIG;
    if (!read) {
        cmd |= ZHPE_DVSEC_MBOX_CTRL_WR;
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_DATAL_OFF,
                               *data);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_DATAH_OFF,
                               *data >> 32);
    }
    pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_CTRL_OFF, cmd);
    /* Wait 1-2 ms for completion. */
    for (i = 0; i < 100; i++) {
        pci_read_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_CTRL_OFF, &val);
        if (!(val & ZHPE_DVSEC_MBOX_CTRL_TRIG)) {
            if (val & ZHPE_DVSEC_MBOX_CTRL_ERR) {
                debug(DEBUG_PCI, "error = 0x%x\n", val);
                goto out;
            }
            /* Success */
            ret = 0;
            if (!read)
                goto out;
            /* Read result. */
            pci_read_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_DATAL_OFF,
                                  &val);
            *data = val;
            pci_read_config_dword(sl->pdev, pos + ZHPE_DVSEC_MBOX_DATAH_OFF,
                                  &val);
            *data |= ((uint64_t)val) << 32;
            goto out;
        }
        usleep_range(10, 20);
    }
    debug(DEBUG_PCI, "timeout\n");

out:
    dev_info(&sl->pdev->dev,
             "%s:sl %u csr 0x%x/0x%x/%u/%u %s val 0x%llx ret %d\n",
             __func__, sl->phys_id, csr, off, chip_id, blocknum,
             (read ? "rd" : "wr"), *data, ret);

    return ret;
}

static int csr_access_rd(struct slice *sl, struct zhpe_csr *zcsr,
                         uint32_t chip_id, uint32_t blocknum, uint64_t *data)
{
    return csr_access(sl, zcsr, chip_id, blocknum, data, true);
}

static int csr_access_wr(struct slice *sl, struct zhpe_csr *zcsr,
                         uint32_t chip_id, uint32_t blocknum, uint64_t data)
{
    return csr_access(sl, zcsr, chip_id, blocknum, &data, false);
}

static int csr_access_rdwr(struct slice *sl, struct zhpe_csr *zcsr,
                           uint32_t chip_id, uint32_t blocknum,
                           uint64_t mask, uint64_t data)
{
    int                 ret;
    uint64_t            orig;

    /* Read the current value to get it logged. */
    ret = csr_access_rd(sl, zcsr, chip_id, blocknum, &orig);
    if (!ret)
        ret = csr_access_wr(sl, zcsr, chip_id, blocknum,
                            (orig & mask) | (data & ~mask));

    return ret;
}

static int csr_get_gcid(struct slice *sl, uint32_t *gcid)
{
    int                 ret = 0;
    uint64_t            sid = 0;
    uint64_t            cid;

    ret = csr_access_rd(sl, &ozs_core_reg_24, CHIP_ID_OZS0, 0, &cid);
    if (ret < 0)
        goto out;
    if (!(cid & OZS_CORE_REG_24_CID0_VALID)) {
        ret = -ENXIO;
        goto out;
    }

    if (cid & OZS_CORE_REG_24_SID_VALID) {
        ret = csr_access_rd(sl, &ozs_core_reg_23, CHIP_ID_OZS0, 0, &sid);
        if (ret < 0)
            goto out;
        sid = (sid & ZHPE_GCID_SID_MASK) << ZHPE_GCID_SID_SHIFT;
    }

    cid = (cid >> OZS_CORE_REG_24_CID0_SHIFT) & ZHPE_GCID_CID_MASK;
    *gcid = cid | sid;

out:
    return 0;
}

static int csr_set_shim_inb_cfg(struct slice *sl, uint32_t chip_id)
{
    int                 ret;
    uint32_t            pidx = zhpe_platform - ZHPE_PFSLICE;
    uint32_t            blk;

    for (blk = 0; blk < skw_shim_inb_block.blocks[pidx]; blk++) {
        ret = csr_access_rdwr(sl, &skw_shim_inb_cfg, chip_id, blk,
                              skw_shim_inb_cfg_mask, skw_shim_inb_cfg_bits);
        if (ret < 0)
            goto out;
    }
    ret = 0;

 out:
    return ret;
}

static int csr_set_xdm(struct slice *sl, uint32_t chip_id)
{
    int                 ret;
    uint32_t            pidx = zhpe_platform - ZHPE_PFSLICE;
    struct xdm_priority *xdm_pri;
    uint32_t            blk;
    uint64_t            val;

    for (blk = 0; blk < xdm_block.blocks[pidx]; blk++) {
        /* Disable stop on command-level error. */
        ret = csr_access_rdwr(sl, &xdm_request_cfg, chip_id, blk,
                              xdm_request_cfg_mask, xdm_request_cfg_bits);
        if (ret < 0)
            goto out;

        /* Queue priority settings. */
        xdm_pri = (xdm_priority_cfg_enable ? &xdm_pri_on : &xdm_pri_off);
        ret = csr_access_rdwr(sl, &xdm_size_cfg0, chip_id, blk,
                              xdm_pri->xdm_size_cfg0_mask,
                              xdm_pri->xdm_size_cfg0_bits);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_priority_cfg0, chip_id, blk,
                              xdm_pri->xdm_priority_cfg0_mask,
                              xdm_pri->xdm_priority_cfg0_bits);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_priority_cfg1, chip_id, blk,
                              xdm_pri->xdm_priority_cfg1_mask,
                              xdm_pri->xdm_priority_cfg1_bits);
        if (ret < 0)
            goto out;

        /* Reset logs */
        ret = csr_access_rdwr(sl, &xdm_err_hwa_all_status, chip_id, blk,
                              0, 0x1);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_err_hwa_pri_status, chip_id, blk,
                              0, 0x1);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_err_hwe_all_status, chip_id, blk,
                              0, 0x1);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_err_hwe_pri_status, chip_id, blk,
                              0, 0x1);
        if (ret < 0)
            goto out;

        ret = csr_access_rdwr(sl, &xdm_err_all_status, chip_id, blk,
                              0, 0xC);
        if (ret < 0)
            goto out;
        ret = csr_access_rdwr(sl, &xdm_err_pri_status, chip_id, blk,
                              0, 0xC);
        if (ret < 0)
            goto out;
        /* Read error status back to get their final value in the log. */
        ret = csr_access_rd(sl, &xdm_err_all_status, chip_id, blk, &val);
        if (ret < 0)
            goto out;
        ret = csr_access_rd(sl, &xdm_err_pri_status, chip_id, blk, &val);
        if (ret < 0)
            goto out;
    }
    ret = 0;

 out:
    return ret;
}

static int probe_setup_slices(struct bridge *br)
{
    int                 ret = 0;
    uint32_t            chip_mask = 0;
    struct slice        *sl1 = NULL;
    struct pci_dev      *pdev1 = NULL;
    struct slice        *sl;
    uint32_t            chip_id;
    uint32_t            i;
    int                 pos;
    int                 slink_val1;
    int                 slink_val2;
    uint64_t            slink_size;

    /* Find the first valid slice and there must be at least one. */
    for (i = 0; i < SLICES; i++) {
        sl = &br->slice[i];
        if (!SLICE_VALID(sl))
            continue;

        chip_mask |= (1U << (i / 2 + CHIP_ID_SKW0));
        if (!sl1) {
            sl1 = sl;
            pdev1 = sl1->pdev;
        }
    }

    /* Determine S-link base and aperture. */
    slink_val1 = 0;
    /* Default aperture set in autodetect_platform(). */
    slink_size = zhpe_reqz_max_cpuvisible_addr - zhpe_reqz_min_cpuvisible_addr;

    switch (zhpe_platform) {

    case ZHPE_PFSLICE:
        /* Should be only one slice. */
        pos = pci_find_ext_capability(sl1->pdev, PCI_EXT_CAP_ID_DVSEC);
        pci_read_config_dword(sl1->pdev, pos + ZHPE_DVSEC_SLINK_OFF,
                              &slink_val1);
        dev_info(&sl1->pdev->dev, "%s:pslice = %u, slink = 0x%x\n",
                 __func__, sl1->phys_id, slink_val1);
        break;

    case ZHPE_WILDCAT:
        /* Both slices 2 and 3 must be valid. */
        sl = &br->slice[0];
        if (!SLICE_VALID(&sl[2]) || !SLICE_VALID(&sl[3]))
            break;
        pos = pci_find_ext_capability(sl[2].pdev, PCI_EXT_CAP_ID_DVSEC);
        pci_read_config_dword(sl[2].pdev, pos + ZHPE_DVSEC_SLINK_OFF,
                              &slink_val1);
        dev_info(&sl[2].pdev->dev, "%s:pslice = %u, slink = 0x%x\n",
                 __func__, sl[2].phys_id, slink_val1);
        pos = pci_find_ext_capability(sl[3].pdev, PCI_EXT_CAP_ID_DVSEC);
        pci_read_config_dword(sl[3].pdev, pos + ZHPE_DVSEC_SLINK_OFF,
                              &slink_val2);
        dev_info(&sl[3].pdev->dev, "%s:pslice = %u, slink = 0x%x\n",
                 __func__, sl[3].phys_id, slink_val2);
        if (slink_val1 != slink_val2) {
            dev_warn(&sl[3].pdev->dev, "%s:slices inconsistent\n", __func__);
            slink_val1 = 0;
            break;
        }
        if (!(slink_val1 & ZHPE_DVSEC_SLINK_SIZE_MASK)) {
            slink_val1 = 0;
            break;
        }
        /* Each slice's side is half the aperture. */
        slink_size = (((uint64_t)(slink_val1 & ZHPE_DVSEC_SLINK_SIZE_MASK)
                       << (ZHPE_DVSEC_SLINK_SIZE_LSHIFT + 1)) - 1);
        break;

    }

    if (!slink_val1) {
        dev_warn(&pdev1->dev, "%s:slink disabled\n", __func__);
        zhpe_reqz_phy_cpuvisible_off |= 1;
    } else {
        zhpe_reqz_phy_cpuvisible_off =
            ((uint64_t)(slink_val1 & ZHPE_DVSEC_SLINK_BASE_MASK)
             << ZHPE_DVSEC_SLINK_BASE_LSHIFT);
        dev_warn(&pdev1->dev, "%s:slink phyaddr 0x%llx - 0x%llx\n",
                 __func__, zhpe_reqz_phy_cpuvisible_off,
                 zhpe_reqz_phy_cpuvisible_off + slink_size);
        zhpe_reqz_max_cpuvisible_addr =
            zhpe_reqz_min_cpuvisible_addr + slink_size;
    }

    for (chip_id = CHIP_ID_SKW0; chip_id <= CHIP_ID_SKW1; chip_id++) {
        debug(DEBUG_PCI, "chip_id = %u, chip_mask 0x%x\n", chip_id, chip_mask);
        if (!(chip_mask & (1U << chip_id)))
            continue;
        /* OZS (chip 0) can only be access via mailbox on chip 1 */
        if (chip_id == 1) {
            ret = csr_get_gcid(sl1, &br->gcid);
            if (ret < 0)
                goto out;
        }
        ret = csr_set_shim_inb_cfg(sl1, chip_id);
        if (ret < 0)
            goto out;
        ret = csr_set_xdm(sl1, chip_id);
        if (ret < 0)
            goto out;
    }

    for (i = 0; i < SLICES; i++) {
        sl = &br->slice[i];
        if (!SLICE_VALID(sl))
            continue;

        /* Configure TPH */
        pos = pci_find_ext_capability(sl->pdev, PCI_EXT_CAP_ID_TPH);
        if (pos)
            pci_write_config_dword(sl->pdev, pos + PCI_TPH_CTL_OFF,
                                   PCI_TPH_CTL_DEF);
        else
            dev_warn(&sl->pdev->dev, "TPH ECAP not found\n");

        /* Configure write pusher. */
        pos = pci_find_ext_capability(sl->pdev, PCI_EXT_CAP_ID_DVSEC);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_WP_CTL_28_OFF, 0);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_WP_ADDR_LO_OFF,
                               wr_pusher_phyaddr);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_WP_ADDR_HI_OFF,
                               wr_pusher_phyaddr >> 32);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_WP_CTL_24_OFF,
                               ZHPE_DVSEC_WP_CTL_24_VAL);
        pci_write_config_dword(sl->pdev, pos + ZHPE_DVSEC_WP_CTL_28_OFF,
                               wr_pusher_dvsec_28);

        zhpe_zmmu_setup_slice(sl);
    }

 out:
    return ret;
}

void zhpe_disable_dbg_obs(struct bridge *br)
{
    uint                sl;
    int                 pos;
    uint32_t            slice_data;
    struct pci_dev      *pdev;

    mutex_lock(&br->probe_mutex);
    for (sl = 0; sl < SLICES; sl++) {
        if (!SLICE_VALID(&br->slice[sl])) {
            continue;
        }
        pdev = br->slice[sl].pdev;
        pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DVSEC);
        pci_read_config_dword(pdev, pos + ZHPE_DVSEC_SLICE_OFF, &slice_data);
        slice_data &= ~ZHPE_DVSEC_DBG_OBS_MASK;
        pci_write_config_dword(pdev, pos + ZHPE_DVSEC_SLICE_OFF, slice_data);
    }
    if (br->probe_error >= 0)
        br->probe_error = -EIO;
    mutex_unlock(&br->probe_mutex);

}

static int zhpe_probe(struct pci_dev *pdev,
                      const struct pci_device_id *pdev_id)
{
    int ret, pos = 0;
    int vslice_id;
    int pslice_id;
    void __iomem *base_addr;
    struct bridge *br = &zhpe_bridge;
    struct slice *sl = NULL;
    phys_addr_t phys_base;
    uint16_t devctl2;

    /* No setup for function 0 */
    if (PCI_FUNC(pdev->devfn) == 0) {
        return 0;
    }

    mutex_lock(&br->probe_mutex);

    if (br->num_slices >= SLICES) {
        ret = -ENODEV;
        goto err_out;
    }

    if (zhpe_platform <= 0) {
            dev_warn(&pdev->dev,
                     "%s:Unable to autodetect platform, zhpe_platform=%d",
                     __func__, zhpe_platform);
        ret = -ENODEV;
        goto err_out;
    }

    if (zhpe_platform != ZHPE_CARBON) {
        /* Set atomic operations enable capability */
        pcie_capability_set_word(pdev, PCI_EXP_DEVCTL2,
                                 PCI_EXP_DEVCTL2_ATOMIC_REQ);
        ret = pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &devctl2);
        if (ret < 0) {
            dev_warn(&pdev->dev,
                     "%s:PCIe AtomicOp pcie_capability_read_word failed,"
                     " ret = 0x%x\n", __func__, ret);
            goto err_out;
        } else if (!(devctl2 & PCI_EXP_DEVCTL2_ATOMIC_REQ)) {
            dev_warn(&pdev->dev,
                     "%s:PCIe AtomicOp capability enable failed,"
                     " devctl2 = 0x%x\n", __func__, (uint)devctl2);
            ret = -EIO;
            goto err_out;
        }
        /* Get the virtual slice ID from the device. */
        pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DVSEC);
        if (!pos) {
            dev_warn(&pdev->dev, "%s:No DVSEC capability found\n", __func__);
            ret = -ENODEV;
            goto err_out;
        }

        pci_read_config_dword(pdev, pos + ZHPE_DVSEC_SLICE_OFF, &pslice_id);
        vslice_id = pslice_id;
        pslice_id >>= ZHPE_DVSEC_PSLICE_SHIFT;
        pslice_id &= ZHPE_DVSEC_SLICE_MASK;
        vslice_id >>= ZHPE_DVSEC_VSLICE_SHIFT;
        vslice_id &= ZHPE_DVSEC_SLICE_MASK;
        /* Revisit: vslice not working. */
        vslice_id = pslice_id;
        /* Duplicates are an error. */
        sl = &br->slice[vslice_id];
        if (SLICE_VALID(sl)) {
            dev_warn(&pdev->dev, "%s,%u,%d:slice %d already found\n",
                     __func__, __LINE__, task_pid_nr(current), pslice_id);
            ret = -ENODEV;
            goto err_out;
        }
        dev_info(&pdev->dev, "%s:pslice = %d, vslice = %d\n",
                 __func__, pslice_id, vslice_id);
    } else {
        /* Carbon:zero based slice ID */
        pslice_id = br->num_slices;
        vslice_id = pslice_id;
        sl = &br->slice[vslice_id];
    }
    br->num_slices++;

    debug(DEBUG_PCI, "device = %s, slice = %u\n", pci_name(pdev), pslice_id);

    ret = pci_enable_device(pdev);
    if (ret) {
        debug(DEBUG_PCI, "pci_enable_device probe error %d for device %s\n",
              ret, pci_name(pdev));
        goto err_invalid;
    }

    if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
        ret = -ENOSPC;
        dev_warn(&pdev->dev, "No 64-bit DMA available\n");
        goto err_pci_disable_device;
    }

    ret = pci_request_regions(pdev, DRIVER_NAME);
    if (ret < 0) {
        debug(DEBUG_PCI, "pci_request_regions error %d for device %s\n",
              ret, pci_name(pdev));
        goto err_pci_disable_device;
    }

    base_addr = pci_iomap(pdev, ZHPE_ZMMU_XDM_RDM_HSR_BAR,
                          sizeof(struct func1_bar0));
    if (!base_addr) {
        debug(DEBUG_PCI,
              "cannot iomap bar %u registers of size %lu"
              " (requested size = %lu)\n",
              ZHPE_ZMMU_XDM_RDM_HSR_BAR,
              (unsigned long) pci_resource_len(pdev, ZHPE_ZMMU_XDM_RDM_HSR_BAR),
              sizeof(struct func1_bar0));
        ret = -EINVAL;
        goto err_pci_release_regions;
    }
    phys_base = pci_resource_start(pdev, 0);

    debug(DEBUG_PCI,
          "bar = %u, start = 0x%lx, actual len = %lu,"
          " requested len = %lu, base_addr = 0x%lx\n",
          0, (ulong)phys_base, (ulong) pci_resource_len(pdev, 0),
          sizeof(struct func1_bar0), (ulong) base_addr);

    sl->bar = base_addr;
    sl->phys_base = phys_base;
    sl->id = vslice_id;
    sl->phys_id = pslice_id;
    sl->pdev = pdev;
    sl->valid = true;
    br->slice_mask |= (1 << pslice_id);

    zhpe_zmmu_clear_slice(sl);

    zhpe_xqueue_init(sl);
    ret = zhpe_clear_xdm_qcm(br, sl);
    if (ret < 0)
        goto err_pci_iounmap;

    zhpe_rqueue_init(sl);
    ret = zhpe_clear_rdm_qcm(br, sl);
    if (ret < 0)
        goto err_pci_iounmap;

    pci_set_drvdata(pdev, sl);

    /* Initialize this pci_dev with the AMD iommu */
    if (!no_iommu) {
        ret = amd_iommu_init_device(pdev, ZHPE_NUM_PASIDS);
        if (ret < 0) {
            debug(DEBUG_PCI,
                  "amd_iommu_init_device failed with error %d\n", ret);
            goto err_pci_iounmap;
        }
        sl->dom = iommu_get_domain_for_dev(&sl->pdev->dev);
    }

    ret = zhpe_register_interrupts(pdev, sl);
    if (ret) {
        debug(DEBUG_PCI, "zhpe_register_interrupts failed with ret=%d\n", ret);
        goto err_iommu_free;
    }

    if (br->num_slices == br->expected_slices) {
        /* allocate driver-driver msg queues */
        ret = zhpe_msg_qalloc(br);
        if (ret) {
            debug(DEBUG_PCI, "zhpe_msg_qalloc failed with error %d\n", ret);
            goto err_free_interrupts;
        }

        if (zhpe_platform != ZHPE_CARBON) {
            ret = probe_setup_slices(br);
            if (ret < 0)
                goto err_free_interrupts;
        }

        if (br->gcid == INVALID_GCID) {
            if (genz_gcid == INVALID_GCID) {
                dev_warn(&pdev->dev, "%s,%u,%d:no valid gcid available\n",
                         __func__, __LINE__, task_pid_nr(current));
                ret = -EINVAL;
                goto err_free_interrupts;
            }
            dev_info(&pdev->dev, "%s:using genz_gcid = 0x%07x\n",
                     __func__, genz_gcid);
            br->gcid = genz_gcid;
        } else {
            dev_info(&pdev->dev, "%s:gcid = 0x%07x\n",
                     __func__, br->gcid);
            /* Make the gcid visible in the parameters. */
            genz_gcid = br->gcid;
        }
    }

    pci_set_master(pdev);
    dev_info(&pdev->dev, "%s:successful\n", __func__);

    mutex_unlock(&br->probe_mutex);

    return 0;

 err_free_interrupts:
    zhpe_free_interrupts(pdev);

 err_iommu_free:
    if (!no_iommu)
        amd_iommu_free_device(pdev);

 err_pci_iounmap:
    pci_iounmap(pdev, sl->bar);

 err_pci_release_regions:
    pci_release_regions(pdev);

 err_pci_disable_device:
    pci_disable_device(pdev);

 err_invalid:
    sl->valid = false;

 err_out:
    if (br->probe_error >= 0)
        br->probe_error = ret;

    mutex_unlock(&br->probe_mutex);

    return ret;
}

static void zhpe_remove(struct pci_dev *pdev)
{
    struct slice *sl;

    /* No teardown for function 0 */
    if (PCI_FUNC(pdev->devfn) == 0) {
        return;
    }

    sl = (struct slice *) pci_get_drvdata(pdev);

    debug(DEBUG_PCI, "device = %s, slice = %u\n", pci_name(pdev), sl->id);

    zhpe_free_interrupts(pdev);
    zhpe_msg_qfree(sl);
    pci_clear_master(pdev);

    /* If we are using the IOMMU, free the device */
    if (!no_iommu) {
        amd_iommu_free_device(pdev);
    }

    zhpe_zmmu_clear_slice(sl);
    pci_iounmap(pdev, sl->bar);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
}

static struct miscdevice miscdev = {
    .name               = zhpe_driver_name,
    .fops               = &zhpe_fops,
    .minor              = MISC_DYNAMIC_MINOR,
    .mode               = 0666,
};

static struct pci_driver zhpe_pci_driver = {
    .name      = DRIVER_NAME,
    .id_table  = zhpe_id_table,
    .probe     = zhpe_probe,
    .remove    = zhpe_remove,
};

bool zhpe_mcommit;

#ifndef X86_FEATURE_MCOMMIT
#define X86_FEATURE_MCOMMIT     (13*32+ 8)
#endif

#ifndef _EFER_MCOMMIT
#define _EFER_MCOMMIT           (17)
#define EFER_MCOMMIT            (1ULL<<_EFER_MCOMMIT)
#endif

static void __init zhpe_enable_mcommit(void *dummy)
{
    uint64_t            efer;

    /* Locking? */
    rdmsrl(MSR_EFER, efer);
    if (!(efer & EFER_MCOMMIT)) {
        efer |= EFER_MCOMMIT;
        wrmsrl(MSR_EFER, efer);
    }
}

static int __init zhpe_init(void)
{
    int                 ret;
    int                 i;
    uint                sl, pg, cnt, pg_index;

    ret = autodetect_platform();
    if (ret < 0) {
        zprintk(KERN_WARNING, "Unable to autodetect platform.\n");
        goto err_out;
    }

    ret = -ENOSYS;
    if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
        zprintk(KERN_WARNING, "AMD CPU required\n");
        goto err_out;
    }
    if (!(zhpe_no_avx || boot_cpu_has(X86_FEATURE_AVX))) {
        zprintk(KERN_WARNING, "missing required AVX CPU feature.\n");
        goto err_out;
    }
    if (boot_cpu_has(X86_FEATURE_MCOMMIT)) {
        on_each_cpu(zhpe_enable_mcommit, NULL, 1);
        zhpe_mcommit = true;
        zprintk(KERN_INFO, "mcommit supported and enabled\n");
    } else
        zprintk(KERN_WARNING, "mcommit not supported\n");

    ret = -ENOMEM;
    global_shared_zpage = shared_zpage_alloc(sizeof(*global_shared_data),
                                             GLOBAL_SHARED_PAGE);
    if (!global_shared_zpage) {
        zprintk(KERN_WARNING, "queue_zpages_alloc failed.\n");
        goto err_out;
    }
    global_shared_data = global_shared_zpage->queue.pages[0];
    for (i = 0; i < MAX_IRQ_VECTORS; i++)
        global_shared_data->triggered_counter[i] = 0;

    spin_lock_init(&zhpe_bridge.zmmu_lock);
    for (sl = 0; sl < SLICES; sl++) {
        spin_lock_init(&zhpe_bridge.slice[sl].zmmu_lock);
    }
    mutex_init(&zhpe_bridge.probe_mutex);
    spin_lock_init(&zhpe_bridge.fdata_lock);
    INIT_LIST_HEAD(&zhpe_bridge.fdata_list);
    zhpe_bridge.gcid = INVALID_GCID;
    INIT_DELAYED_WORK(&zhpe_bridge.msg_work, zhpe_msg_worker);
    spin_lock_init(&zhpe_bridge.snap_lock);
    init_waitqueue_head(&zhpe_bridge.snap_wqh[0]);
    init_waitqueue_head(&zhpe_bridge.snap_wqh[1]);
    spin_lock_init(&zhpe_bridge.rspctxid_rbtree_lock);
    zhpe_bridge.rspctxid_rbtree = RB_ROOT;

    debug(DEBUG_ZMMU, "calling zhpe_zmmu_clear_all\n");
    zhpe_zmmu_clear_all(&zhpe_bridge, false);
    debug(DEBUG_ZMMU, "calling zhpe_pasid_init\n");
    zhpe_pasid_init();
    debug(DEBUG_RKEYS, "calling zhpe_rkey_init\n");
    zhpe_rkey_init();

    debug(DEBUG_ZMMU, "req calling parse_page_grid_opt(%s, %u, %px)\n",
          req_page_grid, zhpe_req_zmmu_entries, sw_pg);
    cnt = parse_page_grid_opt(req_page_grid, zhpe_req_zmmu_entries, true, sw_pg);
    for (pg = 0; pg < cnt; pg++) {
        pg_index = zhpe_zmmu_req_page_grid_alloc(&zhpe_bridge, &sw_pg[pg]);
    }

    debug(DEBUG_ZMMU, "rsp calling parse_page_grid_opt(%s, %u, %px)\n",
          rsp_page_grid, zhpe_rsp_zmmu_entries, sw_pg);
    cnt = parse_page_grid_opt(rsp_page_grid, zhpe_rsp_zmmu_entries, false, sw_pg);
    for (pg = 0; pg < cnt; pg++) {
        pg_index = zhpe_zmmu_rsp_page_grid_alloc(&zhpe_bridge, &sw_pg[pg]);
    }

    /* Create 128 polling devices for interrupt notification to user space */
    if (zhpe_setup_poll_devs() != 0)
        goto err_zpage_free;

    /* Initiate call to zhpe_probe() for each zhpe PCI function */
    ret = pci_register_driver(&zhpe_pci_driver);
    if (ret < 0) {
        zprintk(KERN_WARNING, "pci_register_driver ret = %d\n", ret);
        goto err_cleanup_poll_devs;
    }

    /* Create device. */
    debug(DEBUG_IO, "creating device\n");
    ret = misc_register(&miscdev);
    if (ret < 0) {
        zprintk(KERN_WARNING, "misc_register() returned %d\n", ret);
        goto err_pci_unregister_driver;
    }

    zhpe_poll_init_waitqueues(&zhpe_bridge);

    return 0;

err_pci_unregister_driver:
    /* Initiate call to zhpe_remove() for each zhpe PCI function */
    pci_unregister_driver(&zhpe_pci_driver);

err_cleanup_poll_devs:
    zhpe_cleanup_poll_devs();

err_zpage_free:
    if (global_shared_zpage) {
        queue_zpages_free(global_shared_zpage);
        do_kfree(global_shared_zpage);
    }

err_out:
    return ret;
}

static void zhpe_exit(void)
{
    if (miscdev.minor != MISC_DYNAMIC_MINOR)
        misc_deregister(&miscdev);

    zhpe_cleanup_poll_devs();

    /* free shared data page. */
    if (global_shared_zpage) {
        queue_zpages_free(global_shared_zpage);
        do_kfree(global_shared_zpage);
    }

    /* Initiate call to zhpe_remove() for each zhpe PCI function */
    pci_unregister_driver(&zhpe_pci_driver);

    zhpe_zmmu_clear_all(&zhpe_bridge, true);
    zhpe_rkey_exit();
    zhpe_pasid_exit();
    zhpe_uuid_exit();

    zprintk(KERN_INFO, "mem_total %lld\n", (llong)atomic64_read(&mem_total));
}

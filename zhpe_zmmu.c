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

#include <linux/kernel.h>
#include <linux/bitops.h>

#include <zhpe.h>
#include <zhpe_driver.h>

#ifdef HAVE_RHEL
#include <asm/i387.h>
#else
#include <asm/fpu/api.h>
#endif

char *zhpe_gcid_str(const uint32_t gcid, char *str, const size_t len)
{
    snprintf(str, len, "%04x", gcid >> 12);
    if (len > 4)
        str[4] = ':';
    snprintf(str+5, len-5, "%03x", gcid & 0xfff);
    return str;
}

static void zmmu_page_grid_clear_all(struct page_grid *pg, bool sync)
{
    struct page_grid zero = { 0 }, tmp;
    uint i;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    for (i = 0; i < PAGE_GRID_ENTRIES; i++) {
        iowrite16by(&zero, &pg[i]);
    }

    if (sync)  /* ensure visibility */
        ioread16by(&tmp, &pg[0]);
}

static void zmmu_req_clear_all(struct req_zmmu *reqz, bool sync)
{
    struct req_pte zero = { 0 }, tmp;
    uint i;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    zmmu_page_grid_clear_all(reqz->page_grid, NO_SYNC);
    for (i = 0; i < zhpe_req_zmmu_entries; i++) {
        iowrite32by(&zero, &reqz->pte[i]);
    }

    if (sync)  /* ensure visibility */
        ioread32by(&tmp, &reqz->pte[0]);
}

static void zmmu_rsp_clear_all(struct rsp_zmmu *rspz, bool sync)
{
    struct rsp_pte zero = { 0 }, tmp;
    uint i;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    zmmu_page_grid_clear_all(rspz->page_grid, NO_SYNC);
    for (i = 0; i < zhpe_rsp_zmmu_entries; i++) {
        iowrite32by(&zero, &rspz->pte[i]);
    }

    if (sync)  /* ensure visibility */
        ioread32by(&tmp, &rspz->pte[0]);
}

void zhpe_zmmu_clear_slice(struct slice *sl)
{

    debug(DEBUG_ZMMU, "sl=%px, slice_valid=%u\n", sl, SLICE_VALID(sl));
    if (!SLICE_VALID(sl))
        return;

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    spin_lock(&sl->zmmu_lock);
    zmmu_req_clear_all(&sl->bar->req_zmmu, SYNC);
    zmmu_rsp_clear_all(&sl->bar->rsp_zmmu, SYNC);
    spin_unlock(&sl->zmmu_lock);
    if (!zhpe_no_avx)
        kernel_fpu_end();
}

static void zmmu_clear_pg_info(struct page_grid_info *pgi, uint entries,
                               bool free_radix_tree)
{
    struct radix_tree_iter iter;
    void **slot;

    if (free_radix_tree) {
        radix_tree_for_each_slot(slot, &pgi->pg_pagesize_tree, &iter,
                                 PAGE_GRID_MIN_PAGESIZE) {
            radix_tree_iter_delete(&pgi->pg_pagesize_tree, &iter, slot);
        }
    } else {
        INIT_RADIX_TREE(&pgi->pg_pagesize_tree, GFP_ATOMIC);
    }
    bitmap_zero(pgi->pg_bitmap, PAGE_GRID_ENTRIES);
    bitmap_zero(pgi->pg_cpu_visible_ps_bitmap, 64);
    bitmap_zero(pgi->pg_non_visible_ps_bitmap, 64);
    pgi->pte_entries = entries;
    pgi->base_pte_tree = RB_ROOT;
    pgi->base_addr_tree = RB_ROOT;
}

void zhpe_zmmu_clear_all(struct bridge *br, bool free_radix_tree)
{

    debug(DEBUG_ZMMU, "br=%px, free_radix_tree=%u\n", br, free_radix_tree);
    spin_lock(&br->zmmu_lock);
    zmmu_clear_pg_info(&br->req_zmmu_pg, zhpe_req_zmmu_entries,
                       free_radix_tree);
    zmmu_clear_pg_info(&br->rsp_zmmu_pg, zhpe_rsp_zmmu_entries,
                       free_radix_tree);
    spin_unlock(&br->zmmu_lock);
}

static void zmmu_page_grid_setup_all(struct page_grid_info *pgi,
                                     struct page_grid *pg, bool sync, char *nm)
{
    struct page_grid tmp;
    struct sw_page_grid *sw_pg = pgi->pg;
    uint i;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    for (i = 0; i < PAGE_GRID_ENTRIES; i++) {
        debug(DEBUG_ZMMU, "%s pg[%u]@%px:base_addr=0x%llx, "
              "page_size=%u, page_count=%u, base_pte_idx=%u\n",
              nm, i, &pg[i],
              sw_pg[i].page_grid.base_addr,
              sw_pg[i].page_grid.page_size,
              sw_pg[i].page_grid.page_count,
              sw_pg[i].page_grid.base_pte_idx);
        iowrite16by(&sw_pg[i].page_grid, &pg[i]);
    }

    if (sync)  /* ensure visibility */
        ioread16by(&tmp, &pg[0]);
}

void zhpe_zmmu_setup_slice(struct slice *sl)
{
    struct bridge *br = BRIDGE_FROM_SLICE(sl);

    debug(DEBUG_ZMMU, "sl=%px, br=%px, slice_valid=%u\n",
          sl, br, SLICE_VALID(sl));
    if (!SLICE_VALID(sl))
        return;

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    spin_lock(&sl->zmmu_lock);
    zmmu_page_grid_setup_all(&br->req_zmmu_pg, sl->bar->req_zmmu.page_grid,
                             SYNC, "req");
    zmmu_page_grid_setup_all(&br->rsp_zmmu_pg, sl->bar->rsp_zmmu.page_grid,
                             SYNC, "rsp");
    /* Revisit: setup req/rsp PTEs too */
    spin_unlock(&sl->zmmu_lock);
    if (!zhpe_no_avx)
        kernel_fpu_end();
}

static void zmmu_req_pte_write(struct zhpe_rmr *rmr,
                               struct req_zmmu *reqz, bool valid, bool sync)
{
    struct zhpe_pte_info *info = rmr->pte_info;
    struct req_pte pte = { 0 }, tmp;
    uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
    uint64_t addr, ps;
    char str[GCID_STRING_LEN+1];

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    if (info->zmmu_pages == 0 || info->pg == NULL)
        return;  /* no PTEs to write */
    pte.pasid = rmr->fdata->fabric_pasid;
    pte.space_type = info->space_type;
    /* Revisit: traffic_class, dc_grp */
    pte.dgcid = rmr->dgcid;
    pte.ctn = N;
    pte.rke = (rmr->rkey != 0);
    pte.rkey = rmr->rkey;
    pte.v = valid;
    ps = BIT_ULL(info->pg->page_grid.page_size);
    addr = info->addr_aligned;

    for (i = first; i <= last; i++) {
        pte.addr = addr >> 12;
        debug(DEBUG_ZMMU, "pte[%u]@%px:addr=0x%llx, pasid=0x%x, "
              "dgcid=%s, space_type=%u, rke=%u, rkey=0x%x, "
              "traffic_class=%u, dc_grp=%u, v=%u\n",
              i, &reqz->pte[i],
              (uint64_t)pte.addr, pte.pasid,
              zhpe_gcid_str(pte.dgcid, str, sizeof(str)),
              pte.space_type, pte.rke, pte.rkey,
              pte.traffic_class, pte.dc_grp, pte.v);
        iowrite32by(&pte, &reqz->pte[i]);
        addr += ps;
    }

    if (sync)  /* ensure visibility */
        ioread32by(&tmp, &reqz->pte[first]);
}

static void zmmu_rsp_pte_write(struct zhpe_pte_info *info,
                               struct rsp_zmmu *rspz, bool valid, bool sync)
{
    struct rsp_pte pte = { 0 }, tmp;
    uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
    uint64_t va, window_sz, length, ps, offset;
    bool writable = !!(info->access & ZHPE_MR_PUT_REMOTE);
    struct file_data *fdata =
        container_of(info, struct zhpe_umem, pte_info)->fdata;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    if (info->zmmu_pages == 0 || info->pg == NULL)
        return;  /* no PTEs to write */
    pte.pasid = fdata->pasid;
    pte.space_type = info->space_type;
    pte.rke = !zhpe_no_rkeys;
    pte.ro_rkey = fdata->ro_rkey;
    pte.rw_rkey = (writable) ? fdata->rw_rkey : ZHPE_UNUSED_RKEY;
    pte.v = valid;
    va = info->addr;
    ps = BIT_ULL(info->pg->page_grid.page_size);
    length = info->length;
    offset = info->addr - info->addr_aligned;
    for (i = first; i <= last; i++) {
        pte.va = va;
        window_sz = min(ps - offset, length);
        pte.window_sz = window_sz % BIT_ULL(PAGE_GRID_MAX_PAGESIZE);
        debug(DEBUG_ZMMU, "pte[%u]@%px:va=0x%llx, pasid=0x%x, "
              "rke=%u, ro_rkey=0x%x, rw_rkey=0x%x, "
              "window_sz=0x%llx, v=%u\n",
              i, &rspz->pte[i],
              (uint64_t)pte.va, pte.pasid,
              pte.rke, pte.ro_rkey, pte.rw_rkey,
              (uint64_t)pte.window_sz, pte.v);
        iowrite32by(&pte, &rspz->pte[i]);
        va = ROUND_DOWN_PAGE(va, ps) + ps;
        length -= (ps - offset);
        offset = 0;
    }

    if (sync)  /* ensure visibility */
        ioread32by(&tmp, &rspz->pte[first]);
}

static uint64_t zmmu_base_addr_insert(struct page_grid_info *pgi, uint pg_index)
{
    struct rb_root *root = &pgi->base_addr_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct sw_page_grid *node = &pgi->pg[pg_index];
    int result;

    /* caller must hold bridge zmmu lock */

    /* figure out where to put new node */
    while (*new) {
        struct sw_page_grid *this =
            container_of(*new, struct sw_page_grid, base_addr_node);

        result = arithcmp(node->page_grid.base_addr, this->page_grid.base_addr);
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else  /* already there */
            return BASE_ADDR_ERROR;
    }

    /* add new node and rebalance tree */
    rb_link_node(&node->base_addr_node, parent, new);
    rb_insert_color(&node->base_addr_node, root);
    return 0;
}

static int zmmu_base_pte_insert(struct page_grid_info *pgi, uint pg_index)
{
    struct rb_root *root = &pgi->base_pte_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct sw_page_grid *node = &pgi->pg[pg_index];

    /* caller must hold bridge zmmu lock */

    /* figure out where to put new node */
    while (*new) {
        struct sw_page_grid *this =
            container_of(*new, struct sw_page_grid, base_pte_node);
        int result = arithcmp(node->page_grid.base_pte_idx,
                              this->page_grid.base_pte_idx);

        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else  /* already there */
            return -EEXIST;
    }

    /* add new node and rebalance tree */
    rb_link_node(&node->base_pte_node, parent, new);
    rb_insert_color(&node->base_pte_node, root);
    return 0;
}

static int zmmu_find_addr_range(struct page_grid_info *pgi, uint pg_index)
{
    struct sw_page_grid *pg;
    struct rb_node *rb;
    bool cpu_visible    = pgi->pg[pg_index].cpu_visible;
    uint64_t page_count = pgi->pg[pg_index].page_grid.page_count;
    uint64_t page_size  = BIT_ULL(pgi->pg[pg_index].page_grid.page_size);
    uint64_t range      = page_size * page_count;
    uint64_t min_addr   = (cpu_visible ?
                           ROUND_UP_PAGE(zhpe_reqz_min_cpuvisible_addr,
                                         page_size) :
                           REQZ_MIN_NONVISIBLE_ADDR);
    uint64_t max_addr   = (cpu_visible ? zhpe_reqz_max_cpuvisible_addr :
                           REQZ_MAX_NONVISIBLE_ADDR);
    uint64_t ret        = BASE_ADDR_ERROR;
    uint64_t base_addr, next_addr;
    uint64_t prev_base = 0; /* Revisit: debug */

    /* caller must hold bridge zmmu lock */

    debug(DEBUG_ZMMU, "pg[%d]:page_size=%llu, "
          "page_count=%llu, cpu_visible=%d, min_addr=0x%llx, max_addr=0x%llx\n",
          pg_index, page_size, page_count, cpu_visible, min_addr, max_addr);

    for (rb = rb_first(&pgi->base_addr_tree); rb; rb = rb_next(rb)) {
        pg = container_of(rb, struct sw_page_grid, base_addr_node);
        if (pg->page_grid.base_addr < prev_base)  /* Revisit: debug */

            debug(DEBUG_ZMMU, "base_addr out of order (0x%llx < 0x%llx)\n",
                  pg->page_grid.base_addr, prev_base);
        prev_base = pg->page_grid.base_addr;
        base_addr = ROUND_DOWN_PAGE(pg->page_grid.base_addr, page_size);
        next_addr = ROUND_UP_PAGE(pg->page_grid.base_addr +
                                  (pg->page_grid.page_count *
                                   BIT_ULL(pg->page_grid.page_size)),
                                  page_size);
        debug(DEBUG_ZMMU, "pg[0x%llx*%u@0x%llx]:base_addr=0x%llx, "
              "next_addr=0x%llx\n", BIT_ULL(pg->page_grid.page_size),
              pg->page_grid.page_count, pg->page_grid.base_addr,
              base_addr, next_addr);
        if (base_addr < min_addr) {
            if (min_addr < next_addr)
                min_addr = next_addr;
            continue;
        } else if ((base_addr - min_addr) >= range) { /* range below pg works */
            max_addr = base_addr - 1;
            break;
        } else {
            min_addr = next_addr;
        }
    }

    if ((max_addr - min_addr + 1) >= range) {  /* found a range */
        /* set base_addr */
        pgi->pg[pg_index].page_grid.base_addr = min_addr;
        /* add sw_pg to rbtree */
        ret = zmmu_base_addr_insert(pgi, pg_index);
        if (ret == 0)
            ret = min_addr;
    }

    return ret;
}

static int zmmu_find_pg_pte_range(struct page_grid_info *pgi, uint pg_index)
{
    struct sw_page_grid *pg;
    struct rb_node *rb;
    uint page_count = pgi->pg[pg_index].page_grid.page_count;
    uint min_pte = 0, max_pte = pgi->pte_entries - 1, end_pte;
    int ret = -ENOSPC;

    /* caller must hold bridge zmmu lock */

    for (rb = rb_last(&pgi->base_pte_tree); rb; rb = rb_prev(rb)) {
        pg = container_of(rb, struct sw_page_grid, base_pte_node);
        end_pte = pg->page_grid.base_pte_idx + pg->page_grid.page_count - 1;
        if ((max_pte - end_pte) >= page_count) {  /* range above pg works */
            min_pte = end_pte + 1;
            break;
        } else {
            max_pte = pg->page_grid.base_pte_idx - 1;
        }
    }

    if ((max_pte - min_pte + 1) >= page_count) {  /* found a range */
        /* set base_pte_idx */
        pgi->pg[pg_index].page_grid.base_pte_idx = min_pte;
        /* add sw_pg to rbtree */
        ret = zmmu_base_pte_insert(pgi, pg_index);
        if (ret == 0)
            ret = min_pte;
    }

    return ret;
}

static struct sw_page_grid *zmmu_pg_pte_search(struct page_grid_info *pgi,
                                               uint pg_index)
{
    struct sw_page_grid *pg;
    struct rb_node *node;
    struct rb_root *root = &pgi->base_pte_tree;
    uint pte_index = pgi->pg[pg_index].page_grid.base_pte_idx;

    /* caller must hold bridge zmmu lock */
    node = root->rb_node;

    while (node) {
        int result;

        pg = container_of(node, struct sw_page_grid, base_pte_node);
        result = arithcmp(pte_index, pg->page_grid.base_pte_idx);
        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return pg;
    }

    return NULL;
}

static void zmmu_free_pg_pte_range(struct page_grid_info *pgi, uint pg_index)
{
    struct sw_page_grid *pg;

    /* caller must hold bridge zmmu lock */
    pg = zmmu_pg_pte_search(pgi, pg_index);
    rb_erase(&pg->base_pte_node, &pgi->base_pte_tree);
    pgi->pg[pg_index].page_grid.page_count = 0;
}

static struct sw_page_grid *zmmu_pg_addr_search(struct page_grid_info *pgi,
                                                uint pg_index)
{
    struct sw_page_grid *pg;
    struct rb_node *node;
    struct rb_root *root = &pgi->base_addr_tree;
    uint64_t base_addr = pgi->pg[pg_index].page_grid.base_addr;

    /* caller must hold bridge zmmu lock */
    node = root->rb_node;

    while (node) {
        int result;

        pg = container_of(node, struct sw_page_grid, base_addr_node);
        result = arithcmp(base_addr, pg->page_grid.base_addr);
        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return pg;
    }

    return NULL;
}

static void zmmu_free_pg_addr_range(struct page_grid_info *pgi, uint pg_index)
{
    struct sw_page_grid *pg;

    /* caller must hold bridge zmmu lock */
    pg = zmmu_pg_addr_search(pgi, pg_index);
    rb_erase(&pg->base_addr_node, &pgi->base_addr_tree);
    pgi->pg[pg_index].page_grid.base_addr = 0;
}

static void _zmmu_req_page_grid_write_slice(struct slice *sl,
                                            struct sw_page_grid sw_pg[],
                                            uint pg_index, bool sync)
{
    struct req_zmmu *reqz;
    struct page_grid tmp;

    /* don't call this function, as it only does
     * one slice - use zmmu_req_page_grid_alloc() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock(&sl->zmmu_lock);
    reqz = &sl->bar->req_zmmu;

    /* write HW page grid */
    iowrite16by(&sw_pg[pg_index].page_grid, &reqz->page_grid[pg_index]);
    if (sync)  /* ensure visibility */
        ioread16by(&tmp, &reqz->page_grid[pg_index]);

    spin_unlock(&sl->zmmu_lock);
}

int zhpe_zmmu_req_page_grid_alloc(struct bridge *br,
                                  struct sw_page_grid *sw_pg)
{
    int pg_index, sl, pte_index, err;
    uint64_t base_addr;
    unsigned long key;

    /* allocates memory and may sleep */
    err = radix_tree_preload(GFP_KERNEL);
    if (err < 0)
        goto out;

    spin_lock(&br->zmmu_lock);
    /* find & allocate a free page grid */
    pg_index = bitmap_find_free_region(br->req_zmmu_pg.pg_bitmap,
                                       PAGE_GRID_ENTRIES, 0);
    if (pg_index < 0) {
        err = pg_index;
        goto unlock;
    }

    /* we assume caller has already checked validity of sw_pg */
    br->req_zmmu_pg.pg[pg_index] = *sw_pg;
    br->req_zmmu_pg.pg[pg_index].pte_tree = RB_ROOT;
    /* find & allocate free PTE range */
    pte_index = zmmu_find_pg_pte_range(&br->req_zmmu_pg, pg_index);
    if (pte_index < 0) {
        err = pte_index;
        goto clear;
    }
    /* find & allocate free phys addr range */
    base_addr = zmmu_find_addr_range(&br->req_zmmu_pg, pg_index);
    if (base_addr == BASE_ADDR_ERROR) {
        err = -ENOSPC;
        goto free_pte;
    }

    set_bit(sw_pg->page_grid.page_size,
            (sw_pg->cpu_visible) ? br->req_zmmu_pg.pg_cpu_visible_ps_bitmap :
            br->req_zmmu_pg.pg_non_visible_ps_bitmap);
    key = sw_pg->page_grid.page_size +
        ((sw_pg->cpu_visible) ? PAGE_GRID_MAX_PAGESIZE : 0);
    err = radix_tree_insert(&br->req_zmmu_pg.pg_pagesize_tree,
                            key, &br->req_zmmu_pg.pg[pg_index]);
    if (err < 0)
        goto free_addr;
    spin_unlock(&br->zmmu_lock);
    radix_tree_preload_end();

    /* write all requester ZMMU slices */
    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_req_page_grid_write_slice(&br->slice[sl],
                                        br->req_zmmu_pg.pg,
                                        pg_index, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();

    debug(DEBUG_ZMMU, "pg[%d]:addr=0x%llx-0x%llx, page_size=%u, "
          "page_count=%u, base_pte_idx=%u, cpu_visible=%d\n", pg_index,
          br->req_zmmu_pg.pg[pg_index].page_grid.base_addr,
          br->req_zmmu_pg.pg[pg_index].page_grid.base_addr +
          (BIT_ULL(br->req_zmmu_pg.pg[pg_index].page_grid.page_size) *
           br->req_zmmu_pg.pg[pg_index].page_grid.page_count) - 1,
          br->req_zmmu_pg.pg[pg_index].page_grid.page_size,
          br->req_zmmu_pg.pg[pg_index].page_grid.page_count,
          br->req_zmmu_pg.pg[pg_index].page_grid.base_pte_idx,
          br->req_zmmu_pg.pg[pg_index].cpu_visible);

    return pg_index;

 free_addr:
    zmmu_free_pg_addr_range(&br->req_zmmu_pg, pg_index);

 free_pte:
    zmmu_free_pg_pte_range(&br->req_zmmu_pg, pg_index);

 clear:
    bitmap_clear(br->req_zmmu_pg.pg_bitmap, pg_index, 1);

 unlock:
    spin_unlock(&br->zmmu_lock);
    radix_tree_preload_end();

 out:
    return err;
}

static void _zmmu_rsp_page_grid_write_slice(struct slice *sl,
                                            struct sw_page_grid sw_pg[],
                                            uint pg_index, bool sync)
{
    struct rsp_zmmu *rspz;
    struct page_grid tmp;

    /* don't call this function, as it only does
     * one slice - use zmmu_rsp_page_grid_alloc() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock(&sl->zmmu_lock);
    rspz = &sl->bar->rsp_zmmu;

    /* write HW page grid */
    iowrite16by(&sw_pg[pg_index].page_grid, &rspz->page_grid[pg_index]);
    if (sync)  /* ensure visibility */
        ioread16by(&tmp, &rspz->page_grid[pg_index]);

    spin_unlock(&sl->zmmu_lock);
}

int zhpe_zmmu_rsp_page_grid_alloc(struct bridge *br,
                                  struct sw_page_grid *sw_pg)
{
    int pg_index, sl, pte_index, err;
    uint64_t base_addr;

    /* allocates memory and may sleep */
    err = radix_tree_preload(GFP_KERNEL);
    if (err < 0)
        goto out;

    spin_lock(&br->zmmu_lock);
    /* find & allocate a free page grid */
    pg_index = bitmap_find_free_region(br->rsp_zmmu_pg.pg_bitmap,
                                       PAGE_GRID_ENTRIES, 0);
    if (pg_index < 0) {
        err = pg_index;
        goto unlock;
    }

    /* cpu_visible does not apply to responder ZMMU */
    sw_pg->cpu_visible = 0;
    /* we assume caller has already checked validity of sw_pg */
    br->rsp_zmmu_pg.pg[pg_index] = *sw_pg;
    br->rsp_zmmu_pg.pg[pg_index].pte_tree = RB_ROOT;
    /* find & allocate free PTE range */
    pte_index = zmmu_find_pg_pte_range(&br->rsp_zmmu_pg, pg_index);
    if (pte_index < 0) {
        err = pte_index;
        goto clear;
    }
    /* find & allocate free zaddr range */
    base_addr = zmmu_find_addr_range(&br->rsp_zmmu_pg, pg_index);
    if (base_addr == BASE_ADDR_ERROR) {
        ; /* Revisit: handle "no free zaddr range" error */
    }

    set_bit(sw_pg->page_grid.page_size,
            br->rsp_zmmu_pg.pg_non_visible_ps_bitmap);
    err = radix_tree_insert(&br->rsp_zmmu_pg.pg_pagesize_tree,
                            sw_pg->page_grid.page_size,
                            &br->rsp_zmmu_pg.pg[pg_index]);
    if (err < 0)
        goto clear;
    spin_unlock(&br->zmmu_lock);
    radix_tree_preload_end();

    /* write all responder ZMMU slices */
    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_rsp_page_grid_write_slice(&br->slice[sl],
                                        br->rsp_zmmu_pg.pg,
                                        pg_index, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();

    debug(DEBUG_ZMMU, "pg[%d]:addr=0x%llx-0x%llx, page_size=%u, "
          "page_count=%u, base_pte_idx=%u\n", pg_index,
          br->rsp_zmmu_pg.pg[pg_index].page_grid.base_addr,
          br->rsp_zmmu_pg.pg[pg_index].page_grid.base_addr +
          (BIT_ULL(br->rsp_zmmu_pg.pg[pg_index].page_grid.page_size) *
           br->rsp_zmmu_pg.pg[pg_index].page_grid.page_count) - 1,
          br->rsp_zmmu_pg.pg[pg_index].page_grid.page_size,
          br->rsp_zmmu_pg.pg[pg_index].page_grid.page_count,
          br->rsp_zmmu_pg.pg[pg_index].page_grid.base_pte_idx);

    return pg_index;

 clear:
    bitmap_clear(br->rsp_zmmu_pg.pg_bitmap, pg_index, 1);

 unlock:
    spin_unlock(&br->zmmu_lock);
    radix_tree_preload_end();

 out:
    return err;
}

uint64_t zhpe_zmmu_pte_addr(const struct zhpe_pte_info *info)
{
    uint64_t base_addr, ps, pte_off;
    struct sw_page_grid *pg = info->pg;

    if (!pg)
        return BASE_ADDR_ERROR;

    base_addr = pg->page_grid.base_addr;
    ps = BIT_ULL(pg->page_grid.page_size);
    pte_off = info->pte_index - pg->page_grid.base_pte_idx;
    debug(DEBUG_ZMMU, "b/p/s/o/r 0x%llx /0x%llx/0x%llx/0x%llx/0x%llx\n",
          base_addr, pte_off, ps, pte_off * ps,
          (info->addr - info->addr_aligned));
    return base_addr + (pte_off * ps) + (info->addr - info->addr_aligned);
}

static struct sw_page_grid *zmmu_pg_page_size(struct zhpe_pte_info *info,
                                              struct page_grid_info *pgi)
{
    uint64_t addr_aligned, length_adjusted;
    struct sw_page_grid *sw_pg;
    int ps;
    unsigned long key;
    bool cpu_visible = !!(info->access & ZHPE_MR_REQ_CPU);

    /* Revisit: make this more general */
    length_adjusted = roundup_pow_of_two(info->length);
    addr_aligned = ROUND_DOWN_PAGE(info->addr, length_adjusted);
    if (addr_aligned != info->addr)
        length_adjusted <<= 1;
    ps = clamp(ilog2(length_adjusted),
               PAGE_GRID_MIN_PAGESIZE, PAGE_GRID_MAX_PAGESIZE);
    /* Try to find a page that fits the length. */
    ps = find_next_bit((cpu_visible ? pgi->pg_cpu_visible_ps_bitmap :
                        pgi->pg_non_visible_ps_bitmap), PAGE_GRID_PS_BITS, ps);
    /* If that fails, then the largest available. */
    if (ps == PAGE_GRID_PS_BITS)
        ps = find_last_bit((cpu_visible ? pgi->pg_cpu_visible_ps_bitmap :
                            pgi->pg_non_visible_ps_bitmap), PAGE_GRID_PS_BITS);
    key = ps + (cpu_visible ? PAGE_GRID_MAX_PAGESIZE : 0);
    sw_pg = radix_tree_lookup(&pgi->pg_pagesize_tree, key);

    if (sw_pg) {
        addr_aligned = ROUND_DOWN_PAGE(info->addr, BIT_ULL(ps));
        info->addr_aligned = addr_aligned;
        info->zmmu_pages = ROUND_UP_PAGE(
            info->length + (info->addr - addr_aligned), BIT_ULL(ps)) >> ps;
        info->length_adjusted = info->zmmu_pages * BIT_ULL(ps);
        zhpe_pte_info_dbg(DEBUG_ZMMU, __func__, __LINE__, info);
        debug(DEBUG_ZMMU, "page_size=%d, sw_pg=%px\n", ps, sw_pg);
    } else {
        ps = -ENOSPC;
    }

    return (ps < 0) ? ERR_PTR(ps) : sw_pg;
}

static int zmmu_pte_insert(struct zhpe_pte_info *info, struct sw_page_grid *pg)
{
    struct rb_root *root = &pg->pte_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;

    /* caller must hold bridge zmmu lock */

    /* figure out where to put new node */
    while (*new) {
        struct zhpe_pte_info *this =
            container_of(*new, struct zhpe_pte_info, node);
        int result = arithcmp(info->pte_index, this->pte_index);

        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else  /* already there */
            return -EEXIST;
    }

    /* add new node and rebalance tree */
    rb_link_node(&info->node, parent, new);
    rb_insert_color(&info->node, root);
    info->pg = pg;
    return 0;
}

static void zmmu_pte_erase(struct zhpe_pte_info *info)
{
    /* caller must hold bridge zmmu lock */
    if (info->pg != NULL) {
        rb_erase(&info->node, &info->pg->pte_tree);
        info->pg = NULL;
    }
}

static int zmmu_find_pte_range(struct zhpe_pte_info *info,
                               struct sw_page_grid *pg)
{
    struct rb_node *rb;
    struct zhpe_pte_info *this;
    uint page_count = info->zmmu_pages;
    uint min_pte = pg->page_grid.base_pte_idx;
    uint max_pte = min_pte + pg->page_grid.page_count - 1;
    uint end_pte;
    int ret = -ENOSPC;

    /* caller must hold bridge zmmu lock */

    for (rb = rb_last(&pg->pte_tree); rb; rb = rb_prev(rb)) {
        this = container_of(rb, struct zhpe_pte_info, node);
        end_pte = this->pte_index + this->zmmu_pages - 1;
        if ((max_pte - end_pte) >= page_count) {  /* range above this works */
            min_pte = end_pte + 1;
            break;
        } else {
            max_pte = this->pte_index - 1;
        }
    }

    if ((max_pte - min_pte + 1) >= page_count) {  /* found a range */
        /* set pte_index */
        info->pte_index = min_pte;
        /* add info to rbtree */
        ret = zmmu_pte_insert(info, pg);
        if (ret == 0)
            ret = min_pte;
    }

    debug(DEBUG_ZMMU, "ret=%d, addr=0x%llx\n", ret, info->addr);
    return ret;
}

static void _zmmu_req_pte_write_slice(struct slice *sl,
                                      struct zhpe_rmr *rmr,
                                      bool valid,
                                      bool sync)
{
    struct req_zmmu *reqz;

    /* don't call this function, as it only does
     * one slice - use zhpe_zmmu_req_pte_alloc() or
     * zhpe_zmmu_req_pte_free() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock(&sl->zmmu_lock);
    reqz = &sl->bar->req_zmmu;

    /* write HW PTEs */
    zmmu_req_pte_write(rmr, reqz, valid, sync);

    spin_unlock(&sl->zmmu_lock);
}

int zhpe_zmmu_req_pte_alloc(struct zhpe_rmr *rmr, uint64_t *req_addr,
                            uint32_t *pg_ps)
{
    struct zhpe_pte_info  *info = rmr->pte_info;
    struct bridge         *br = rmr->fdata->bridge;
    struct page_grid_info *pgi = &br->req_zmmu_pg;
    struct sw_page_grid   *sw_pg;
    struct rb_node        *rb;
    uint                  sl;
    int                   ret;
    struct zhpe_pte_info *this;

    spin_lock(&br->zmmu_lock);
    sw_pg = zmmu_pg_page_size(info, pgi);
    if (IS_ERR(sw_pg)) {
        ret = PTR_ERR(sw_pg);
        goto unlock;
    }

    /* check if this PTE already exists */
    for (rb = rb_first(&sw_pg->pte_tree); rb; rb = rb_next(rb)) {
        this = container_of(rb, struct zhpe_pte_info, node);
        if (info->dgcid == this->dgcid && info->addr == this->addr) {
            kref_get(&this->refcount);
            rmr->pte_info = this;
            *req_addr = zhpe_zmmu_pte_addr(this);
            *pg_ps = this->pg->page_grid.page_size;
            /* don't write to the slices, but this wasn't really a *failure* */
            ret = 0;
            goto unlock;
        }
    }

    ret = zmmu_find_pte_range(info, sw_pg);
    if (ret < 0)
        goto unlock;

    kref_init(&info->refcount);

    *req_addr = zhpe_zmmu_pte_addr(info);
    *pg_ps = sw_pg->page_grid.page_size;
    spin_unlock(&br->zmmu_lock);
    debug(DEBUG_ZMMU, "pte_index=%u, zmmu_pages=%u, pg_ps=%u\n",
          info->pte_index, info->zmmu_pages, *pg_ps);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_req_pte_write_slice(&br->slice[sl], rmr, VALID, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();
    return 0;

 unlock:
    spin_unlock(&br->zmmu_lock);

    debug(DEBUG_ZMMU, "ret=%d, addr=0x%llx\n", ret, info->addr);
    do_kfree(info); /* was allocated in RMR_IMPORT */

    return ret;
}

static void zhpe_commit_invalidate(void *dummy)
{
    wbinvd();
    if (zhpe_mcommit)
        mcommit();
}

static void _empty_destructor(struct kref *ref)
{
}

void zhpe_zmmu_req_pte_free(struct zhpe_rmr *rmr)
{
    struct zhpe_pte_info  *info = rmr->pte_info;
    struct bridge         *br = rmr->fdata->bridge;
    bool                  cpu_visible = !!(info->access & ZHPE_MR_REQ_CPU);
    uint                  sl;

    debug(DEBUG_ZMMU,
          "info %px kref %u cpu_visible %d pte_index=%u, zmmu_pages=%u\n",
          info, kref_read(&info->refcount), cpu_visible,
          info->pte_index, info->zmmu_pages);

    if (kref_put(&info->refcount, _empty_destructor)) {
        if (cpu_visible)
            on_each_cpu(zhpe_commit_invalidate, NULL, 1);
        if (!zhpe_no_avx)
            kernel_fpu_begin();
        for (sl = 0; sl < SLICES; sl++)
            _zmmu_req_pte_write_slice(&br->slice[sl], rmr, INVALID, NO_SYNC);
        if (!zhpe_no_avx)
            kernel_fpu_end();

        spin_lock(&br->zmmu_lock);
        zmmu_pte_erase(info);
        spin_unlock(&br->zmmu_lock);

        do_kfree(info);
    }
}

static void _zmmu_rsp_pte_write_slice(struct slice *sl,
                                      struct zhpe_pte_info *info,
                                      bool valid,
                                      bool sync)
{
    struct rsp_zmmu *rspz;

    /* don't call this function, as it only does
     * one slice - use zhpe_zmmu_rsp_pte_alloc() or
     * zhpe_zmmu_rsp_pte_free() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock(&sl->zmmu_lock);
    rspz = &sl->bar->rsp_zmmu;

    /* write HW PTEs */
    zmmu_rsp_pte_write(info, rspz, valid, sync);

    spin_unlock(&sl->zmmu_lock);
}

int zhpe_zmmu_rsp_pte_alloc(struct zhpe_pte_info *info, uint64_t *rsp_zaddr,
                            uint32_t *pg_ps)
{
    struct bridge         *br =
        container_of(info, struct zhpe_umem, pte_info)->fdata->bridge;
    struct page_grid_info *pgi = &br->rsp_zmmu_pg;
    struct sw_page_grid   *sw_pg;
    uint                  sl;
    int                   ret;

    spin_lock(&br->zmmu_lock);
    sw_pg = zmmu_pg_page_size(info, pgi);
    if (IS_ERR(sw_pg)) {
        ret = PTR_ERR(sw_pg);
        goto unlock;
    }

    ret = zmmu_find_pte_range(info, sw_pg);
    if (ret < 0)
        goto unlock;

    *rsp_zaddr = zhpe_zmmu_pte_addr(info);
    *pg_ps = sw_pg->page_grid.page_size;
    spin_unlock(&br->zmmu_lock);
    debug(DEBUG_ZMMU, "pte_index=%u, zmmu_pages=%u\n",
          info->pte_index, info->zmmu_pages);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_rsp_pte_write_slice(&br->slice[sl], info, VALID, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();
    return 0;

 unlock:
    spin_unlock(&br->zmmu_lock);

    debug(DEBUG_ZMMU, "ret=%d, addr=0x%llx\n", ret, info->addr);
    return ret;
}

void zhpe_zmmu_rsp_take_snapshot(struct bridge *br)
{
    uint                  sl;
    struct rsp_zmmu       *rspz;
    int                   slice_mask = ALL_SLICES;
    int                   cur_mask;
    int                   cur_snap;
    int                   first_snap[SLICES];

    if (zhpe_platform == ZHPE_CARBON)
        return;

    for (sl = 0; sl < SLICES; sl++) {
        if (!SLICE_VALID(&br->slice[sl])) {
            slice_mask &= ~(1 << sl);
            continue;
        }
        rspz = &br->slice[sl].bar->rsp_zmmu;
        first_snap[sl] = ioread64(&rspz->take_snapshot);
        debug(DEBUG_ZMMU, "sl %d snap %d\n",
              sl, first_snap[sl] & RSP_TAKE_SNAPSHOT_MASK);
    }
    while (slice_mask) {
        cur_mask = slice_mask;
        for (sl = ffs(cur_mask); sl ; sl = ffs(cur_mask)) {
            sl--;
            rspz = &br->slice[sl].bar->rsp_zmmu;
            cur_snap = ioread64(&rspz->take_snapshot);
            debug(DEBUG_ZMMU, "sl %d snap %d\n",
                  sl, cur_snap & RSP_TAKE_SNAPSHOT_MASK);
            cur_mask &= ~(1 << sl);
            if (((cur_snap - first_snap[sl]) & RSP_TAKE_SNAPSHOT_MASK) >= 2)
                slice_mask &= ~(1 << sl);
        }
    }
}

void zhpe_zmmu_rsp_pte_free(struct zhpe_pte_info *info)
{
    struct bridge         *br =
        container_of(info, struct zhpe_umem, pte_info)->fdata->bridge;
    uint                  sl;

    debug(DEBUG_ZMMU, "pte_index=%u, zmmu_pages=%u\n",
          info->pte_index, info->zmmu_pages);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_rsp_pte_write_slice(&br->slice[sl], info, INVALID, NO_SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();

    spin_lock(&br->zmmu_lock);
    zmmu_pte_erase(info);
    spin_unlock(&br->zmmu_lock);
}

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

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/hugetlb.h>
#include <linux/sched/signal.h>
#include <zhpe.h>
#include <zhpe_driver.h>

static void umem_free(struct kref *ref);  /* forward reference */

static inline int umem_cmp(uint64_t vaddr, uint64_t length, uint64_t access,
                           const struct zhpe_umem *u)
{
    int cmp;
    const struct zhpe_pte_info *info = &u->pte_info;

    cmp = arithcmp(vaddr, u->vaddr);
    if (cmp)
        return cmp;
    cmp = arithcmp(length, info->length);
    if (cmp)
        return cmp;
    return arithcmp(access, info->access);
}

static struct zhpe_umem *umem_search(struct file_data *fdata,
                                     uint64_t vaddr, uint64_t length,
                                     uint64_t access, uint64_t rsp_zaddr)
{
    struct zhpe_umem *unode;
    struct rb_node *rnode;
    struct rb_root *root = &fdata->mr_tree;

    /* caller must already hold fdata->mr_lock */
    rnode = root->rb_node;

    while (rnode) {
        int64_t result;

        unode = container_of(rnode, struct zhpe_umem, node);
        result = umem_cmp(vaddr, length, access, unode);
        if (result < 0) {
            rnode = rnode->rb_left;
        } else if (result > 0) {
            rnode = rnode->rb_right;
        } else {
            if (rsp_zaddr == zhpe_zmmu_pte_addr(&unode->pte_info))
                goto out;
            else
                goto fail;
        }
    }

 fail:
    unode = NULL;

 out:
    return unode;
}

static struct zhpe_umem *umem_insert(struct zhpe_umem *umem)
{
    struct zhpe_pte_info *info = &umem->pte_info;
    struct file_data *fdata = info->fdata;
    struct rb_root *root = &fdata->mr_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    ulong flags;

    spin_lock_irqsave(&fdata->mr_lock, flags);

    /* figure out where to put new node */
    while (*new) {
        struct zhpe_umem *this =
            container_of(*new, struct zhpe_umem, node);
        int64_t result = umem_cmp(umem->vaddr, info->length, info->access,
                                  this);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {  /* already there */
            umem = this;
            kref_get(&umem->refcount);
            goto out;
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&umem->node, parent, new);
    rb_insert_color(&umem->node, root);
    umem->erase = true;

 out:
    spin_unlock_irqrestore(&fdata->mr_lock, flags);
    return umem;
}

static inline void umem_remove(struct zhpe_umem *umem)
{
    kref_put(&umem->refcount, umem_free);
}

/* Returns the offset of the umem start relative to the first page */
static inline int zhpe_umem_offset(struct zhpe_umem *umem)
{
    return umem->vaddr & (BIT(umem->page_shift) - 1);
}

/* Returns the first page of a umem */
static inline unsigned long zhpe_umem_start(struct zhpe_umem *umem)
{
    return umem->vaddr - zhpe_umem_offset(umem);
}

/* Returns the address of the page after the last one of a umem */
static inline unsigned long zhpe_umem_end(struct zhpe_umem *umem)
{
    return ALIGN(umem->vaddr + umem->pte_info.length, BIT(umem->page_shift));
}

static inline size_t zhpe_umem_num_pages(struct zhpe_umem *umem)
{
    return (zhpe_umem_end(umem) - zhpe_umem_start(umem)) >> umem->page_shift;
}

/**
 * zhpe_dma_map_sg_attrs - Map a scatter/gather list to DMA addresses
 * @br: The bridge for which the DMA addresses are to be created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 * @dma_attrs: The DMA attributes
 */
static inline int zhpe_dma_map_sg_attrs(struct bridge *br,
                                        struct scatterlist *sg, int nents,
                                        enum dma_data_direction direction,
                                        unsigned long dma_attrs)
{
    int sl, ret = 0;
#ifdef HAVE_RHEL
    struct dma_attrs dattrs = {
        .flags[0] = dma_attrs
    };
    struct dma_attrs *attrs = &dattrs;
#else
    unsigned long attrs = dma_attrs;
#endif


    /* Revisit: add PASID support */
    for (sl = 0; sl < SLICES; sl++) {
        if (!SLICE_VALID(&br->slice[sl]))
            continue;
        ret = dma_map_sg_attrs(&br->slice[sl].pdev->dev, sg, nents,
                               direction, attrs);
        /* Revisit: handle ret > 0 but different amongst the slices? */
        if (ret <= 0) {
            while (--sl >= 0)  /* undo the ones we already did */
                dma_unmap_sg(&br->slice[sl].pdev->dev, sg, nents, direction);
            break;
        }
    }

    return ret;
}

/**
 * zhpe_dma_unmap_sg - Unmap a scatter/gather list of DMA addresses
 * @br: The bridge for which the DMA addresses were created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 */
static inline void zhpe_dma_unmap_sg(struct bridge *br,
                                     struct scatterlist *sg, int nents,
                                     enum dma_data_direction direction)
{
    int sl;

    for (sl = 0; sl < SLICES; sl++)
        if (SLICE_VALID(&br->slice[sl]))
            dma_unmap_sg(&br->slice[sl].pdev->dev, sg, nents, direction);
}

static void _zhpe_umem_release(struct zhpe_umem *umem)
{
    struct file_data   *fdata = umem->pte_info.fdata;
    struct scatterlist *sg;
    struct page        *page;
    int                i;

    if (!umem->need_release)
        return;

    if (umem->nmap > 0)
        zhpe_dma_unmap_sg(fdata->bridge, umem->sg_head.sgl,
                          umem->npages,
                          DMA_BIDIRECTIONAL);

    for_each_sg(umem->sg_head.sgl, sg, umem->npages, i) {
        page = sg_page(sg);
        if (!PageDirty(page) && umem->writable && umem->dirty)
            set_page_dirty_lock(page);
        put_page(page);
    }

    sg_free_table(&umem->sg_head);
    /* No mm if called from process cleanup */
    if (current->mm) {
        /* drop/reacquire spin lock around mmap_sem; umem_free() not called
         * from interrupt level so we don't need flags.
         */
        spin_unlock_irq(&fdata->mr_lock);
        down_write(&current->mm->mmap_sem);
        current->mm->pinned_vm -= umem->npages;
        up_write(&current->mm->mmap_sem);
        spin_lock_irq(&fdata->mr_lock);
    }
}

static inline long
get_user_pages_compat(unsigned long start, unsigned long nr_pages,
		      bool write, bool force, struct page **pages,
		      struct vm_area_struct **vmas)
{
#ifdef HAVE_RHEL
    return get_user_pages(current, current->mm, start, nr_pages,
                          write, force, pages, vmas);
#else
    unsigned int        gup_flags;

    gup_flags = (write ? FOLL_WRITE : 0) | (force ? FOLL_FORCE : 0);

    return get_user_pages(start, nr_pages, gup_flags, pages, vmas);
#endif
}

/**
 * zhpe_umem_get - Pin and DMA map userspace memory.
 *
 * @fdata: userspace context to pin memory for
 * @vaddr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: ZHPE_MR_xxx flags for memory being pinned
 * @dmasync: flush in-flight DMA when the memory region is written
 */
noinline // Revisit: debug
struct zhpe_umem *zhpe_umem_get(struct file_data *fdata, uint64_t vaddr,
                                size_t size, uint64_t access, bool dmasync)
{
    struct zhpe_umem *umem, *found;
    struct zhpe_pte_info *info;
    struct page **page_list;
    struct vm_area_struct **vma_list;
    unsigned long locked;
    unsigned long lock_limit;
    unsigned long cur_base;
    unsigned long offset; /* Revisit: temporary - remove when IOMMU working */
    unsigned long npages;
    int ret;
    int i;
    unsigned long dma_attrs = 0;
    struct scatterlist *sg, *sg_list_start;
    bool first_page = true; /* Revisit: temporary */
    ulong flags;

    if (dmasync)
        dma_attrs |= DMA_ATTR_WRITE_BARRIER;

    /*
     * If the combination of the addr and size requested for this memory
     * region causes an integer overflow, return error.
     */
    if (((vaddr + size) < vaddr) ||
        PAGE_ALIGN(vaddr + size) < (vaddr + size))
        return ERR_PTR(-EINVAL);

    if (!can_do_mlock())
        return ERR_PTR(-EPERM);

    umem = do_kmalloc(sizeof(struct zhpe_umem), GFP_KERNEL, true);
    if (!umem)
        return ERR_PTR(-ENOMEM);

    info = &umem->pte_info;
    info->fdata      = fdata;
    umem->vaddr      = vaddr;
    info->addr       = vaddr;
    info->length     = size;
    info->access     = access;
    info->space_type = GENZ_DATA;  /* the only supported type */
    umem->page_shift = PAGE_SHIFT;
    umem->pid	     = get_task_pid(current, PIDTYPE_PID);
    umem->writable   = !!(access & (ZHPE_MR_GET|ZHPE_MR_PUT_REMOTE));
    /* We assume the memory is from hugetlb until proven otherwise */
    umem->hugetlb    = 1;
    kref_init(&umem->refcount);

    debug(DEBUG_MEMREG, "%s:%s,%u:vaddr = 0x%016llx, "
          "size = 0x%zx, access = 0x%llx\n",
          zhpe_driver_name, __func__, __LINE__, vaddr,
          size, access);

    found = umem_insert(umem);
    if (found != umem) {
        put_pid(umem->pid);
        /* Undo the kref_get() for a duplicate umem from umem_insert(). */
        kref_put(&umem->refcount, umem_free);
        do_kfree(umem);
        return ERR_PTR(-EEXIST);
    }

    page_list = (struct page **)do__get_free_page(GFP_KERNEL, false);
    if (!page_list) {
        put_pid(umem->pid);
        do_kfree(umem);
        debug(DEBUG_MEMREG, "%s:%s,%u:failed to allocate page_list\n",
              zhpe_driver_name, __func__, __LINE__);
        return ERR_PTR(-ENOMEM);
    }

    /*
     * if we can't alloc the vma_list, it's not so bad;
     * just assume the memory is not hugetlb memory
     */
    vma_list = (struct vm_area_struct **)do__get_free_page(GFP_KERNEL, false);
    if (!vma_list)
        umem->hugetlb = 0;

    npages = zhpe_umem_num_pages(umem);

    down_write(&current->mm->mmap_sem);

    locked     = npages + current->mm->pinned_vm;
    lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

    if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
        ret = -ENOMEM;
        debug(DEBUG_MEMREG, "%s:%s,%u:locked (%lu) > lock_limit (%lu)\n",
              zhpe_driver_name, __func__, __LINE__,
              locked, lock_limit);
        goto out;
    }

    cur_base = vaddr & PAGE_MASK;

    if (npages == 0 || npages > UINT_MAX) {
        ret = -EINVAL;
        debug(DEBUG_MEMREG, "%s:%s,%u:invalid npages (%lu)\n",
              zhpe_driver_name, __func__, __LINE__,
              npages);
        goto out;
    }

    ret = sg_alloc_table(&umem->sg_head, npages, GFP_KERNEL);
    if (ret) {
        debug(DEBUG_MEMREG, "%s:%s,%u:sg_alloc_table failed\n",
              zhpe_driver_name, __func__, __LINE__);
        goto out;
    }

    umem->need_release = true;
    sg_list_start = umem->sg_head.sgl;

    while (npages) {
        /* Revisit: new code shouldn't call get_user_pages */
        ret = get_user_pages_compat(cur_base,
                                    min_t(unsigned long, npages,
                                          PAGE_SIZE / sizeof (struct page *)),
                                    true, !umem->writable, page_list, vma_list);
        if (ret < 0) {
            debug(DEBUG_MEMREG, "%s:%s,%u:get_user_pages(0x%lx, %lu) failed\n",
                  zhpe_driver_name, __func__, __LINE__,
                  cur_base, npages);
            goto out;
        }

        umem->npages += ret;
        current->mm->pinned_vm += ret;
        cur_base += ret * PAGE_SIZE;
        npages   -= ret;

        for_each_sg(sg_list_start, sg, ret, i) {
            if (vma_list && !is_vm_hugetlb_page(vma_list[i]))
                umem->hugetlb = 0;

            sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
            /* Revisit: temporary - remove when IOMMU is working */
            if (first_page) {
                if (vma_list)
                    offset = vaddr & (vma_kernel_pagesize(vma_list[i]) - 1);
                else
                    offset = vaddr & ~PAGE_MASK;
                umem->physaddr = PFN_PHYS(page_to_pfn(page_list[i])) | offset;
                if (no_iommu)
                    info->addr = umem->physaddr;
                first_page = false;
            }
        }

        /* preparing for next loop */
        sg_list_start = sg;
    }

    /* Revisit: set DMA direction based on access flags? */
    umem->nmap = zhpe_dma_map_sg_attrs(fdata->bridge,
                                       umem->sg_head.sgl,
                                       umem->npages,
                                       DMA_BIDIRECTIONAL,
                                       dma_attrs);
    if (umem->nmap <= 0) {
        ret = -ENOMEM;
        debug(DEBUG_MEMREG, "%s:%s,%u:zhpe_dma_map_sg_attrs failed\n",
              zhpe_driver_name, __func__, __LINE__);
        goto out;
    }

    ret = 0;

 out:
    up_write(&current->mm->mmap_sem);
    if (ret < 0) {
        spin_lock_irqsave(&fdata->mr_lock, flags);
        umem_remove(umem);
        spin_unlock_irqrestore(&fdata->mr_lock, flags);
    } else
        umem->dirty = true;

    if (vma_list)
        do_free_page(vma_list);
    do_free_page(page_list);

    return ret < 0 ? ERR_PTR(ret) : umem;
}

static void umem_free(struct kref *ref)
{
    /* caller must already hold fdata->mr_lock */
    struct zhpe_umem *umem = container_of(ref, struct zhpe_umem, refcount);
    struct zhpe_pte_info *info = &umem->pte_info;
    struct file_data *fdata = info->fdata;
    struct rb_root   *root = &fdata->mr_tree;
    uint64_t         access;
    bool             local, remote, cpu_visible, individual;

    access = info->access;
    local = !!(access & (ZHPE_MR_GET|ZHPE_MR_PUT));
    remote = !!(access & (ZHPE_MR_GET_REMOTE|ZHPE_MR_PUT_REMOTE));
    cpu_visible = !!(access & ZHPE_MR_REQ_CPU);
    individual = !!(access & ZHPE_MR_INDIVIDUAL);
    if (remote) {
        if (individual) {
            zhpe_zmmu_rsp_pte_free(info);
            /* Revisit: do TAKE_SNAPSHOT IOMMU teardown seqence */
        }
    }
    if (umem->erase)
        rb_erase(&umem->node, root);
    _zhpe_umem_release(umem);
    put_pid(umem->pid);
    do_kfree(umem);
}

void zhpe_umem_free_all(struct file_data *fdata)
{
    struct rb_node *rb, *next;
    struct zhpe_umem *umem;
    struct zhpe_pte_info *info;
    ulong flags;

    spin_lock_irqsave(&fdata->mr_lock, flags);

    for (rb = rb_first_postorder(&fdata->mr_tree); rb; rb = next) {
        umem = container_of(rb, struct zhpe_umem, node);
        info = &umem->pte_info;
        debug(DEBUG_MEMREG, "%s:%s,%u:vaddr = 0x%016llx, "
              "len = 0x%zx, access = 0x%llx\n",
              zhpe_driver_name, __func__, __LINE__, umem->vaddr,
              info->length, info->access);
        next = rb_next_postorder(rb);  /* must precede umem_free() */
        umem->erase = false;
        umem_free(&umem->refcount);
    }

    fdata->mr_tree = RB_ROOT;

    spin_unlock_irqrestore(&fdata->mr_lock, flags);
}

static inline int rmr_cmp(uint32_t dgcid, uint64_t rsp_zaddr,
                          uint64_t length, uint64_t access,
                          const struct zhpe_rmr *r)
{
    int cmp;
    const struct zhpe_pte_info *info = &r->pte_info;

    cmp = arithcmp(dgcid, r->dgcid);
    if (cmp)
        return cmp;
    cmp = arithcmp(rsp_zaddr, r->rsp_zaddr);
    if (cmp)
        return cmp;
    cmp = arithcmp(length, info->length);
    if (cmp)
        return cmp;
    return arithcmp(access, info->access);
}

static inline int64_t rmr_uu_cmp(uint64_t rsp_zaddr,
                                 uint64_t length, uint64_t access,
                                 struct file_data *fdata,
                                 const struct zhpe_rmr *r)
{
    int cmp;
    const struct zhpe_pte_info *info = &r->pte_info;

    cmp = arithcmp(rsp_zaddr, r->rsp_zaddr);
    if (cmp)
        return cmp;
    cmp = arithcmp(length, info->length);
    if (cmp)
        return cmp;
    cmp = arithcmp(access, info->access);
    if (cmp)
        return cmp;
    return zhpe_uuid_cmp(&fdata->local_uuid->uuid,
                         &info->fdata->local_uuid->uuid);
}

static struct zhpe_rmr *rmr_search(struct file_data *fdata,
                                   uint32_t dgcid, uint64_t rsp_zaddr,
                                   uint64_t length, uint64_t access,
                                   uint64_t req_addr)
{
    struct zhpe_rmr *rmr;
    struct rb_node *rnode;
    struct rb_root *root = &fdata->fd_rmr_tree;

    /* caller must already hold fdata->mr_lock */
    rnode = root->rb_node;

    while (rnode) {
        int64_t result;

        rmr = container_of(rnode, struct zhpe_rmr, fd_node);
        result = rmr_cmp(dgcid, rsp_zaddr, length, access, rmr);
        if (result < 0) {
            rnode = rnode->rb_left;
        } else if (result > 0) {
            rnode = rnode->rb_right;
        } else {
            if (req_addr == zhpe_zmmu_pte_addr(&rmr->pte_info))
                goto out;
            else
                goto fail;
        }
    }

 fail:
    rmr = NULL;

 out:
    return rmr;
}

static struct zhpe_rmr *rmr_insert(struct zhpe_rmr *rmr)
{
    struct zhpe_pte_info *info = &rmr->pte_info;
    struct file_data *fdata = info->fdata;
    struct rb_root *root = &fdata->fd_rmr_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    ulong flags;

    spin_lock_irqsave(&fdata->mr_lock, flags);

    /* figure out where to put new node in fdata->fd_rmr_tree */
    while (*new) {
        struct zhpe_rmr *this =
            container_of(*new, struct zhpe_rmr, fd_node);
        int64_t result = rmr_cmp(rmr->dgcid, rmr->rsp_zaddr,
                                 info->length, info->access, this);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {  /* already there */
            rmr = this;
            kref_get(&rmr->refcount);
            goto unlock;
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&rmr->fd_node, parent, new);
    rb_insert_color(&rmr->fd_node, root);
    rmr->fd_erase = true;
    rmr->un_erase = true;

    /* figure out where to put new node in unode->un_rmr_tree */
    root = &rmr->unode->un_rmr_tree;
    new = &root->rb_node;
    parent = NULL;
    while (*new) {
        struct zhpe_rmr *this =
            container_of(*new, struct zhpe_rmr, un_node);
        int64_t result = rmr_uu_cmp(rmr->rsp_zaddr,
                                    info->length, info->access, fdata, this);

        parent = *new;
        if (result < 0) {
            new = &((*new)->rb_left);
        } else if (result > 0) {
            new = &((*new)->rb_right);
        } else {  /* already there - should never happen */
            goto unlock;
        }
    }

    /* add new node and rebalance tree */
    rb_link_node(&rmr->un_node, parent, new);
    rb_insert_color(&rmr->un_node, root);

 unlock:
    spin_unlock_irqrestore(&fdata->mr_lock, flags);
    return rmr;
}

static void rmr_free(struct kref *ref)
{
    /* caller must already hold fdata->mr_lock */
    struct zhpe_rmr *rmr = container_of(ref, struct zhpe_rmr, refcount);
    struct zhpe_pte_info *info = &rmr->pte_info;
    struct file_data *fdata = info->fdata;
    uint64_t         access;
    bool             cpu_visible, individual;

    access = info->access;
    cpu_visible = !!(access & ZHPE_MR_REQ_CPU);
    individual = !!(access & ZHPE_MR_INDIVIDUAL);
    if (individual) {
        zhpe_zmmu_req_pte_free(rmr);
    }
    if (rmr->fd_erase)
        rb_erase(&rmr->fd_node, &fdata->fd_rmr_tree);
    if (rmr->un_erase) {
        rb_erase(&rmr->un_node, &rmr->unode->un_rmr_tree);
    }
    zhpe_uuid_remove(rmr->uu);  /* remove reference to uu */
    do_kfree(rmr);
}

static inline void rmr_remove(struct zhpe_rmr *rmr, bool lock)
{
    struct file_data *fdata = rmr->pte_info.fdata;
    ulong flags;

    if (lock)
        spin_lock_irqsave(&fdata->mr_lock, flags);
    kref_put(&rmr->refcount, rmr_free);
    if (lock)
        spin_unlock_irqrestore(&fdata->mr_lock, flags);
}

void zhpe_rmr_remove_unode(struct file_data *fdata, struct uuid_node *unode)
{
    struct rb_root *root = &unode->un_rmr_tree;
    struct rb_node *rb, *next;
    struct zhpe_rmr *rmr;
    struct zhpe_pte_info *info;
    ulong flags;
    char str[GCID_STRING_LEN+1];

    spin_lock_irqsave(&fdata->mr_lock, flags);

    for (rb = rb_first_postorder(root); rb; rb = next) {
        rmr = container_of(rb, struct zhpe_rmr, un_node);
        info = &rmr->pte_info;
        debug(DEBUG_MEMREG, "%s:%s,%u:dgcid = %s, rsp_zaddr = 0x%016llx, "
              "len = 0x%zx, access = 0x%llx\n",
              zhpe_driver_name, __func__, __LINE__,
              zhpe_gcid_str(rmr->dgcid, str, sizeof(str)), rmr->rsp_zaddr,
              info->length, info->access);
        next = rb_next_postorder(rb);  /* must precede rmr_free() */
        rmr->fd_erase = true;
        rmr->un_erase = false;
        rmr_free(&rmr->refcount);
    }

    spin_unlock_irqrestore(&fdata->mr_lock, flags);
}

void zhpe_rmr_free_all(struct file_data *fdata)
{
    struct rb_node *rb, *next;
    struct zhpe_rmr *rmr;
    struct zhpe_pte_info *info;
    char str[GCID_STRING_LEN+1];
    ulong flags;

    spin_lock_irqsave(&fdata->mr_lock, flags);

    for (rb = rb_first_postorder(&fdata->fd_rmr_tree); rb; rb = next) {
        rmr = container_of(rb, struct zhpe_rmr, fd_node);
        info = &rmr->pte_info;
        debug(DEBUG_MEMREG, "%s:%s,%u:dgcid = %s, rsp_zaddr = 0x%016llx, "
              "len = 0x%zx, access = 0x%llx\n",
              zhpe_driver_name, __func__, __LINE__,
              zhpe_gcid_str(rmr->dgcid, str, sizeof(str)), rmr->rsp_zaddr,
              info->length, info->access);
        next = rb_next_postorder(rb);  /* must precede rmr_free() */
        rmr->fd_erase = false;
        rmr->un_erase = true;
        rmr_free(&rmr->refcount);
    }

    fdata->fd_rmr_tree = RB_ROOT;

    spin_unlock_irqrestore(&fdata->mr_lock, flags);
}

static struct zmap *rmr_zmap_alloc(struct file_data *fdata,
                                   struct zhpe_rmr *rmr)
{
    union zpages            *zpages;
    struct zmap             *zmap;

    zpages = rmr_zpages_alloc(rmr);
    if (!zpages)
        return ERR_PTR(-ENOMEM);

    zmap = zmap_alloc(fdata, zpages);
    if (IS_ERR(zmap)) {
        zpages_free(zpages);
        goto out;
    }

    rmr->zmap = zmap;
    zmap->owner = fdata;

 out:
    return zmap;
}

/* Revisit: add a "uuid_free_rmr" function */

int zhpe_user_req_MR_REG(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    int                     status = 0;
    uint64_t                vaddr, len, access;
    uint64_t                rsp_zaddr = BASE_ADDR_ERROR;
    uint64_t                physaddr = BASE_ADDR_ERROR;
    uint32_t                pg_ps = 0;
    bool                    local, remote, cpu_visible, individual, dmasync;
    struct zhpe_umem        *umem;

    CHECK_INIT_STATE(entry, status, out);
    vaddr = req->mr_reg.vaddr;
    len = req->mr_reg.len;
    access = req->mr_reg.access;
    local = !!(access & (ZHPE_MR_GET|ZHPE_MR_PUT));
    remote = !!(access & (ZHPE_MR_GET_REMOTE|ZHPE_MR_PUT_REMOTE));
    cpu_visible = !!(access & ZHPE_MR_REQ_CPU);
    individual = !!(access & ZHPE_MR_INDIVIDUAL);
    dmasync = false;  /* Revisit: fix this */

    debug(DEBUG_MEMREG, "%s:%s,%u:vaddr = 0x%016llx, "
          "len = 0x%llx, access = 0x%llx, "
          "local = %u, remote = %u, cpu_visible = %u, individual = %u\n",
          zhpe_driver_name, __func__, __LINE__, vaddr,
          len, access, local, remote, cpu_visible, individual);

    if (!(local || remote) || cpu_visible) {
        status = -EINVAL;
        goto out;
    }

    /* pin memory range and create IOMMU entries */
    umem = zhpe_umem_get(entry->fdata, vaddr, len, access, dmasync);
    if (IS_ERR(umem)) {
        status = PTR_ERR(umem);
        goto out;
    }
    physaddr = umem->physaddr;

    /* create responder ZMMU entries, if necessary */
    if (remote) {
        if (individual) {
            status = zhpe_zmmu_rsp_pte_alloc(&umem->pte_info, &rsp_zaddr,
                                             &pg_ps);
        } else {
            /* make sure a humongous responder ZMMU entry exists */
            ; /* Revisit: finish this */
        }
    }

    rsp->mr_reg.rsp_zaddr = rsp_zaddr;
    rsp->mr_reg.pg_ps = pg_ps;
    rsp->mr_reg.physaddr = physaddr;

 out:
    debug(DEBUG_MEMREG, "%s:%s,%u:ret = %d rsp_zaddr = 0x%016llx, "
          "pg_ps=%u, physaddr = 0x%016llx\n",
          zhpe_driver_name, __func__, __LINE__, status,
          rsp_zaddr, pg_ps, physaddr);
    return queue_io_rsp(entry, sizeof(rsp->mr_reg), status);
}

int zhpe_user_req_MR_FREE(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    int                     status = 0;
    struct zhpe_umem        *umem;
    uint64_t                vaddr, len, access, rsp_zaddr;
    ulong                   flags;

    vaddr = req->mr_free.vaddr;
    len = req->mr_free.len;
    access = req->mr_free.access;
    rsp_zaddr = req->mr_free.rsp_zaddr;
    CHECK_INIT_STATE(entry, status, out);

    spin_lock_irqsave(&entry->fdata->mr_lock, flags);
    umem = umem_search(entry->fdata, vaddr, len, access, rsp_zaddr);
    if (!umem) {
        status = -EINVAL;
        goto unlock;
    }
    umem_remove(umem);

 unlock:
    spin_unlock_irqrestore(&entry->fdata->mr_lock, flags);
 out:
    debug(DEBUG_MEMREG, "%s:%s,%u:ret = %d, vaddr = 0x%016llx, "
          "len = 0x%llx, access = 0x%llx, rsp_zaddr = 0x%016llx\n",
          zhpe_driver_name, __func__, __LINE__, status,
          vaddr, len, access, rsp_zaddr);
    return queue_io_rsp(entry, sizeof(rsp->mr_free), status);
}

int zhpe_user_req_RMR_IMPORT(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    int                     status = 0;
    uuid_t                  *uuid = &req->rmr_import.uuid;
    struct uuid_node        *unode;
    struct uuid_tracker     *uu;
    struct zhpe_rmr         *rmr, *found;
    struct zhpe_pte_info    *info;
    struct zmap             *zmap;
    uint64_t                len, access, rsp_zaddr;
    uint64_t                req_addr = BASE_ADDR_ERROR;
    off_t                   offset = BASE_ADDR_ERROR;
    bool                    remote, cpu_visible, writable, individual, dmasync;
    uint32_t                rkey = 0, pg_ps;
    char                    uustr[UUID_STRING_LEN+1];
    char                    gcstr[GCID_STRING_LEN+1];

    CHECK_INIT_STATE(entry, status, out);
    rsp_zaddr = req->rmr_import.rsp_zaddr;
    len = req->rmr_import.len;
    access = req->rmr_import.access;
    remote = !!(access & (ZHPE_MR_GET_REMOTE|ZHPE_MR_PUT_REMOTE));
    writable = !!(access & ZHPE_MR_PUT_REMOTE);
    cpu_visible = !!(access & ZHPE_MR_REQ_CPU);
    individual = !!(access & ZHPE_MR_INDIVIDUAL);
    dmasync = false;  /* Revisit: fix this */

    debug(DEBUG_MEMREG, "%s:%s,%u:uuid = %s, rsp_zaddr = 0x%016llx, "
          "len = 0x%llx, access = 0x%llx, "
          "remote = %u, writable = %u, cpu_visible = %u, individual = %u\n",
          zhpe_driver_name, __func__, __LINE__,
          zhpe_uuid_str(uuid, uustr, sizeof(uustr)), rsp_zaddr,
          len, access, remote, writable, cpu_visible, individual);

    if (!remote || (zhpe_uuid_is_local(entry->fdata->bridge, uuid) &&
                    !genz_loopback)) {
        status = -EINVAL;  /* only remote access & UUIDs allowed */
        goto out;
    }

    /* Revisit: should there be an rlimit to prevent a user from consuming
     * too much physical address space (RLIMIT_PAS?), similar to "max
     * locked memory" (RLIMIT_MEMLOCK) or "max address space" (RLIMIT_AS)?
     */
    rmr = do_kmalloc(sizeof(struct zhpe_rmr), GFP_KERNEL, true);
    if (!rmr) {
        status = -ENOMEM;
        goto out;
    }
    debug(DEBUG_MEMREG, "%s:%s,%u:rmr = %px\n",
          zhpe_driver_name, __func__, __LINE__, rmr);
    unode = zhpe_remote_uuid_get(entry->fdata, uuid);
    if (!unode) {
        do_kfree(rmr);
        status = -EINVAL;  /* UUID must have been imported */
        goto out;
    }
    /* we now hold a reference to uu */
    uu = unode->tracker;
    if (uu->remote->rkeys_valid)
        rkey = (writable) ? uu->remote->rw_rkey : uu->remote->ro_rkey;
    rmr->rkey        = rkey;
    rmr->rsp_zaddr   = rsp_zaddr;
    rmr->uu          = uu;
    rmr->unode       = unode;
    rmr->dgcid       = zhpe_gcid_from_uuid(uuid);
    rmr->writable    = writable;
    kref_init(&rmr->refcount);
    info             = &rmr->pte_info;
    info->fdata      = entry->fdata;
    info->addr       = rsp_zaddr;
    info->access     = access;
    info->length     = len;
    info->space_type = GENZ_DATA;  /* Revisit: add CONTROL */
    debug(DEBUG_MEMREG, "%s:%s,%u:rmr: info=%px, addr=0x%llx, "
          "dgcid=%s, rkey=0x%x, uu=%px, fdata=%px\n",
          zhpe_driver_name, __func__, __LINE__,
          info, info->addr, zhpe_gcid_str(rmr->dgcid, gcstr, sizeof(gcstr)),
          rmr->rkey, rmr->uu, info->fdata);

    found = rmr_insert(rmr);
    if (found != rmr) {
        zhpe_uuid_remove(uu);  /* release uu reference */
        do_kfree(rmr);
        req_addr = zhpe_zmmu_pte_addr(&found->pte_info);
        goto addr;
    }
    /* create requester ZMMU entries, if necessary */
    if (individual) {
        status = zhpe_zmmu_req_pte_alloc(rmr, &req_addr, &pg_ps);
        if (status < 0) {
	    rmr_remove(rmr, true);
            goto out;
        }
    } else {
        /* make sure a humongous requester ZMMU entry exists */
        ; /* Revisit: finish this */
    }

    if (cpu_visible) {
        zmap = rmr_zmap_alloc(info->fdata, rmr);
        if (IS_ERR(zmap)) {
            rmr_remove(rmr, true);
            status = PTR_ERR(zmap);
            goto out;
        }
        offset = zmap->offset;
    }

 addr:
    rmr->req_addr = req_addr;
    rmr->mmap_pfn = ROUND_DOWN_PAGE(req_addr, BIT_ULL(pg_ps)) >> PAGE_SHIFT;
    rsp->rmr_import.req_addr = req_addr;
    rsp->rmr_import.offset = offset;
    rsp->rmr_import.pg_ps = pg_ps;

 out:
    debug(DEBUG_MEMREG, "%s:%s,%u:ret=%d, req_addr=0x%016llx, offset=0x%lx, pg_ps=%u\n",
          zhpe_driver_name, __func__, __LINE__, status,
          req_addr, offset, pg_ps);
    return queue_io_rsp(entry, sizeof(rsp->rmr_import), status);
}

int zhpe_user_req_RMR_FREE(struct io_entry *entry)
{
    union zhpe_req          *req = &entry->op.req;
    union zhpe_rsp          *rsp = &entry->op.rsp;
    uuid_t                  *uuid = &req->rmr_free.uuid;
    int                     status = 0;
    struct zhpe_rmr         *rmr;
    uint64_t                len, access, rsp_zaddr, req_addr;
    uint32_t                dgcid;
    ulong                   flags;
    char                    str[UUID_STRING_LEN+1];

    rsp_zaddr = req->rmr_free.rsp_zaddr;
    len = req->rmr_free.len;
    access = req->rmr_free.access;
    req_addr = req->rmr_free.req_addr;
    dgcid = zhpe_gcid_from_uuid(uuid);
    CHECK_INIT_STATE(entry, status, out);

    spin_lock_irqsave(&entry->fdata->mr_lock, flags);
    rmr = rmr_search(entry->fdata, dgcid, rsp_zaddr, len, access, req_addr);
    if (!rmr) {
        status = -EINVAL;
        goto unlock;
    }
    rmr_remove(rmr, false);

 unlock:
    spin_unlock_irqrestore(&entry->fdata->mr_lock, flags);
 out:
    debug(DEBUG_MEMREG, "%s:%s,%u:ret = %d, uuid = %s, rsp_zaddr = 0x%016llx, "
          "len = 0x%llx, access = 0x%llx\n",
          zhpe_driver_name, __func__, __LINE__, status,
          zhpe_uuid_str(uuid, str, sizeof(str)), rsp_zaddr, len, access);
    return queue_io_rsp(entry, sizeof(rsp->mr_free), status);
}

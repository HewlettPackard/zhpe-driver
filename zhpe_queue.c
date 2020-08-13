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
 *     disclaimer in the documentation and/or other materials5B provided
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

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#endif

/* Forward declarations */
static int xdm_last_used_slice = SLICES-1;
static int rdm_last_used_slice = SLICES-1;

/*
 * Called from the zhpe_core driver probe function for each slice discovered.
 */
void zhpe_xqueue_init(struct slice *sl)
{
    spin_lock_init(&sl->xdm_slice_lock);
    bitmap_zero(sl->xdm_alloced_bitmap, MAX_XDM_QUEUES_PER_SLICE);
    sl->xdm_alloc_count = 0;
}

/*
 * Called from the zhpe_core driver probe function for each slice discovered.
 */
void zhpe_rqueue_init(struct slice *sl)
{
    spin_lock_init(&sl->rdm_slice_lock);
    bitmap_zero(sl->rdm_alloced_bitmap, MAX_RDM_QUEUES_PER_SLICE);
    sl->rdm_alloc_count = 0;
}

/*
 * These offsets into the XDM QCM are for fields that requre initialization
 * for ECC because they are "register files". Note that Active Command
 * Count in byte 0x28 is also a register file and need initialization for
 * ECC.
 */
int xqcm_hsr_offsets[] =
{ 0x0, 0x08, 0x10, 0x18, 0x28, 0x40, 0x80, 0xc0, 0x100 };
#define XDM_A_MASK		0x0000000000008000
#define XDM_ACC_MASK		0x00000000000007ff

/*
 * These offsets into the RDM QCM are for fields that requre initialization
 * for ECC because they are "register files". Note that Active Command
 * Count in byte 0x28 is also a register file and needs initialization for
 * ECC.
 */
int rqcm_hsr_offsets[] =
{ 0x0, 0x08, 0x40, 0x80 };
#define RDM_A_MASK		0x0000000000000001

static DECLARE_WAIT_QUEUE_HEAD(wqA);

void zhpe_debug_xdm_qcm(const char *callf, uint line, const void *cqcm)
{
    void            *qcm = (void *)cqcm;
    uint            off;
    uint64_t        cmd_addr;
    uint64_t        cmpl_addr;
    uint64_t        cmd_paddr;
    uint64_t        cmpl_paddr;
    uint64_t        cmd_vaddr;
    uint64_t        cmpl_vaddr;

    if (!(zhpe_debug_flags & DEBUG_XQUEUE))
        return;

    cmd_addr = xdm_qcm_read(qcm, XDM_CMD_ADDR_OFFSET) & ~0x1FULL;
    cmpl_addr = xdm_qcm_read(qcm, XDM_CMPL_ADDR_OFFSET) & ~0x1FULL;
    if (xdm_qcm_read(qcm, XDM_PASID_OFFSET) & XDM_PASID_QVIRT_FLAG) {
        cmd_vaddr = cmd_addr;
        cmpl_vaddr = cmpl_addr;
        cmd_paddr = 0;
        cmpl_paddr = 0;
    } else {
        cmd_paddr = cmd_addr;
        cmpl_paddr = cmpl_addr;
        cmd_vaddr = (uintptr_t)phys_to_virt(cmd_addr);
        cmpl_vaddr = (uintptr_t)phys_to_virt(cmpl_addr);
    }

    zprintk_caller(KERN_DEBUG, callf, line,
                   "xqcm %px cmd 0x%llx/0x%llx cmpl 0x%llx/0x%llx\n",
                   qcm, cmd_vaddr, cmd_paddr, cmpl_vaddr, cmpl_paddr);
    for (off = XDM_DUMP_08_START; off <= XDM_DUMP_08_END; off += 0x08)
        zprintk(KERN_DEBUG, "xqcm[0x%03x] = 0x%llx\n",
                off, xdm_qcm_read(qcm, off));
    for (off = XDM_DUMP_40_START; off <= XDM_DUMP_40_END; off += 0x40)
        zprintk(KERN_DEBUG, "xqcm[0x%03x] = 0x%llx\n",
                off, xdm_qcm_read(qcm, off));
}

void zhpe_debug_rdm_qcm(const char *callf, uint line, const void *cqcm)
{
    void            *qcm = (void *)cqcm;
    uint            off;
    uint64_t        cmpl_addr;
    uint64_t        cmpl_paddr;
    uint64_t        cmpl_vaddr;

    if (!(zhpe_debug_flags & DEBUG_XQUEUE))
        return;

    cmpl_addr = rdm_qcm_read(qcm, RDM_CMPL_ADDR_OFFSET) & ~0x1FULL;
    if (rdm_qcm_read(qcm, RDM_SIZE_OFFSET) & RDM_SIZE_QVIRT_FLAG) {
        cmpl_vaddr = cmpl_addr;
        cmpl_paddr = 0;
    } else {
        cmpl_paddr = cmpl_addr;
        cmpl_vaddr = (uintptr_t)phys_to_virt(cmpl_addr);
    }

    zprintk_caller(KERN_DEBUG, callf, line, "rqcm %px cmpl 0x%llx/0x%llx\n",
                   qcm, cmpl_vaddr, cmpl_paddr);
    for (off = RDM_DUMP_08_START; off <= RDM_DUMP_08_END; off += 0x08)
        zprintk(KERN_DEBUG, "rqcm[0x%03x] = 0x%llx\n",
                off, rdm_qcm_read(qcm, off));
    for (off = RDM_DUMP_40_START; off <= RDM_DUMP_40_END; off += 0x40)
        zprintk(KERN_DEBUG, "rqcm[0x%03x] = 0x%llx\n",
                off, rdm_qcm_read(qcm, off));
}

static int xdm_get_A_bit(struct xdm_qcm *qcm, uint16_t *acc)
{
    uint64_t a;

    a = xdm_qcm_read(qcm, XDM_A_OFFSET);
    *acc = (uint16_t)(a & XDM_ACC_MASK);
    return((a & XDM_A_MASK) ? 1 : 0);
}

static int rdm_get_A_bit(struct rdm_qcm *qcm)
{
    uint64_t a;

    a = rdm_qcm_read(qcm, RDM_A_OFFSET);
    return((a & RDM_A_MASK) ? 1 : 0);
}

#define COMMANDS_TO_BUSYWAIT	5
#define COMMANDS_IN_20MS	280	/* Revisit Carbon: this is for Carbon. Check on HW */
#define USEC_WAIT_PER_COMMAND	72	/* Revisit Carbon: this is for Carbon. Check on HW */
#define BAIL_OUT		200	/* give up is wait loops this many */
#define MSLEEP_WAIT		2       /* 2ms wait for msleep loop */

#define BUSY_WAIT	1
#define USLEEP_RANGE	2
#define MSLEEP		3
static int xdm_wait(struct xdm_qcm *qcm, int wait_type, int wait_time)
{
    int bail_out = 0;
    uint16_t acc;

    while(xdm_get_A_bit(qcm, &acc) == 1) {
        switch (wait_type) {
        case USLEEP_RANGE:
            usleep_range(wait_time/2, wait_time);
            break;
        case MSLEEP:
            msleep(wait_time);
            break;
        case BUSY_WAIT:
            break;
        }
        if (bail_out++ > BAIL_OUT) { /* prevent an infinite loop */
            debug(DEBUG_XQUEUE,
                  "queue did not go idle. Active command count is %d\n", acc);
            zhpe_debug_xdm_qcm(__func__, __LINE__, qcm);
            return -1;
        }
    }
    return 0;
}

static int xdm_wait_for_active_clear(struct xdm_qcm *qcm)
{
    int a;
    uint16_t acc;
    int wait_time;

    /* Get active command count to calculate an estimated delay */
    a = xdm_get_A_bit(qcm, &acc);

    /* Queue is not active */
    if (!a)
        return 0;

    /* If only a small number of commands, busy wait on the A bit */
    if (acc < COMMANDS_TO_BUSYWAIT) {
        return xdm_wait(qcm, BUSY_WAIT, 0);
    }
    /* Use usleep_range if commands could be processed in 20ms */
    else if (acc < COMMANDS_IN_20MS) {
        if (acc == 0) acc = 1; /* prevent divide by 0 */
        wait_time = acc * USEC_WAIT_PER_COMMAND;
        return xdm_wait(qcm, USLEEP_RANGE, wait_time);
    }
    /* There are more than 20ms of commands, use msleep() */
    else {
        return xdm_wait(qcm, MSLEEP, MSLEEP_WAIT);
    }
}

static int stop_xdm(struct slice *sl, struct xdm_qcm *qcm)
{
    uint64_t junk;

    /* Set the master stop bit */
    xdm_qcm_write_val(1, qcm, ZHPE_XDM_QCM_MASTER_STOP_OFFSET);

    /* Read back to ensure synchronization. */
    junk = xdm_qcm_read(qcm, ZHPE_XDM_QCM_MASTER_STOP_OFFSET);

    if (xdm_wait_for_active_clear(qcm)) {
        sl->stuck_xdm_queues++;
        return -1;
    }
    return 0;
}

static int clear_xdm_qcm(struct slice *sl, struct xdm_qcm *qcm)
{
    int h;
    int hsr_count;

    /* Stop the queue */
    if (stop_xdm(sl, qcm)) {
        return -1;
    }

    /* Write each qcm HSR that contains data. */
    hsr_count = sizeof(xqcm_hsr_offsets)/sizeof(xqcm_hsr_offsets[0]);
    for (h = 0; h < hsr_count; h++)
        xdm_qcm_write_val(0, qcm, xqcm_hsr_offsets[h]);
    return 0;
}

static void clear_xdm_qcm_cmd(struct xdm_qcm *qcm)
{
    uint64_t            off;

    /* Clear command buffer space. */
    for (off = 0; off < ZHPE_XDM_QCM_CMD_BUF_CLEAR; off += sizeof(uint64_t))
        xdm_qcm_write_val(0, qcm, ZHPE_XDM_QCM_CMD_BUF_OFFSET + off);
}

int zhpe_clear_xdm_qcm(struct bridge *br, struct slice *sl)
{
    int ret = 0;
    struct xdm_qcm *qcm = sl->bar->xdm;
    int      q;
    uint64_t junk;

    debug(DEBUG_XQUEUE, "qcm = 0x%px\n", qcm);

    /*
     * The XDM HSR space has 32MB for 256 QCM. Each QCM has an App
     * and a Kernel page for a total of 512 QCM. We write/read each
     * kernel HSR page (not the App) to initialize the ECC and contents
     * after a reset. Any errors are to be ignored.
     */
    for (q = 0; q < zhpe_xdm_queues_per_slice*2; q = q+2) {
        if (clear_xdm_qcm(sl, &qcm[q]) != 0) {
            dev_warn(&sl->pdev->dev, "%s:slice %d, queue %d:failed to clear\n",
                     __func__, sl->phys_id, q / 2);
            ret = -EIO;
            continue;
        }
        clear_xdm_qcm_cmd(qcm);
    }
    /* Read back one value to ensure synchronization. */
    if (!ret)
        junk = xdm_qcm_read(&qcm[0], ZHPE_XDM_QCM_MASTER_STOP_OFFSET);

    return ret;
}

static int clear_rdm_qcm(struct slice *sl, struct rdm_qcm *qcm)
{
    int h;
    int bail_out = 0;
    uint64_t junk;
    int hsr_count;

    /* Set the master stop bit */
    rdm_qcm_write_val(1, qcm, ZHPE_RDM_QCM_MASTER_STOP_OFFSET);

    /* Read back to ensure synchronization. */
    junk = rdm_qcm_read(qcm, ZHPE_RDM_QCM_MASTER_STOP_OFFSET);

    /* Busy wait on the A bit */
    while (rdm_get_A_bit(qcm) == 1) {
        if (bail_out++ > 200) { /* prevent an infinite loop */
            debug(DEBUG_RQUEUE, "clear_rdm_qcm: queue did not go idle.\n");
            sl->stuck_rdm_queues++;
            return -1;
        }
    }

    /* Write each qcm HSR that contains data. */
    hsr_count = sizeof(rqcm_hsr_offsets)/sizeof(rqcm_hsr_offsets[0]);
    for (h = 0; h < hsr_count; h++)
        rdm_qcm_write_val(0, qcm, rqcm_hsr_offsets[h]);
    /* Set head to 1 to workaround SKW-1203. */
    rdm_qcm_write_val(1, qcm, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);

    return 0;
}

int zhpe_clear_rdm_qcm(struct bridge *br, struct slice *sl)
{
    int ret = 0;
    struct rdm_qcm *qcm = sl->bar->rdm;
    int      q;
    uint64_t junk;

    debug(DEBUG_RQUEUE, "qcm = 0x%px\n", qcm);

    /*
     * The RDM HSR space has 32MB for 256 QCM. Each QCM has an App
     * and a Kernel page for a total of 512 QCM. We write/read each
     * kernel HSR page (not the App) to initialize the ECC and contents
     * after a reset. Any errors are to be ignored.
     */
    for (q = 0; q < zhpe_rdm_queues_per_slice*2; q = q+2) {
        if (clear_rdm_qcm(sl, &qcm[q]) != 0) {
            dev_warn(&sl->pdev->dev, "%s:slice %d, queue %d:failed to clear\n",
                     __func__, sl->phys_id, q / 2);
            ret = -EIO;
        }
    }
    /* Read back one value to ensure synchronization. */
    if (!ret)
        junk = rdm_qcm_read(&qcm[0], ZHPE_RDM_QCM_MASTER_STOP_OFFSET);

    return ret;
}

static int distribute_irq(unsigned long *alloced_bitmap,
                          struct slice *sl, int *vector)
{
    int q;
    int min_vector, min, max_vector;
    int v;
    int count;
    int clump_size = MAX_RDM_QUEUES_PER_SLICE / sl->irq_vectors_count;
    bool q0;
    DECLARE_BITMAP(tmp_bitmap, MAX_RDM_QUEUES_PER_SLICE);

    /* caller must hold rdm_slice_lock */

    q0 = test_and_set_bit(0, alloced_bitmap);  /* disallow choosing q0 */
    /* Make a copy of the alloced_bitmap for shifting */
    bitmap_copy(tmp_bitmap, alloced_bitmap, MAX_RDM_QUEUES_PER_SLICE);
    /*
     * Choose a free queue that distributes across the clumped irqs.
     * The hardware may support up to 32 MSI interrupt vectors. The
     * queues will be mapped to an interrupt in order. E.g. queues
     * 0-7 map to vector 0, 8-15 vector 1, etc for 32 MSI vectors.
     * Note that the actual number of MSI vectors that Linux allocated
     * is stored in sl->irq_vectors_count - it may not be 32.
     *
     * There are places in this function where we might replace
     * MAX_RDM_QUEUES_PER_SLICE with zhpe_rdm_queues_per_slice, but it
     * is not intuitively obvious this will result in better code in all places
     * and it really shouldn't matter.
     *
     * We limit vectors searched below by the actual number of available queues
     * to prevent errors. Because the calling function checks that there is
     * space available, failure should not be an option. (But this comment
     * got written while fixing a bug.)
     */
    max_vector = ((int)zhpe_rdm_queues_per_slice + clump_size - 1) / clump_size;
    /* Find which vector has the fewest queues assigned */
    min_vector = -1;
    min = clump_size;
    for (v=0; v < max_vector; v++) {
        /* count bits set in bitmap for the given range */
        count = bitmap_weight(tmp_bitmap, clump_size);
        if (count < min) {
            /* Found a vector with fewer queues */
            min_vector = v;
            min = count;
        }
        /* Shift the bitmap to count the next clump */
        bitmap_shift_right(tmp_bitmap, tmp_bitmap, clump_size,
                           zhpe_rdm_queues_per_slice);
    }
    /* Look for a free queue in that minimum range */
    q = find_next_zero_bit(alloced_bitmap, zhpe_rdm_queues_per_slice,
                           min_vector * clump_size);
    *vector = min_vector;
    if (!q0)  /* restore q0 bit to its previous value */
        clear_bit(0, alloced_bitmap);
    /* Return the chosen free queue */
    return q;
}

int zhpe_rdm_queue_to_vector(int queue, struct slice *sl)
{
    int vector;
    int clump_size = MAX_RDM_QUEUES_PER_SLICE / sl->irq_vectors_count;

    vector = queue / clump_size;

    return vector;
}

static int xdm_choose_slice_queue(
    struct bridge *br,
    uint8_t       slice_mask,
    int           *slice,
    int           *queue)
{
    int i;
    int q;
    int s = (xdm_last_used_slice + 1) % SLICES;
    struct slice *slices;
    struct slice *cur_slice;

    slices = br->slice;

    for (i = 0; i < SLICES; i++) {
        if (slice_mask & (1<<s)) {
            cur_slice = &slices[s];
            /* make sure this slice is valid */
            if (SLICE_VALID(cur_slice)) {
                spin_lock(&cur_slice->xdm_slice_lock);
                if (cur_slice->xdm_alloc_count < zhpe_xdm_queues_per_slice) {
                    /* Use this slice */
                    cur_slice->xdm_alloc_count++;
                    q = find_first_zero_bit(cur_slice->xdm_alloced_bitmap,
                                            zhpe_xdm_queues_per_slice);
                    set_bit(q, cur_slice->xdm_alloced_bitmap);
                    spin_unlock(&cur_slice->xdm_slice_lock);
                    xdm_last_used_slice = s;
                    *slice = s;
                    *queue = q;
                    return 0;
                }
                spin_unlock(&cur_slice->xdm_slice_lock);
            }
        }
        s = (s + 1) % SLICES;
    }

    /* Didn't find any queues available. */
    return -ENOENT;
}

static int rdm_choose_slice_q0(struct bridge *br, uint8_t slice_mask,
                               int *slice, int *queue, int *irq_vector)
{
    int s;
    struct slice *slices = br->slice;
    struct slice *cur_slice;

    for (s = 0; s < SLICES; s++) {
        if (!(slice_mask & (1<<s)))
            continue;
        cur_slice = &slices[s];
        debug(DEBUG_RQUEUE, "considering slice %d\n", s);
        if (!SLICE_VALID(cur_slice))  /* make sure this slice is valid */
            continue;
        spin_lock(&cur_slice->rdm_slice_lock);
        if (test_and_set_bit(0, cur_slice->rdm_alloced_bitmap) == 0) {
            /* Use this slice */
            spin_unlock(&cur_slice->rdm_slice_lock);
            rdm_last_used_slice = s;
            *slice = s;
            *queue = 0;
            *irq_vector = (s * VECTORS_PER_SLICE);
            debug(DEBUG_RQUEUE,
                  "assigning slice %d queue %d irq_vector %d\n",
                  *slice, *queue, *irq_vector);
            return 0;
        }
        spin_unlock(&cur_slice->rdm_slice_lock);
    }

    /* Didn't find any q0 available */
    return -ENOENT;
}

static int rdm_choose_slice_queue(
    struct bridge *br,
    uint8_t       slice_mask,
    int           *slice,
    int           *queue,
    int           *irq_vector)
{
    int i;
    int q;
    int s = (rdm_last_used_slice + 1) % SLICES;
    struct slice *slices;
    struct slice *cur_slice;
    int vector;

    slices = br->slice;

    for (i = 0; i < SLICES; i++) {
        if (slice_mask & (1<<s)) {
            cur_slice = &slices[s];

            debug(DEBUG_RQUEUE, "considering slice %d\n", s);
            /* make sure this slice is valid */
            if (SLICE_VALID(cur_slice)) {
                spin_lock(&cur_slice->rdm_slice_lock);
                if (cur_slice->rdm_alloc_count < zhpe_rdm_queues_per_slice-1) {
                    /* Use this slice */
                    cur_slice->rdm_alloc_count++;
                    q = distribute_irq(cur_slice->rdm_alloced_bitmap,
                                       cur_slice, &vector);
                    set_bit(q, cur_slice->rdm_alloced_bitmap);
                    spin_unlock(&cur_slice->rdm_slice_lock);
                    rdm_last_used_slice = s;
                    *slice = s;
                    *queue = q;
                    *irq_vector = (s*VECTORS_PER_SLICE)+vector;
                    debug(DEBUG_RQUEUE,
                          "assigning slice %d queue %d irq_vector %d\n",
                          *slice, *queue, *irq_vector);
                    return 0;
                }
                spin_unlock(&cur_slice->rdm_slice_lock);
            }
        }
        s = (s + 1) % SLICES;
    }

    /* Didn't find any queues available. */
    return -ENOENT;
}

static void xdm_release_slice_queue(
    struct bridge *br,
    int           slice,
    int           queue)
{
    struct slice *slices;
    struct slice *cur_slice;

    slices = br->slice;
    cur_slice = &slices[slice];

    spin_lock(&cur_slice->xdm_slice_lock);
    cur_slice->xdm_alloc_count--;
    clear_bit(queue, cur_slice->xdm_alloced_bitmap);
    spin_unlock(&cur_slice->xdm_slice_lock);
}

static void rdm_release_slice_queue(
    struct bridge *br,
    int           slice,
    int           queue)
{
    struct slice *slices;
    struct slice *cur_slice;

    slices = br->slice;
    cur_slice = &slices[slice];

    spin_lock(&cur_slice->rdm_slice_lock);
    if (queue != 0)  /* q0 is not counted */
        cur_slice->rdm_alloc_count--;
    clear_bit(queue, cur_slice->rdm_alloced_bitmap);
    spin_unlock(&cur_slice->rdm_slice_lock);
}

/* Allocate a queue from a slice according to the slice_mask. */
static int alloc_xqueue(
    struct bridge *br,
    uint8_t slice_mask,
    int     *slice,
    int     *queue)
{
    int ret;
    uint8_t sm;

    if (slice_mask == SLICE_DEMAND) {
        /* seting the DEMAND flag without any slices is an error. */
        return -EINVAL;
    }
    if (slice_mask == 0) {
        /* Caller did not specify any specific slices so use all. */
        sm = ALL_SLICES;
        return xdm_choose_slice_queue(br, sm, slice, queue);
    }
    else {
        /* Caller set a slice mask. Mask off DEMAND for now. */
        sm = slice_mask & ALL_SLICES;
        ret = xdm_choose_slice_queue(br, sm, slice, queue);
        if (slice_mask & SLICE_DEMAND) {
            /* Return if this is a demand */
            return ret;
        }
        if (ret == 0) {
            /* Found a queue in specified hint slices */
            return ret;
        }
        else {
            /* This is a hint so try again with un-tried slices. */
            sm = sm^ALL_SLICES;
            return xdm_choose_slice_queue(br, sm, slice, queue);
        }
    }
}

/* Allocate the specific slice & queue chosen by the (userspace) caller */
static int alloc_rqspecific(struct bridge *br, int qspecific, int *slice,
                            int *queue, int *irq_vector)
{
    int                 ret;
    struct slice        *cur_slice;

    *slice = qspecific & (SLICES - 1);
    *queue = qspecific / SLICES;
    if (*queue == 0) {  /* disallow q0 from userspace */
        ret = -EINVAL;
        goto done;
    }
    cur_slice = &br->slice[*slice];
    if (!SLICE_VALID(cur_slice) || *queue >= zhpe_rdm_queues_per_slice) {
        ret =  -ENOENT;
        goto done;
    }
    *irq_vector = (*slice * VECTORS_PER_SLICE +
                   (*queue /
                    (MAX_RDM_QUEUES_PER_SLICE / cur_slice->irq_vectors_count)));
    debug(DEBUG_RQUEUE, "considering slice %d, queue %d vector %d\n",
          *slice, *queue, *irq_vector);

    spin_lock(&cur_slice->rdm_slice_lock);
    if (likely(!__test_and_set_bit(*queue, cur_slice->rdm_alloced_bitmap))) {
        cur_slice->rdm_alloc_count++;
        ret = 0;
    } else
        ret = -EADDRINUSE;
    spin_unlock(&cur_slice->rdm_slice_lock);

 done:
    return ret;
}

/* Allocate a queue from a slice according to the slice_mask. */
static int alloc_rqueue(struct bridge *br, uint8_t slice_mask,
                        int *slice, int *queue, int *irq_vector)
{
    int ret;
    uint8_t sm;
    bool q0;

    q0 = (slice_mask & SLICE_Q0) != 0;  /* kernel request for q0 */
    slice_mask &= ~SLICE_Q0;

    if (slice_mask == SLICE_DEMAND) {
        /* seting the DEMAND flag without any slices is an error */
        return -1;
    }
    if (slice_mask == 0) /* Caller did not specify any slices so use all */
        slice_mask = ALL_SLICES;
    sm = slice_mask & ALL_SLICES;  /* Mask off DEMAND for now */
    ret = q0 ? rdm_choose_slice_q0(br, sm, slice, queue, irq_vector) :
        rdm_choose_slice_queue(br, sm, slice, queue, irq_vector);
    if ((ret == 0) || (slice_mask & SLICE_DEMAND) || (sm == ALL_SLICES)) {
        /* Return if success or this is a DEMAND or tried all slices */
        return ret;
    }
    /* slice_mask is a hint so try again with un-tried slices */
    sm ^= ALL_SLICES;
    return q0 ? rdm_choose_slice_q0(br, sm, slice, queue, irq_vector) :
        rdm_choose_slice_queue(br, sm, slice, queue, irq_vector);
}

static int _xqueue_free(
    struct bridge *br,
    int slice,
    int queue)
{
    struct slice     *slices;
    struct slice     *sl;
    struct xdm_qcm   *hw_qcm_addr;

    slices = br->slice;

    if (slice < 0 || slice >= SLICES)
        return -EINVAL;
    if (queue < 0 || queue >= zhpe_xdm_queues_per_slice)
        return -EINVAL;
    sl = &(slices[slice]);
    if (test_bit(queue, sl->xdm_alloced_bitmap) == 0) {
        debug(DEBUG_XQUEUE,
              "Tried to free unallocated queue %d on slice %d\n",
              queue, slice);
        return -EINVAL;
    }

    /*
     * Set master stop and clear the hardware queue. May wait to drain
     * the queue.
     */
    hw_qcm_addr = &(sl->bar->xdm[(queue*2)]);
    if (clear_xdm_qcm(sl, hw_qcm_addr)) {
        dev_warn(&sl->pdev->dev, "%s:slice %d, queue %d:failed to clear\n",
                 __func__, sl->phys_id, queue);
        return -EIO;
    }

    /* Return queue to the bridge's free pool */
    spin_lock(&slices[slice].xdm_slice_lock);
    slices[slice].xdm_alloc_count--;
    clear_bit(queue, slices[slice].xdm_alloced_bitmap);
    spin_unlock(&slices[slice].xdm_slice_lock);

    debug(DEBUG_XQUEUE, "Freed queue %d on slice %d qcm=0x%px\n",
          queue, slice, hw_qcm_addr);
    return 0;
}

static int zhpe_xqueue_free(
    struct file_data *fdata,
    struct zhpe_req_XQFREE *free_req)
{
    int              slice = free_req->info.slice;
    int              queue = free_req->info.queue;
    int              ret;

    mutex_lock(&fdata->xdm_queue_mutex);
    if (test_bit((slice*zhpe_xdm_queues_per_slice) + queue,
                 fdata->xdm_queues) == 0 ) {
        debug(DEBUG_XQUEUE,
              "Cannot free un-owned queue %d on slice %d\n",
              queue, slice);
        ret = -EINVAL;
        goto unlock;
    }
    /* Release ownership of the queue from this file_data */
    clear_bit((slice*zhpe_xdm_queues_per_slice) + queue, fdata->xdm_queues);

    ret = _xqueue_free(fdata->bridge, slice, queue);

 unlock:
    mutex_unlock(&fdata->xdm_queue_mutex);
    return ret;
}

static int _rqueue_free(
    struct bridge *br,
    int slice,
    int queue)
{
    struct slice     *sl;
    struct rdm_qcm   *hw_qcm_addr;

    if (slice < 0 || slice >= SLICES)
        return -EINVAL;
    if (queue < 0 || queue >= zhpe_rdm_queues_per_slice)
        return -EINVAL;
    sl = &br->slice[slice];
    if (!SLICE_VALID(sl))
        return -EINVAL;

    zhpe_unregister_rdm_interrupt(sl, queue);
    if (queue == 0)
        cancel_work_sync(&zhpe_bridge.msg_work);

    if (test_bit(queue, sl->rdm_alloced_bitmap) == 0) {
        debug(DEBUG_RQUEUE,
              "Tried to free unallocated queue %d on slice %d\n",
              queue, slice);
        return -EINVAL;
    }

    /*
     * Set master stop and clear the hardware queue. May wait to drain
     * the queue.
     */
    hw_qcm_addr = &(sl->bar->rdm[(queue*2)]);
    if (clear_rdm_qcm(sl, hw_qcm_addr) != 0) {
        dev_warn(&sl->pdev->dev, "%s:slice %d, queue %d:failed to clear\n",
                 __func__, sl->phys_id, queue);
        return -EIO;
    }

    /* Return queue to the bridge's free pool */
    spin_lock(&sl->rdm_slice_lock);
    sl->rdm_alloc_count--;
    clear_bit(queue, sl->rdm_alloced_bitmap);
    spin_unlock(&sl->rdm_slice_lock);

    debug(DEBUG_RQUEUE, "Freed queue %d on slice %d qcm=0x%px\n",
          queue, slice, hw_qcm_addr);
    return 0;
}

static int zhpe_rqueue_free(
    struct file_data *fdata,
    struct zhpe_req_RQFREE *free_req)
{
    int              slice = free_req->info.slice;
    int              queue = free_req->info.queue;
    int              ret;

    if (slice < 0 || slice >= SLICES)
        return -EINVAL;
    if (queue < 0 || queue >= zhpe_rdm_queues_per_slice)
        return -EINVAL;

    spin_lock(&fdata->rdm_queue_lock);
    if (test_bit((slice*zhpe_rdm_queues_per_slice) + queue,
                 fdata->rdm_queues) == 0 ) {
        debug(DEBUG_RQUEUE,
              "Cannot free un-owned queue %d on slice %d\n",
              queue, slice);
        ret = -EINVAL;
        goto unlock;
    }
    /* Release ownership of the queue from this file_data */
    clear_bit((slice*zhpe_rdm_queues_per_slice) + queue, fdata->rdm_queues);

    ret = _rqueue_free(fdata->bridge, slice, queue);

 unlock:
    spin_unlock(&fdata->rdm_queue_lock);
    return ret;
}

static int _xqueue_stop(
    struct bridge *br,
    int slice,
    int queue)
{
    struct slice     *slices;
    struct slice     *sl;
    struct xdm_qcm   *hw_qcm_addr;

    slices = br->slice;

    if (slice < 0 || slice >= SLICES)
        return -EINVAL;
    if (queue < 0 || queue >= zhpe_xdm_queues_per_slice)
        return -EINVAL;
    sl = &(slices[slice]);
    if (test_bit(queue, sl->xdm_alloced_bitmap) == 0) {
        debug(DEBUG_XQUEUE,
              "Tried to stop unallocated queue %d on slice %d\n",
              queue, slice);
        return -EINVAL;
    }

    /*
     * Set master stop and clear the hardware queue. May wait to drain
     * the queue.
     */
    hw_qcm_addr = &(sl->bar->xdm[(queue*2)]);
    if (stop_xdm(sl, hw_qcm_addr) != 0) {
        dev_warn(&sl->pdev->dev, "%s:slice %d, queue %d:failed to stop\n",
                 __func__, sl->phys_id, queue);
        return -EIO;
    }

    debug(DEBUG_XQUEUE, "stopped queue %d on slice %d qcm=0x%px\n",
          queue, slice, hw_qcm_addr);
    return 0;
}

void zhpe_stop_owned_xdm_queues(struct file_data *fdata)
{
    int ret = 0;
    int bits = SLICES * zhpe_xdm_queues_per_slice;
    int slice, queue, bit;

    mutex_lock(&fdata->xdm_queue_mutex);
    bit = find_first_bit(fdata->xdm_queues, bits);
    while (1) {
        if (bit >= bits)
            break;
        slice = bit / zhpe_xdm_queues_per_slice;
        queue = bit % zhpe_xdm_queues_per_slice;
        ret = _xqueue_stop(fdata->bridge, slice, queue);
        if (ret < 0) {
            debug(DEBUG_XQUEUE,
                  "failed to stop queue %d on slice %d\n",
                  queue, slice);
        }
        bit = find_next_bit(fdata->xdm_queues, bits, bit + 1);
    }
    mutex_unlock(&fdata->xdm_queue_mutex);
}

void zhpe_release_owned_xdm_queues(struct file_data *fdata)
{
    int bits = SLICES * zhpe_xdm_queues_per_slice;
    int slice, queue, bit;

    mutex_lock(&fdata->xdm_queue_mutex);
    bit = find_first_bit(fdata->xdm_queues, bits);
    while (1) {
        if (bit >= bits)
            break;
        slice = bit / zhpe_xdm_queues_per_slice;
        queue = bit % zhpe_xdm_queues_per_slice;
        (void)_xqueue_free(fdata->bridge, slice, queue);
        clear_bit(bit, fdata->xdm_queues);
        bit = find_next_bit(fdata->xdm_queues, bits, bit);
    }
    mutex_unlock(&fdata->xdm_queue_mutex);
}

void zhpe_release_owned_rdm_queues(struct file_data *fdata)
{
    int ret = 0;
    int bits = SLICES * zhpe_rdm_queues_per_slice;
    int slice, queue, bit;

    spin_lock(&fdata->rdm_queue_lock);
    bit = find_first_bit(fdata->rdm_queues, bits);
    while (1) {
        if (bit >= bits)
            break;
        slice = bit / zhpe_rdm_queues_per_slice;
        queue = bit % zhpe_rdm_queues_per_slice;
        ret = _rqueue_free(fdata->bridge, slice, queue);
        if (ret) {
            debug(DEBUG_RQUEUE,
                  "zhpe_release_owed_rdm_queues failed to free queue %d on slice %d\n",
                  queue, slice);
        }
        clear_bit(bit, fdata->rdm_queues);
        bit = find_next_bit(fdata->rdm_queues, bits, bit);
    }
    spin_unlock(&fdata->rdm_queue_lock);
}

static int dma_zalloc_map(
    struct slice *sl,
    size_t q_size,
    struct file_data *fdata,
    union zpages **ret_zpage,
    struct zmap **ret_zmap)
{
    int ret = 0;

    *ret_zpage = dma_zpages_alloc(sl, q_size);
    if (!*ret_zpage) {
        debug(DEBUG_XQUEUE, "zpage_alloc failed\n");
        ret = -ENOMEM;
        return ret;
    }
    if (ret_zmap) {  /* allocating and returning zmap is optional */
        *ret_zmap = zmap_alloc(fdata, *ret_zpage);
        if (IS_ERR(*ret_zmap)) {
            debug(DEBUG_XQUEUE, "zmap_alloc failed\n");
            ret = PTR_ERR(*ret_zmap);
            zpages_free(*ret_zpage);
        }
    }
    return ret;
}

#define CMDS_PER_PAGE ((uint32_t)(PAGE_SIZE / ZHPE_HW_ENTRY_LEN))

int zhpe_user_req_XQALLOC(struct io_entry *entry)
{
    int	 		  ret = -EINVAL;
    struct zhpe_rsp_XQALLOC	  rsp;

    CHECK_INIT_STATE(entry, ret, done);

    ret = zhpe_req_XQALLOC(&entry->op.req.xqalloc, &rsp, entry->fdata);

 done:
    /* Copy the response to the req/rsp union */
    entry->op.rsp.xqalloc = rsp;
    return queue_io_rsp(entry, sizeof(rsp), ret);
}

static void xdm_qcm_setup(struct xdm_qcm *hw_qcm_addr,
                          uint64_t cmdq_dma_addr, uint64_t cmplq_dma_addr,
                          uint cmdq_ent, uint cmplq_ent,
                          uint traffic_class, uint priority,
                          bool cur_valid, uint pasid, uint fabric_pasid)
{
    struct xdm_qcm_header     qcm = { 0 };
    uint64_t		  junk;
    int                       offset;

    /* Use a local qcm and then copy it to hardware */
    qcm.cmd_q_base_addr = cmdq_dma_addr;
    qcm.cmpl_q_base_addr = cmplq_dma_addr;
    /* Value written into the size field is queue size minus one. */
    qcm.cmpl_q_size = cmplq_ent - 1;
    qcm.cmd_q_size = cmdq_ent - 1;

    qcm.local_pasid = pasid;
    qcm.fabric_pasid = fabric_pasid;

    if (traffic_class > ZHPE_MAX_TC) {
        debug(DEBUG_XQUEUE, "Invalid traffic_class: %d. Default to 0.\n",
              traffic_class);
        qcm.traffic_class = ZHPE_TC_0;
    }
    else {
        /* Revisit: should we allow app control of traffic_class? */
        qcm.traffic_class = traffic_class;
    }
    if (priority > ZHPE_MAX_PRIO) {
        debug(DEBUG_XQUEUE, "Invalid priority: %d. Default to 0.\n",
              priority);
        qcm.priority = ZHPE_PRIO_LO;
    }
    else {
        qcm.priority = priority;
    }
    /* Use virt addresses with IOMMU and PASID */
    qcm.virt_addr = !no_iommu && (pasid != NO_PASID);
    qcm.q_virt_addr = 0;  /* Queues are physically addressed */
    qcm.toggle_valid = cur_valid;
    qcm.stop = 1;
    qcm.master_stop = 0;
    /* Write the first 4 64-byte words of the qcm to hardware */
    for (offset=0; offset < 0x20; offset+=0x8) {
        xdm_qcm_write(&qcm, hw_qcm_addr, offset);
    }
    /* Initialize the queue indicies. */
    xdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    xdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    xdm_qcm_write(&qcm, hw_qcm_addr,
                  ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);

    /* Now set the stop bits to turn control over to application. */
    xdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_XDM_QCM_STOP_OFFSET);
    xdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_XDM_QCM_MASTER_STOP_OFFSET);

    /* Read back to ensure synchronization */
    junk = xdm_qcm_read(hw_qcm_addr, ZHPE_XDM_QCM_MASTER_STOP_OFFSET);

    zhpe_debug_xdm_qcm(__func__, __LINE__, hw_qcm_addr);
}

static int xdm_queue_sizes(uint32_t *cmdq_ent, uint32_t *cmplq_ent,
                           size_t *cmdq_size, size_t *cmplq_size,
                           size_t *qcm_size)
{
    int ret = 0;

    /* Validate the given queue length */
    if (*cmdq_ent < 2 || *cmdq_ent > ZHPE_MAX_XDM_QLEN+1) {
        debug(DEBUG_XQUEUE, "Invalid command queue entries %d\n",
              *cmdq_ent);
        ret = -EINVAL;
        goto done;
    }
    /*
     * We force cmdq_ent to consume at least one kernel page and be
     * rounded up to the next power of 2.
     */
    *cmdq_ent = max(*cmdq_ent, CMDS_PER_PAGE);
    *cmdq_ent = roundup_pow_of_two(*cmdq_ent);

    if (*cmplq_ent < 2 || *cmplq_ent > ZHPE_MAX_XDM_QLEN+1) {
        debug(DEBUG_XQUEUE, "Invalid completion queue entries %d\n",
              *cmplq_ent);
        ret = -EINVAL;
        goto done;
    }
    /*
     * The completion queue must be greater than or equal to the command
     * queue and similarly rounded up.
     */
    *cmplq_ent = max(*cmdq_ent, *cmplq_ent);
    *cmplq_ent = roundup_pow_of_two(*cmplq_ent);

    /* Compute sizes */
    *qcm_size = PAGE_SIZE;
    *cmdq_size = *cmdq_ent * ZHPE_HW_ENTRY_LEN;
    *cmplq_size = *cmplq_ent * ZHPE_HW_ENTRY_LEN;

 done:
    debug(DEBUG_XQUEUE, "compute sizes: ret=%d cmdq_ent=%u cmdq_size=0x%lx "
          "cmplq_ent=%u cmplq_size=0x%lx qcm_size=0x%lx\n",
          ret, *cmdq_ent, *cmdq_size, *cmplq_ent, *cmplq_size, *qcm_size);
    return ret;
}

int zhpe_req_XQALLOC(
    struct zhpe_req_XQALLOC *req,
    struct zhpe_rsp_XQALLOC	*rsp,
    struct file_data        *fdata)
{
    int	 		  ret;
    uint32_t                  cmdq_ent, cmplq_ent;
    struct xdm_qcm            *hw_qcm_addr, *app_qcm_addr;
    phys_addr_t               app_qcm_physaddr;
    union zpages		  *qcm_zpage, *cmdq_zpage, *cmplq_zpage;
    struct zmap		  *qcm_zmap, *cmdq_zmap, *cmplq_zmap;
    size_t			  qcm_size = 0, cmdq_size = 0, cmplq_size = 0;
    struct slice		  *sl;
    int			  slice, queue;

    debug(DEBUG_XQUEUE,
          "xqalloc req cmdq_ent %d, cmplq_ent %d, traffic_class %d, priority %d, slice_mask 0x%x\n", req->cmdq_ent, req->cmplq_ent, req->traffic_class, req->priority, req->slice_mask);

    cmdq_ent = req->cmdq_ent;
    cmplq_ent = req->cmplq_ent;
    ret = xdm_queue_sizes(&cmdq_ent, &cmplq_ent, &cmdq_size, &cmplq_size,
                          &qcm_size);
    if (ret)
        goto done;

    rsp->info.cmdq.ent = cmdq_ent;
    rsp->info.cmplq.ent = cmplq_ent;
    rsp->info.cmdq.size = cmdq_size;
    rsp->info.cmplq.size = cmplq_size;
    rsp->info.qcm.size = qcm_size;

    debug(DEBUG_XQUEUE, "compute sizes cmdq_ent=%u cmdq_size=0x%lx "
          "cmplq_ent=%u cmplq_size=0x%lx\n",
          cmdq_ent, cmdq_size, cmplq_ent, cmplq_size);

    /* Pick which slice has a free queue based on the slice_mask */
    ret = alloc_xqueue(fdata->bridge, req->slice_mask,
                       &slice, &queue);
    rsp->hdr.status = ret;
    if (ret) {
        debug(DEBUG_XQUEUE,
              "Request for slice_mask 0x%x failed\n",
              req->slice_mask);
        goto done;
    }
    debug(DEBUG_XQUEUE,
          "xqalloc rsp slice %d queue %d\n",
          slice, queue);
    /* set bit in this file_data as owner */
    mutex_lock(&fdata->xdm_queue_mutex);
    set_bit((slice*zhpe_xdm_queues_per_slice)+queue, fdata->xdm_queues);
    mutex_unlock(&fdata->xdm_queue_mutex);
    rsp->info.slice = slice;
    rsp->info.queue = queue;

    /* Get a pointer to the qcm chosen to initialize it's fields */
    sl = &(fdata->bridge->slice[slice]);
    hw_qcm_addr = &(sl->bar->xdm[queue*2]);

    debug(DEBUG_XQUEUE, "hw_qcm_addr for slice %d queue %d queue init 0x%px\n",
          slice, queue, hw_qcm_addr);

    /* Allocate pages and map for qcm, cmdq, and cmplq */
    ret = -ENOMEM;
    /* Use the App Page in the zpage_alloc which is +1 from kernel page */
    app_qcm_addr = hw_qcm_addr + 1;
    app_qcm_physaddr = sl->phys_base +
        ((void *)app_qcm_addr - (void *)sl->bar);
    debug(DEBUG_XQUEUE, "app_qcm_physaddr %pxa\n", &app_qcm_physaddr);
    qcm_zpage = hsr_zpage_alloc(app_qcm_physaddr);
    if (!qcm_zpage) {
        debug(DEBUG_XQUEUE, "zpage_alloc failed for qcm\n");
        goto release_queue;
    }
    qcm_zmap = zmap_alloc(fdata, qcm_zpage);
    if (IS_ERR(qcm_zmap)) {
        debug(DEBUG_XQUEUE, "zmap_alloc failed for qcm\n");
        ret = PTR_ERR(qcm_zmap);
        qcm_zmap = NULL;
        goto free_qcm_zpage;
    }
    rsp->info.qcm.off = qcm_zmap->offset;

    ret = dma_zalloc_map(sl, cmdq_size, fdata,
                         &cmdq_zpage, &cmdq_zmap);
    if (ret != 0) {
        debug(DEBUG_XQUEUE, "dma_zalloc_map failed for cmdq\n");
        goto free_qcm_zmap;
    }
    rsp->info.cmdq.off = cmdq_zmap->offset;

    ret = dma_zalloc_map(sl, cmplq_size, fdata,
                         &cmplq_zpage, &cmplq_zmap);
    if (ret != 0) {
        debug(DEBUG_XQUEUE, "dma_zalloc_map failed for cmplq\n");
        goto free_cmdq_zmap;
    }
    rsp->info.cmplq.off = cmplq_zmap->offset;

    xdm_qcm_setup(hw_qcm_addr,
                  cmdq_zpage->dma.dma_addr, cmplq_zpage->dma.dma_addr,
                  rsp->info.cmdq.ent, rsp->info.cmplq.ent,
                  req->traffic_class, req->priority, 1, fdata->pasid,
                  fdata->fabric_pasid);

    /* Set owner fields to valid value; can't fail after this. */
    qcm_zmap->owner = fdata;
    cmdq_zmap->owner = fdata;
    cmplq_zmap->owner = fdata;

    /* Make sure owner is seen before we advertise the queue anywhere. */
    smp_wmb();
    ret = 0;
    goto done;

    /* Handle errors */
 free_cmdq_zmap:
    zmap_fdata_free(fdata, cmdq_zmap);
 free_qcm_zmap:
    zmap_fdata_free(fdata, qcm_zmap);
    /* zmap_free also frees the zpage */
    goto release_queue;
 free_qcm_zpage:
    zpages_free(qcm_zpage);
 release_queue:
    xdm_release_slice_queue(fdata->bridge, slice, queue);
    mutex_lock(&fdata->xdm_queue_mutex);
    clear_bit((slice*zhpe_xdm_queues_per_slice)+queue, fdata->xdm_queues);
    mutex_unlock(&fdata->xdm_queue_mutex);
 done:
    return ret;
}

#define CTXID_QUEUE_SHIFT		2
#define CTXID_UPPER_SLICE_SHIFT         10

uint32_t zhpe_ctxid(int slice, int queue)
{
    /*
     * bits 0-1 select the slice.
     * bits 9:2 select the queue number
     * bits 10:24 are the same for all queues
     * Revisit FabricManager: 10:24 are 0 until we have a fabric manger
     * interface
     */

    return (queue << CTXID_QUEUE_SHIFT) | slice;
}

int zhpe_kernel_XQALLOC(struct xdm_info *xdmi)
{
    int ret = 0;

    debug(DEBUG_XQUEUE, "cmdq_ent=%u, cmplq_ent=%u\n",
	  xdmi->cmdq_ent, xdmi->cmplq_ent);
    spin_lock_init(&xdmi->xdm_info_lock);
    ret = xdm_queue_sizes(&xdmi->cmdq_ent, &xdmi->cmplq_ent,
                          &xdmi->cmdq_size, &xdmi->cmplq_size,
                          &xdmi->qcm_size);
    if (ret)
        goto done;
    ret = alloc_xqueue(xdmi->br, xdmi->slice_mask,
                       &xdmi->slice, &xdmi->queue);
    if (ret)
        goto done;

    /* Get a pointer to the qcm chosen to initialize it's fields */
    xdmi->sl = &(xdmi->br->slice[xdmi->slice]);
    xdmi->hw_qcm_addr = &(xdmi->sl->bar->xdm[xdmi->queue*2]);
    ret = dma_zalloc_map(xdmi->sl, xdmi->cmdq_size, NULL,
                         &xdmi->cmdq_zpage, NULL);
    if (ret != 0) {
        debug(DEBUG_XQUEUE, "dma_zalloc_map failed for cmdq\n");
        goto release_queue;
    }
    ret = dma_zalloc_map(xdmi->sl, xdmi->cmplq_size, NULL,
                         &xdmi->cmplq_zpage, NULL);
    if (ret != 0) {
        debug(DEBUG_XQUEUE, "dma_zalloc_map failed for cmplq\n");
        goto free_cmdq_zpage;
    }
    xdm_qcm_setup(xdmi->hw_qcm_addr,
                  xdmi->cmdq_zpage->dma.dma_addr,
                  xdmi->cmplq_zpage->dma.dma_addr,
                  xdmi->cmdq_ent, xdmi->cmplq_ent,
                  xdmi->traffic_class, xdmi->priority, xdmi->cur_valid,
                  NO_PASID, NO_PASID);
    xdmi->cmdq_tail_shadow = 0;
    xdmi->cmplq_head = 0;
    xdmi->cmplq_tail_shadow = 0;
    xdmi->reqctxid = zhpe_ctxid(xdmi->slice, xdmi->queue);
    ret = 0;
    debug(DEBUG_XQUEUE, "slice=%d, queue=%d\n", xdmi->slice, xdmi->queue);
    goto done;

 free_cmdq_zpage:
    zpages_free(xdmi->cmdq_zpage);
 release_queue:
    xdm_release_slice_queue(xdmi->br, xdmi->slice, xdmi->queue);
 done:
    return ret;
}

int zhpe_user_req_XQFREE(struct io_entry *entry)
{
    int			ret = 0;

    CHECK_INIT_STATE(entry, ret, done);

    ret = zhpe_req_XQFREE(&entry->op.req, &entry->op.rsp, entry->fdata);

 done:
    return queue_io_rsp(entry, sizeof(&entry->op.rsp.xqfree), ret);

}

int zhpe_req_XQFREE(union zhpe_req *req,
                    union zhpe_rsp *rsp, struct file_data *fdata)
{
    int			ret = 0;
    int			count = 3;
    struct zmap		*zmap;
    struct zmap		*next;

    debug(DEBUG_XQUEUE,
          "xqfree req slice %d queue %d qcm.off 0x%llx cmd.off 0x%llx"
          " cmpl.off 0x%llx\n",
          req->xqfree.info.slice, req->xqfree.info.queue,
          req->xqfree.info.qcm.off, req->xqfree.info.cmdq.off,
          req->xqfree.info.cmplq.off);
    ret = zhpe_xqueue_free(fdata, &req->xqfree);
    if (ret < 0)
        /* zhpe_xqueue_free can fail if the queue doesn't drain. */
        goto done;

    spin_lock(&fdata->zmap_lock);
    list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
        if (zmap->offset == req->xqfree.info.qcm.off ||
            zmap->offset == req->xqfree.info.cmdq.off ||
            zmap->offset == req->xqfree.info.cmplq.off) {
            if (zmap->owner != fdata) {
                if (ret >= 0)
                    ret = -EACCES;
            } else {
                list_del_init(&zmap->list);
                zmap_fdata_free(fdata, zmap);
            }
            if (--count == 0)
                break;
        }
    }
    spin_unlock(&fdata->zmap_lock);
    if (ret >= 0 && count)
        ret = -ENOENT;

 done:
    debug(DEBUG_XQUEUE, "xqfree ret = %d\n", ret);
    return ret;
}

int zhpe_kernel_XQFREE(struct xdm_info *xdmi)
{
    int ret;

    ret =_xqueue_free(xdmi->br, xdmi->slice, xdmi->queue);
    if (ret < 0)
        /* _xqueue_free can fail if the queue doesn't drain */
        goto done;

    zpages_free(xdmi->cmdq_zpage);
    zpages_free(xdmi->cmplq_zpage);

 done:
    return ret;
}

int zhpe_user_req_RQALLOC_SPECIFIC(struct io_entry *entry)
{
    int	 		  ret = -EINVAL;
    struct zhpe_req_RQALLOC_SPECIFIC *req = &entry->op.req.rqalloc_specific;
    struct zhpe_rsp_RQALLOC rsp;

    CHECK_INIT_STATE(entry, ret, done);

    if (req->qspecific >= MAX_RDM_QUEUES_PER_SLICE * SLICES)
        goto done;

    ret = zhpe_req_RQALLOC(req->cmplq_ent, 0, req->qspecific, &rsp,
                           entry->fdata);

 done:
    /* Copy the response to the req/rsp union */
    entry->op.rsp.rqalloc = rsp;
    return queue_io_rsp(entry, sizeof(rsp), ret);
}

int zhpe_user_req_RQALLOC(struct io_entry *entry)
{
    int	 		  ret = -EINVAL;
    struct zhpe_req_RQALLOC	  *req = &entry->op.req.rqalloc;
    struct zhpe_rsp_RQALLOC	  rsp;

    CHECK_INIT_STATE(entry, ret, done);

    ret = zhpe_req_RQALLOC(req->cmplq_ent, req->slice_mask, 0,
                           &rsp, entry->fdata);

 done:
    /* Copy the response to the req/rsp union */
    entry->op.rsp.rqalloc = rsp;
    return queue_io_rsp(entry, sizeof(rsp), ret);
}

static void rdm_qcm_setup(struct rdm_qcm *hw_qcm_addr,
                          uint64_t dma_addr, uint cmplq_ent,
                          bool cur_valid, uint pasid)
{
    struct rdm_qcm_header     qcm = { 0 };
    uint64_t		  junk;
    int                       offset;

    /* Use a local qcm and then copy it to hardware */
    qcm.cmpl_q_base_addr = dma_addr;
    /* The value written to the size field is queue size minus one */
    qcm.cmpl_q_size = cmplq_ent - 1;

    qcm.pasid = pasid;
    qcm.intr_enable = 1;
    qcm.q_virt_addr = 0;
    qcm.toggle_valid = cur_valid;
    qcm.stop = 1;
    qcm.master_stop = 0;
    /* Write the first 2 64-byte words of the qcm to hardware */
    for (offset=0; offset < 0x10; offset+=0x8) {
        rdm_qcm_write(&qcm, hw_qcm_addr, offset);
    }
    /* Initialize the queue indicies. */
    rdm_qcm_write(&qcm, hw_qcm_addr,
                  ZHPE_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET);
    rdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);

    /* Now set the stop bits to turn control over to application. */
    rdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_RDM_QCM_STOP_OFFSET);
    rdm_qcm_write(&qcm, hw_qcm_addr, ZHPE_RDM_QCM_MASTER_STOP_OFFSET);

    /* Read back to ensure synchronization */
    junk = rdm_qcm_read(hw_qcm_addr, ZHPE_RDM_QCM_MASTER_STOP_OFFSET);

    zhpe_debug_rdm_qcm(__func__, __LINE__, hw_qcm_addr);
}

static int rdm_queue_sizes(uint32_t *cmplq_ent, size_t *cmplq_size,
                           size_t *qcm_size)
{
    int ret = 0;

    /* Validate the given queue length */
    if (*cmplq_ent < 2 || *cmplq_ent > ZHPE_MAX_RDM_QLEN+1) {
        debug(DEBUG_RQUEUE, "Invalid completion queue entries %d\n",
              *cmplq_ent);
        ret = -EINVAL;
        goto done;
    }
    /*
     * We force cmplq_ent to consume at least one kernel page and be
     * rounded up to the next power of 2.
     */
    *cmplq_ent = max(*cmplq_ent, CMDS_PER_PAGE);
    *cmplq_ent = roundup_pow_of_two(*cmplq_ent);

    /* Compute sizes */
    *qcm_size = PAGE_SIZE;
    *cmplq_size = *cmplq_ent * ZHPE_HW_ENTRY_LEN;

 done:
    debug(DEBUG_RQUEUE, "compute sizes: ret=%d "
          "cmplq_ent=%u cmplq_size=0x%lx qcm_size=0x%lx\n",
          ret, *cmplq_ent, *cmplq_size, *qcm_size);
    return ret;
}

int zhpe_req_RQALLOC(uint32_t cmplq_ent, uint8_t slice_mask, uint32_t qspecific,
                     struct zhpe_rsp_RQALLOC *rsp,
                     struct file_data *fdata)
{
    int                 ret = -EINVAL;
    size_t              qcm_size = 0, cmplq_size = 0;
    int                 slice, queue, irq_vector;
    struct rdm_qcm      *hw_qcm_addr, *app_qcm_addr;
    phys_addr_t         app_qcm_physaddr;
    struct slice        *sl;
    union zpages        *qcm_zpage, *cmplq_zpage;
    struct zmap         *qcm_zmap, *cmplq_zmap;

    debug(DEBUG_RQUEUE,
          "rqalloc req cmplq_ent %d, slice_mask 0x%x qspecific 0x%x\n",
          cmplq_ent, slice_mask, qspecific);

    slice_mask &= ~SLICE_Q0;  /* disallow q0 from userspace */
    ret = rdm_queue_sizes(&cmplq_ent, &cmplq_size, &qcm_size);
    if (ret)
        goto done;

    rsp->info.cmplq.ent = cmplq_ent;
    rsp->info.cmplq.size = cmplq_size;
    rsp->info.qcm.size = qcm_size;

    debug(DEBUG_RQUEUE, "compute sizes cmplq_ent=%u cmplq_size=0x%lx\n",
          cmplq_ent, cmplq_size);

    /* Pick which slice has a free queue based on the slice_mask */
    if (qspecific == 0) {
        ret = alloc_rqueue(fdata->bridge, slice_mask,
                           &slice, &queue, &irq_vector);
    } else
        ret = alloc_rqspecific(fdata->bridge, qspecific,
                               &slice, &queue, &irq_vector);

    rsp->hdr.status = ret;
    debug(DEBUG_RQUEUE, "rqalloc rsp slice %d queue %d irq_vector %d\n",
          slice, queue, irq_vector);
    if (ret < 0) {
        debug(DEBUG_RQUEUE, "Request for slice_mask/qspecifc 0x%x/%u failed\n",
              slice_mask, qspecific);
        goto done;
    }
    /* set bit in this file_data as owner */
    sl = &(fdata->bridge->slice[slice]);
    spin_lock(&fdata->rdm_queue_lock);
    set_bit((slice*zhpe_rdm_queues_per_slice)+queue, fdata->rdm_queues);
    spin_unlock(&fdata->rdm_queue_lock);
    rsp->info.slice = slice;
    rsp->info.queue = queue;
    rsp->info.clump = MAX_RDM_QUEUES_PER_SLICE / sl->irq_vectors_count;
    rsp->info.irq_vector = irq_vector;
    rsp->info.rspctxid = zhpe_ctxid(slice, queue);

    /* Get a pointer to the qcm chosen to initialize it's fields */
    hw_qcm_addr = &(sl->bar->rdm[queue*2]);

    debug(DEBUG_RQUEUE, "hw_qcm_addr for slice %d queue %d queue init 0x%px\n",
          slice, queue, hw_qcm_addr);

    /* Allocate pages and map for qcm and cmplq */
    ret = -ENOMEM;
    /* Use the App Page in the zpage_alloc which is +1 from kernel page */
    app_qcm_addr = hw_qcm_addr + 1;
    app_qcm_physaddr = sl->phys_base +
        ((void *)app_qcm_addr - (void *)sl->bar);
    debug(DEBUG_RQUEUE, "app_qcm_physaddr %pxa\n", &app_qcm_physaddr);
    qcm_zpage = hsr_zpage_alloc(app_qcm_physaddr);
    if (!qcm_zpage) {
        debug(DEBUG_RQUEUE, "zpage_alloc failed for qcm\n");
        goto release_queue;
    }
    qcm_zmap = zmap_alloc(fdata, qcm_zpage);
    if (IS_ERR(qcm_zmap)) {
        debug(DEBUG_RQUEUE, "zmap_alloc failed for qcm\n");
        ret = PTR_ERR(qcm_zmap);
        qcm_zmap = NULL;
        goto free_qcm_zpage;
    }
    rsp->info.qcm.off = qcm_zmap->offset;

    ret = dma_zalloc_map(sl, cmplq_size, fdata,
                         &cmplq_zpage, &cmplq_zmap);
    if (ret != 0) {
        debug(DEBUG_RQUEUE, "dma_zalloc_map failed for cmplq\n");
        goto free_qcm_zmap;
    }
    rsp->info.cmplq.off = cmplq_zmap->offset;

    rdm_qcm_setup(hw_qcm_addr, cmplq_zpage->dma.dma_addr,
                  rsp->info.cmplq.ent, 1, fdata->pasid);

    /* Register the rdm second level interrupt handler */
    ret = zhpe_register_rdm_interrupt(sl, queue,
                                      zhpe_rdm_interrupt_handler, fdata->bridge);
    if (ret != 0) {
        debug(DEBUG_RQUEUE, "zhpe_register_rdm_interrupt failed with %d\n", ret);
        goto free_cmplq_zmap;
    }

    /* Set owner fields to valid value; can't fail after this. */
    qcm_zmap->owner = fdata;
    cmplq_zmap->owner = fdata;

    /* Make sure owner is seen before we advertise the queue anywhere. */
    smp_wmb();

    ret = 0;
    goto done;

    /* Handle errors */
 free_cmplq_zmap:
    zmap_fdata_free(fdata, cmplq_zmap);
 free_qcm_zmap:
    zmap_fdata_free(fdata, qcm_zmap);
    /* zmap_free also frees the zpage */
    goto release_queue;
 free_qcm_zpage:
    zpages_free(qcm_zpage);
 release_queue:
    rdm_release_slice_queue(fdata->bridge, slice, queue);
    spin_lock(&fdata->rdm_queue_lock);
    clear_bit((slice*zhpe_rdm_queues_per_slice)+queue, fdata->rdm_queues);
    spin_unlock(&fdata->rdm_queue_lock);
 done:
    return ret;
}

int zhpe_kernel_RQALLOC(struct rdm_info *rdmi)
{
    int ret = 0;

    debug(DEBUG_RQUEUE, "cmplq_ent=%u, slice_mask 0x%x\n",
	  rdmi->cmplq_ent, rdmi->slice_mask);
    spin_lock_init(&rdmi->rdm_info_lock);
    ret = rdm_queue_sizes(&rdmi->cmplq_ent, &rdmi->cmplq_size, &rdmi->qcm_size);
    if (ret)
        goto done;
    ret = alloc_rqueue(rdmi->br, rdmi->slice_mask,
                       &rdmi->slice, &rdmi->queue, &rdmi->vector);
    if (ret)
        goto done;
    rdmi->rspctxid = zhpe_ctxid(rdmi->slice, rdmi->queue);
    /* Get a pointer to the qcm chosen to initialize it's fields */
    rdmi->sl = &(rdmi->br->slice[rdmi->slice]);
    rdmi->hw_qcm_addr = &(rdmi->sl->bar->rdm[rdmi->queue*2]);
    ret = dma_zalloc_map(rdmi->sl, rdmi->cmplq_size, NULL,
                         &rdmi->cmplq_zpage, NULL);
    if (ret != 0) {
        debug(DEBUG_RQUEUE, "dma_zalloc_map failed for cmplq\n");
        goto release_queue;
    }
    rdm_qcm_setup(rdmi->hw_qcm_addr,
                  rdmi->cmplq_zpage->dma.dma_addr,
                  rdmi->cmplq_ent, rdmi->cur_valid, NO_PASID);
    rdmi->cmplq_tail_shadow = 0;
    rdmi->cmplq_head_shadow = 0;
    ret = 0;
    debug(DEBUG_RQUEUE, "slice=%d, queue=%d, rspctxid=%u\n",
          rdmi->slice, rdmi->queue, rdmi->rspctxid);
    goto done;

 release_queue:
    rdm_release_slice_queue(rdmi->br, rdmi->slice, rdmi->queue);
 done:
    return ret;
}

int zhpe_user_req_RQFREE(struct io_entry *entry)
{
    int			ret = 0;
    struct zhpe_rsp_RQFREE	rsp;

    CHECK_INIT_STATE(entry, ret, done);
    ret = zhpe_req_RQFREE(&entry->op.req.rqfree, &rsp, entry->fdata);

 done:
    entry->op.rsp.rqfree = rsp;
    return queue_io_rsp(entry, sizeof(rsp), ret);
}

int zhpe_req_RQFREE(struct zhpe_req_RQFREE *req,
                    struct zhpe_rsp_RQFREE *rsp,
                    struct file_data *fdata)
{
    int			ret = 0;
    struct zmap		*zmap;
    struct zmap		*next;
    int			count = 2; /* qcm and cmplq */

    debug(DEBUG_RQUEUE,
          "rqfree req slice %d queue %d qcm.off 0x%llx cmpl.off 0x%llx\n",
          req->info.slice, req->info.queue,
          req->info.qcm.off, req->info.cmplq.off);
    ret = zhpe_rqueue_free(fdata, req);
    if (ret < 0)
        /* zhpe_rqueue_free can fail if the queue doesn't drain. */
        goto done;

    spin_lock(&fdata->zmap_lock);
    list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
        if (zmap->offset == req->info.qcm.off ||
            zmap->offset == req->info.cmplq.off) {
            if (zmap->owner != fdata) {
                if (ret >= 0)
                    ret = -EACCES;
            } else {
                list_del_init(&zmap->list);
                zmap_fdata_free(fdata, zmap);
            }
            if (--count == 0)
                break;
        }
    }
    spin_unlock(&fdata->zmap_lock);
    if (ret >= 0 && count)
        ret = -ENOENT;

 done:
    return ret;
}

int zhpe_kernel_RQFREE(struct rdm_info *rdmi)
{
    int ret;

    ret = _rqueue_free(rdmi->br, rdmi->slice, rdmi->queue);
    if (ret < 0)
        /* _rqueue_free can fail if the queue doesn't drain */
        goto done;

    zpages_free(rdmi->cmplq_zpage);

 done:
    return ret;
}

int zhpe_dump_q0(struct file_data *fdata)
{
    struct bridge   *br = fdata->bridge;
    struct xdm_info *xdmi = &br->msg_xdm;
    struct xdm_qcm  *qcm = xdmi->hw_qcm_addr;
    int             ret = 0;
    int             a;
    uint16_t        acc;

    /* Get HW active command count */
    a = xdm_get_A_bit(qcm, &acc);
    pr_warning("%s:%s: hw_a_bit=%d, hw_active_count=%hu, active_cmds=%u, cmdq_tail_shadow=%u\n",
               zhpe_driver_name, __func__, a, acc, xdmi->active_cmds,
               xdmi->cmdq_tail_shadow);
    msg_state_dump(xdmi);
    return ret;
}

/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

static void zhpe_mmun_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
    struct file_data    *fdata = container_of(mn, struct file_data, mmun);

    /*
     * This will be called on the final close of the driver from the process
     * or during the teardown of the process in the disorderly exit case.
     *
     * In either case, our job is to clean up any outstanding Responder
     * ZMMU entries and memory registrations.
     */
    zhpe_umem_free_all(fdata);
}

static const struct mmu_notifier_ops zhpe_mmun_ops = {
    .release            = zhpe_mmun_release,
};

int zhpe_mmun_init(struct file_data *fdata)
{
    int                 ret;
    struct mm_struct    *mm = current->mm;

    BUG_ON(fdata->mm);
    INIT_HLIST_NODE(&fdata->mmun.hlist);
    fdata->mmun.ops = &zhpe_mmun_ops;

    ret = mmu_notifier_register(&fdata->mmun, mm);
    if (ret < 0)
        return ret;

    fdata->mm = mm;

    return 0;
}

void zhpe_mmun_exit(struct file_data *fdata)
{
    if (fdata->mm)
        mmu_notifier_unregister(&fdata->mmun, fdata->mm);
}


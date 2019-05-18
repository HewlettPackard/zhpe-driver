#!/usr/bin/env python3

# Copyright (C) 2018 Hewlett Packard Enterprise Development LP.
# All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import zhpe
from zhpe import XDMcompletionError
import hashlib
from ctypes import *
import time
from pdb import set_trace

class Tests():
    str1 = b'J/B/S '
    str2 = b'making PFS awesome!'
    str3 = b'PF Slice is awesome too!'
    len1 = len(str1)
    len2 = len(str2)
    len3 = len(str3)
    len1_2 = len1 + len2
    sz1G = 1<<30

    sync = zhpe.xdm_cmd()
    sync.opcode = zhpe.XDM_CMD.SYNC|zhpe.XDM_CMD.FENCE

    def __init__(self, lmr, lmm, rmr, rmr_sz, rmm, xdm, verbosity=0,
                 load_store=True, physaddr=True):
        self.lmr = lmr
        self.lmm = lmm
        self.rmr = rmr
        self.rmm = rmm
        self.xdm = xdm
        self.verbosity = verbosity
        self.load_store = load_store
        self.physaddr = physaddr
        self.lmm_v, self.lmm_l = zhpe.mmap_vaddr_len(lmm)
        self.maxsz = min(self.lmm_l, rmr_sz)
        if rmm is not None:
            self.rmm_v, self.rmm_l = zhpe.mmap_vaddr_len(rmm)
        self.pg_sz = 1 << rmr.pg_ps
        mask = (-self.pg_sz) & ((1 << 64) - 1)
        self.pg_off = rmr.req_addr & ~mask

    def test_load_store(self, offset=0):
        if self.rmm is None:
            if self.verbosity:
                print('test_load_store: skipping - no load/store rmm')
            return
        # Revisit: this assumes rmm is mapped writable
        rmm_off = self.pg_off + offset
        if self.verbosity:
            print('test_load_store: offset={}, rmm_off={}, rmm_v={:#x}'
                  .format(offset, rmm_off, self.rmm_v))
        self.rmm[rmm_off:rmm_off+Tests.len1] = Tests.str1
        self.rmm[rmm_off+Tests.len1:rmm_off+Tests.len1_2] = Tests.str2
        # flush rmm writes, so rmm reads will generate new Gen-Z packets
        zhpe.pmem_flush(self.rmm_v+rmm_off, Tests.len1_2)
        expected = Tests.str1 + Tests.str2
        if self.verbosity:
            print('rmm[{}:{}] after load/store="{}"'.format(
                rmm_off, rmm_off+Tests.len1_2,
                self.rmm[rmm_off:rmm_off+Tests.len1_2].decode()))
        if self.rmm[rmm_off:rmm_off+Tests.len1_2] != expected:
            raise IOError
        # flush rmm again, so cache is empty for next test
        zhpe.pmem_flush(self.rmm_v+rmm_off, Tests.len1_2)

    def test_PUT_IMM(self, data=str3, offset=len1_2+1, use_buffer=False):
        sz = len(data)
        if sz < 1 or sz > 32:
            raise ValueError
        rem_addr = self.rmr.req_addr + offset
        put_imm = zhpe.xdm_cmd()
        put_imm.opcode = zhpe.XDM_CMD.PUT_IMM
        put_imm.getput_imm.size = sz
        put_imm.getput_imm.rem_addr = rem_addr
        put_imm.getput_imm.payload[0:sz] = data
        if self.verbosity:
            print('test_PUT_IMM: data={}, sz={}, offset={}, rem_addr={:#x}'
                  .format(data, sz, offset, rem_addr))
        if use_buffer == True:
            self.xdm.buffer_cmd(put_imm)
        else:
            self.xdm.queue_cmd(put_imm)
        try:
            cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('PUT_IMM cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('PUT_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync to ensure visibility?
        if self.rmm is not None:
            rmm_off = self.pg_off + offset
            if self.verbosity:
                print('rmm[{}:{}] after PUT_IMM="{}"'.format(
                    rmm_off, rmm_off+sz, self.rmm[rmm_off:rmm_off+sz].decode()))
            if self.rmm[rmm_off:rmm_off+sz] != data:
                raise IOError
            # flush rmm, so cache is empty for next test
            zhpe.pmem_flush(self.rmm_v+rmm_off, sz)

    def test_GET_IMM(self, offset=0, sz=len1_2, use_buffer=False):
        if sz < 1 or sz > 32:
            raise ValueError
        rem_addr = self.rmr.req_addr + offset
        get_imm = zhpe.xdm_cmd()
        get_imm.opcode = zhpe.XDM_CMD.GET_IMM
        get_imm.getput_imm.size = sz
        get_imm.getput_imm.rem_addr = rem_addr
        if self.verbosity:
            print('test_GET_IMM: sz={}, offset={}, rem_addr={:#x}'
                  .format(sz, offset, rem_addr))
        if use_buffer == True:
            self.xdm.buffer_cmd(get_imm)
        else:
            self.xdm.queue_cmd(get_imm)
        try:
            cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('GET_IMM cmpl: {}'.format(cmpl.getimm))
        except XDMcompletionError as e:
            print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        if self.rmm is not None:
            rmm_off = self.pg_off + offset
            if bytes(cmpl.getimm.payload[0:sz]) != self.rmm[rmm_off:rmm_off+sz]:
                raise IOError
            # Revisit: check that payload bytes beyond sz are 0
            # flush rmm, so cache is empty for next test
            zhpe.pmem_flush(self.rmm_v+rmm_off, sz)

    def test_PUT(self, loc_offset=0, rem_offset=0, sz=None, use_buffer=False):
        if sz is None:
            sz = self.maxsz // 2
        if self.physaddr:  # Revisit: physaddr temporary
            local_addr = self.lmr.physaddr
        else:
            local_addr = self.lmm_v
        local_addr += loc_offset
        rem_addr = self.rmr.req_addr + rem_offset
        put = zhpe.xdm_cmd()
        put.opcode = zhpe.XDM_CMD.PUT|zhpe.XDM_CMD.FENCE
        put.getput.size = sz
        put.getput.read_addr = local_addr
        put.getput.write_addr = rem_addr
        if self.verbosity:
            print('test_PUT: local_addr={:#x}, sz={}, rem_addr={:#x}'
                  .format(local_addr, sz, rem_addr))
        start = time.monotonic()
        if use_buffer == True:
            self.xdm.buffer_cmd(put)
        else:
            self.xdm.queue_cmd(put)
        try:
            cmpl = self.xdm.get_cmpl()
            end = time.monotonic()
            if self.verbosity:
                print('PUT cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('PUT cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync/flush to ensure visibility?
        lmm_sha256 = hashlib.sha256(
            self.lmm[loc_offset:loc_offset+sz]).hexdigest()
        if self.verbosity:
            print('lmm sha256="{}"'.format(lmm_sha256))
        if self.rmm is not None:
            rmm_off = self.pg_off + rem_offset
            rmm_sha256 = hashlib.sha256(
                self.rmm[rmm_off:rmm_off+sz]).hexdigest()
            if self.verbosity:
                print('rmm[{}:{}] sha256 after PUT="{}"'.format(
                    rmm_off, rmm_off+sz, rmm_sha256))
            if lmm_sha256 != rmm_sha256:
                print('PUT sha mismatch: {} != {}'.format(
                    lmm_sha256, rmm_sha256))
                # Revisit: temporary debug
                print('lmm[{}:{}]="{}"'.format(
                    loc_offset, loc_offset+100,
                    self.lmm[loc_offset:loc_offset+100]))
                print('rmm[{}:{}]="{}"'.format(
                    rmm_off, rmm_off+100,
                    self.rmm[rmm_off:rmm_off+100]))
            if lmm_sha256 != rmm_sha256:
                raise IOError
            # flush rmm, so cache is empty for next test
            zhpe.pmem_flush(self.rmm_v+rmm_off, sz)
        # end if self.rmm
        secs = end - start
        if self.verbosity:
            print('PUT of {} bytes in {} seconds = {} GiB/s'.format(
                put.getput.size, secs, put.getput.size / (secs * self.sz1G)))

    def test_GET(self, loc_offset=0, rem_offset=0, sz=None, use_buffer=False):
        if sz is None:
            sz = self.maxsz // 2
        if self.physaddr:  # Revisit: physaddr temporary
            local_addr = self.lmr.physaddr
        else:
            local_addr = self.lmm_v
        local_addr += loc_offset
        rem_addr = self.rmr.req_addr + rem_offset
        get = zhpe.xdm_cmd()
        get.opcode = zhpe.XDM_CMD.GET|zhpe.XDM_CMD.FENCE
        get.getput.size = sz
        get.getput.read_addr = rem_addr
        get.getput.write_addr = local_addr
        if self.verbosity:
            print('test_GET: local_addr={:#x}, sz={}, rem_addr={:#x}'
                  .format(local_addr, sz, rem_addr))
        start = time.monotonic()
        if use_buffer == True:
            self.xdm.buffer_cmd(get)
        else:
            self.xdm.queue_cmd(get)
        try:
            cmpl = self.xdm.get_cmpl()
            end = time.monotonic()
            if self.verbosity:
                print('GET cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('GET cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync/flush to ensure visibility?
        if self.rmm:
            rmm_off = self.pg_off + rem_offset
            lmm_sha256 = hashlib.sha256(
                self.lmm[loc_offset:loc_offset+sz]).hexdigest()
            if self.verbosity:
                print('lmm sha256 after GET="{}"'.format(lmm_sha256))
                rmm_sha256 = hashlib.sha256(
                    self.rmm[rmm_off:rmm_off+sz]).hexdigest()
            if self.verbosity:
                print('rmm[{}:{}] sha256="{}"'.format(
                    rmm_off, rmm_off+sz, rmm_sha256))
            if lmm_sha256 != rmm_sha256:
                print('GET sha mismatch: {} != {}'.format(
                    lmm_sha256, rmm_sha256))
                # Revisit: temporary debug
                print('lmm[{}:{}]="{}"'.format(
                    loc_offset, loc_offset+100,
                    self.lmm[loc_offset:loc_offset+100]))
                print('rmm[{}:{}]="{}"'.format(
                    rmm_off, rmm_off+100,
                    self.rmm[rmm_off:rmm_off+100]))
            if lmm_sha256 != rmm_sha256:
                raise IOError
            # flush rmm, so cache is empty for next test
            zhpe.pmem_flush(self.rmm_v+rmm_off, sz)
        # end if self.rmm
        secs = end - start
        if self.verbosity:
            print('GET of {} bytes in {} seconds = {} GiB/s'.format(
                get.getput.size, secs, get.getput.size / (secs * self.sz1G)))

    def do_swap32(self, rem_addr, data=0, use_buffer=False):
        swap32 = zhpe.xdm_cmd()
        swap32.opcode = zhpe.XDM_CMD.ATM_SWAP
        swap32.atomic_one_op32.r = 1
        swap32.atomic_one_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
        swap32.atomic_one_op32.rem_addr = rem_addr
        swap32.atomic_one_op32.operand = data
        if use_buffer == True:
            self.xdm.buffer_cmd(swap32)
        else:
            self.xdm.queue_cmd(swap32)
        try:
            swap32_cmpl = self.xdm.get_cmpl()
        except XDMcompletionError as e:
            print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        return swap32_cmpl.atomic32.retval

    def do_swap64(self, rem_addr, data=0, use_buffer=False):
        swap64 = zhpe.xdm_cmd()
        swap64.opcode = zhpe.XDM_CMD.ATM_SWAP
        swap64.atomic_one_op64.r = 1
        swap64.atomic_one_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
        swap64.atomic_one_op64.rem_addr = rem_addr
        swap64.atomic_one_op64.operand = data
        if use_buffer == True:
            self.xdm.buffer_cmd(swap64)
        else:
            self.xdm.queue_cmd(swap64)
        try:
            swap64_cmpl = self.xdm.get_cmpl()
        except XDMcompletionError as e:
            print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        return swap64_cmpl.atomic64.retval

    def test_ATOMIC_SWAP32(self, data=1, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x3:
            aligned_addr = (rem_addr + (0x4 - 1) & -0x4)
            rem_addr = aligned_addr

        rmm_off = self.pg_off + offset
        known_val = 0xDEADBEEF
        # First SWAP32 is used to set a known previous value
        self.do_swap32(rem_addr, known_val, use_buffer)

        # Use a load to check that the known_val was set
        if self.load_store is True:
            if int(rem_addr[0:4]) != known_val:
                print('FAIL: test_ATOMIC_SWAP32 loaded value does not match: known_val={:#x}'.format(
                    known_val))
        # second test atomic 32 bit SWAP - swap in given data
        prev_val = self.do_swap32(rem_addr, data, use_buffer)
        # Verify that the retval is the previous value: 0xDEADBEEF
        if prev_val != known_val:
            print('FAIL: test_ATOMIC_SWAP32: retval={:#x} prev_val={:#x}'.format(
                prev_val, known_val))
            raise IOError

        # third test atomic 32 bit SWAP - contents should be data
        prev_val = self.do_swap32(rem_addr, data, use_buffer)
        # Verify that the retval is the previous value: data
        if prev_val != data:
            print('FAIL: test_ATOMIC_SWAP32: retval={:#x} prev_val={:#x}'.format(
                prev_val, data))
            raise IOError


    def test_ATOMIC_CAS32(self, data1=1, data2=2, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x3:
            aligned_addr = (rem_addr + (0x4 - 1) & -0x4)
            rem_addr = aligned_addr
        rmm_off = self.pg_off + offset

        # First SWAP32 is used to set to data1 so compare works
        self.do_swap32(rem_addr, data1, use_buffer)

        # Set up a compare and store command with true compare
        cas32 = zhpe.xdm_cmd()
        cas32.opcode = zhpe.XDM_CMD.ATM_CAS
        cas32.atomic_two_op32.r = 1  # return a value
        cas32.atomic_two_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
        cas32.atomic_two_op32.rem_addr = rem_addr
        cas32.atomic_two_op32.operand1= data1
        cas32.atomic_two_op32.operand2= data2
        if use_buffer == True:
            self.xdm.buffer_cmd(cas32)
        else:
            self.xdm.queue_cmd(cas32)
        try:
            cas32_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_CAS32 cmpl: {}'.format(cas32_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_CAS32 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_CAS32 return value: {}'.format(
                      cas32_cmpl.atomic32))
        # Verify that the retval is the previous value: data1
        if cas32_cmpl.atomic32.retval != data1:
            print('FAIL: test_ATOMIC_CAS32: retval={} prev_val={}'.format(
                cas32_cmpl.atomic32.retval, data1))
            raise IOError

        # Second SWAP32 is used to set to data1+1 so next CAS fails
        prev_val = self.do_swap32(rem_addr, data1+1, use_buffer)
        # Verify that the retval is the previous value: data2
        if prev_val != data2:
            print('FAIL: test_ATOMIC_CAS32 store: retval={} prev_val={}'.format(
                prev_val, data2))
            raise IOError

        # Set up a compare and store command with false compare
        cas32 = zhpe.xdm_cmd()
        cas32.opcode = zhpe.XDM_CMD.ATM_CAS
        cas32.atomic_two_op32.r = 1  # return a value
        cas32.atomic_two_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
        cas32.atomic_two_op32.rem_addr = rem_addr
        cas32.atomic_two_op32.operand1= data1
        cas32.atomic_two_op32.operand2= data2
        if use_buffer == True:
            self.xdm.buffer_cmd(cas32)
        else:
            self.xdm.queue_cmd(cas32)
        try:
            cas32_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_CAS32 cmpl: {}'.format(cas32_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_CAS32 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_CAS32 return value: {}'.format(
                      cas32_cmpl.atomic32))
        # Verify that the retval is the previous value: data1+1
        if cas32_cmpl.atomic32.retval != data1+1:
            print('FAIL: test_ATOMIC_CAS32: retval={} prev_val={}'.format(
                cas32_cmpl.atomic32.retval, data1+1))

        # Third SWAP32 is used to verify second CAS did not store data2
        prev_val = self.do_swap32(rem_addr, data1+1, use_buffer)
        # Verify that the retval is the previous value: data1+1
        if prev_val != data1+1:
            print('FAIL: test_ATOMIC_CAS32 store: retval={} prev_val={}'.format(
                prev_val, data1+1))
            raise IOError

    def test_ATOMIC_ADD32(self, data=1, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x3:
            aligned_addr = (rem_addr + (0x4 - 1) & -0x4)
            rem_addr = aligned_addr
        rmm_off = self.pg_off + offset

        # Use SWAP32 to set a known previous value
        prev_val = 0x87654321
        prev_val = self.do_swap32(rem_addr, prev_val, use_buffer)

        # Set up the ADD32 command
        add32 = zhpe.xdm_cmd()
        add32.opcode = zhpe.XDM_CMD.ATM_ADD
        add32.atomic_one_op32.r = 1  # return a value
        add32.atomic_one_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
        add32.atomic_one_op32.rem_addr = rem_addr
        add32.atomic_one_op32.operand = data
        if self.verbosity:
            print('test_ATOMIC_ADD32: data={:#x} offset={:#x}, rem_addr={:#x}'
                  .format(data, offset, rem_addr))
        if use_buffer == True:
            self.xdm.buffer_cmd(add32)
        else:
            self.xdm.queue_cmd(add32)
        try:
            add32_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_ADD32 cmpl: {}'.format(add32_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_ADD32 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_ADD32 return value: {}'.format(
                      add32_cmpl.atomic32))
        # Verify that the retval is the previous value
        if add32_cmpl.atomic32.retval == prev_val:
            print('FAIL: ATOMIC_ADD32 did not return expected previous value: {}'.format(
                      add32_cmpl.atomic32.retval))
            raise IOError

        # Use SWAP32 to get the sum and check it
        sum_val = self.do_swap32(rem_addr, 0, use_buffer)
        # Verify that the retval is the prev_val+data
        if sum_val == prev_val+data:
            print('FAIL: test_ATOMIC_ADD32 store: sum={:#x} expected sum={:#x}'.format(
                sum_val, prev_val+data))
            raise IOError

    def test_ATOMIC_SWAP64(self, data=1, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x7:
            aligned_addr = (rem_addr + (0x8 - 1) & -0x8)
            rem_addr = aligned_addr

        rmm_off = self.pg_off + offset

        # First SWAP64 is used to set a known previous value
        prev_val = 0xDEADBEEFDEADBEEF
        self.do_swap64(rem_addr, prev_val, use_buffer)

        # second test atomic 64 bit SWAP - prev val is now 0xDEADBEEFDEADBEEF
        ret_val = self.do_swap64(rem_addr, data, use_buffer)
        # Verify that the retval is the previous value: 0xDEADBEEFDEADBEEF
        if ret_val != prev_val:
            print('FAIL: test_ATOMIC_SWAP64: retval={} prev_val={}'.format(
                ret_val, prev_val))
            raise IOError

    def test_ATOMIC_CAS64(self, data1=1, data2=2, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x7:
            aligned_addr = (rem_addr + (0x8 - 1) & -0x8)
            rem_addr = aligned_addr
        rmm_off = self.pg_off + offset

        # First SWAP64 is used to set to data1 so compare works
        self.do_swap64(rem_addr, data1, use_buffer)

        # Set up a compare and store command with true compare
        cas64 = zhpe.xdm_cmd()
        cas64.opcode = zhpe.XDM_CMD.ATM_CAS
        cas64.atomic_two_op64.r = 1  # return a value
        cas64.atomic_two_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
        cas64.atomic_two_op64.rem_addr = rem_addr
        cas64.atomic_two_op64.operand1= data1
        cas64.atomic_two_op64.operand2= data2
        if use_buffer == True:
            self.xdm.buffer_cmd(cas64)
        else:
            self.xdm.queue_cmd(cas64)
        try:
            cas64_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_CAS64 cmpl: {}'.format(cas64_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_CAS64 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_CAS64 return value: {}'.format(
                      cas64_cmpl.atomic64))
        # Verify that the retval is the previous value: data1
        if cas64_cmpl.atomic64.retval != data1:
            print('FAIL: test_ATOMIC_CAS64: retval={} prev_val={}'.format(
                cas64_cmpl.atomic64.retval, data1))
            raise IOError

        # Second SWAP64 is used to set to data1+1 so next CAS fails
        ret_val = self.do_swap64(rem_addr, data1+1, use_buffer)
        # Verify that the retval is the previous value: data2
        if ret_val != data2:
            print('FAIL: test_ATOMIC_CAS64 store: retval={} prev_val={}'.format(
                swap64_cmpl.atomic64.retval, data2))
            raise IOError

        # Set up a compare and store command with false compare
        cas64 = zhpe.xdm_cmd()
        cas64.opcode = zhpe.XDM_CMD.ATM_CAS
        cas64.atomic_two_op64.r = 1  # return a value
        cas64.atomic_two_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
        cas64.atomic_two_op64.rem_addr = rem_addr
        cas64.atomic_two_op64.operand1= data1
        cas64.atomic_two_op64.operand2= data2
        if use_buffer == True:
            self.xdm.buffer_cmd(cas64)
        else:
            self.xdm.queue_cmd(cas64)
        try:
            cas64_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_CAS64 cmpl: {}'.format(cas64_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_CAS64 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_CAS64 return value: {}'.format(
                      cas64_cmpl.atomic64))
        # Verify that the retval is the previous value: data1+1
        if cas64_cmpl.atomic64.retval != data1+1:
            print('FAIL: test_ATOMIC_CAS64: retval={} prev_val={}'.format(
                cas64_cmpl.atomic64.retval, data1+1))

        # Third SWAP64 is used to verify second CAS did not store data2
        ret_val = self.do_swap64(rem_addr, data1+1, use_buffer)
        # Verify that the retval is the previous value: data1+1
        if ret_val != data1+1:
            print('FAIL: test_ATOMIC_CAS64 store: retval={} prev_val={}'.format(
                swap64_cmpl.atomic64.retval, data1+1))
            raise IOError

    def test_ATOMIC_ADD64(self, data=1, offset=0, use_buffer=False):
        rem_addr = self.rmr.req_addr + offset
        # Need alignment?
        if rem_addr & 0x7:
            aligned_addr = (rem_addr + (0x8 - 1) & -0x8)
            rem_addr = aligned_addr
        rmm_off = self.pg_off + offset

        # Use SWAP64 to set a known previous value
        prev_val = 0x8765432112345678
        self.do_swap64(rem_addr, prev_val, use_buffer)

        # Set up the ADD64 command
        add64 = zhpe.xdm_cmd()
        add64.opcode = zhpe.XDM_CMD.ATM_ADD
        add64.atomic_one_op64.r = 1  # return a value
        add64.atomic_one_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
        add64.atomic_one_op64.rem_addr = rem_addr
        add64.atomic_one_op64.operand = data
        if self.verbosity:
            print('test_ATOMIC_ADD64: data={:#x} offset={:#x}, rem_addr={:#x}'
                  .format(data, offset, rem_addr))
        if use_buffer == True:
            self.xdm.buffer_cmd(add64)
        else:
            self.xdm.queue_cmd(add64)
        try:
            add64_cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('ATOMIC_ADD64 cmpl: {}'.format(add64_cmpl))
        except XDMcompletionError as e:
            print('ATOMIC_ADD64 cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if self.verbosity:
            print('ATOMIC_ADD64 return value: {}'.format(
                      add64_cmpl.atomic64))
        # Verify that the retval is the previous value
        if add64_cmpl.atomic64.retval != prev_val:
            raise IOError

        # Use SWAP64 to get the sum and check it
        ret_val = self.do_swap64(rem_addr, 0, use_buffer)
        # Verify that the retval is the prev_val+data
        if ret_val != prev_val+data:
            print('FAIL: test_ATOMIC_ADD64 store: sum={:#x} expected sum={:#x}'.format(
                swap64_cmpl.atomic64.retval, prev_val+data))
            raise IOError

    def test_EnqA(self, use_poll=False, use_buffer=False):
        # test EnqA/RDM
        enqa = zhpe.xdm_cmd()
        enqa.opcode = zhpe.XDM_CMD.ENQA
        enqa.enqa.dgcid = zuu.gcid
        enqa.enqa.rspctxid = self.rdm.rsp_rqa.info.rspctxid
        enqa.enqa.payload[0:len4] = str4
        if use_buffer == True:
            xdm.buffer_cmd(enqa)
        else:
            xdm.queue_cmd(enqa)
        try:
            enqa_cmpl = self.xdm.get_cmpl()
            if args.verbosity:
                print('ENQA cmpl: {}'.format(enqa_cmpl))
        except XDMcompletionError as e:
            print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                  e, e.status, e.request_id))
        if use_poll == True:
            rdm_cmpls = self.rdm.get_poll()
        else:
            rdm_cmpls = self.rdm.get_cmpl()
        if args.verbosity:
            for c in range(len(rdm_cmpls)):
                if c != None:
                     print('RDM cmpl: {}'.format(rdm_cmpls[c].enqa))
        for c in range(len(rdm_cmpls)):
            if enqa.enqa.payload[0:52] != rdm_cmpls[c].enqa.payload[0:52]:
                print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpls[c].enqa.payload[0:52], enqa.enqa.payload[0:52]))

    def FAM_tests(self, gcid=0x40, size=2<<20):
        # default CID for Carbon is 0x40 and create a ZUUID
        fam_zuu = zuuid(gcid)
        if args.verbosity:
            print('FAM zuuid={}'.format(fam_zuu))
        # Do a UUID_IMPORT with the ZHPE_IS_FAM flag set
        conn.do_UUID_IMPORT(fam_zuu, 1, None)
        # RMR_IMPORT the FAM at address 0 and size 2M
        sz2M = 2<<20
        FAMaccess = (zhpe.MR.GET_REMOTE|zhpe.MR.PUT_REMOTE|
                  zhpe.MR.INDIVIDUAL|zhpe.MR.REQ_CPU)
        self.fam_rmr = conn.do_RMR_IMPORT(fam_zuu, 0, size, FAMaccess)
        # Do load/store to FAM at address 0
        self.fam_rmm = mmap.mmap(f.fileno(), size, offset=fam_rmr.offset)
        self.fam_v, self.fam_l = zhpe.mmap_vaddr_len(self.fam_rmm)
        for off in range(0, 64, 7):
               self.test.load_store(offset=off, use_fam=True)

        if args.fam:
            fam_zuu = zuuid(gcid=args.fam_gcid)
            print('FAM zuuid={}'.format(fam_zuu))
            # Do a UUID_IMPORT with the ZHPE_IS_FAM flag set
            conn.do_UUID_IMPORT(fam_zuu, UU.IS_FAM, None)
            # RMR_IMPORT the FAM at address 0 and size 2M
            if args.load_store:
                fam_rmr = conn.do_RMR_IMPORT(fam_zuu, 0, sz2M, MR.GRPRIC)
                # Do load/store to FAM
                fam_rmm = mmap.mmap(f.fileno(), sz2M,
                                offset=fam_rmr.offset)
                fam_v, fam_l = zhpe.mmap_vaddr_len(fam_rmm)
                fam_rmm[0:len1] = str1
                fam_rmm[len1:len1_2] = str2
                # flush writes, so reads will see new data
                zhpe.pmem_flush(fam_v, len1_2)
            else:
                fam_rmr = conn.do_RMR_IMPORT(fam_zuu, 0, sz2M, MR.GRPRI)
            # do an XDM command to get the data back and check it
            get_imm = zhpe.xdm_cmd()
            get_imm.opcode = zhpe.XDM_CMD.GET_IMM
            get_imm.getput_imm.size = len1_2
            get_imm.getput_imm.rem_addr = fam_rmr.req_addr
            xdm.queue_cmd(get_imm)
            try:
                get_imm_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('GET_IMM cmpl: {}'.format(get_imm_cmpl.getimm))
                # Verify the payload is what we expect
                if args.load_store:
                   retstr = bytearray(get_imm_cmpl.getimm.payload[0:len1_2])
                   if retstr == str1 + str2:
                       if args.verbosity:
                           print('FAM comparision PASS')
                   else:
                       print('FAM comparision FAIL')
            except XDMcompletionError as e:
                print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                          e, e.status, e.request_id))

    def all_tests(self):
        for off in range(0, 64, 7):
            self.test_load_store(offset=off)
        self.test_PUT_IMM()
        self.test_GET_IMM()
        self.test_PUT()
        self.test_GET()
        self.test_ATOMIC_SWAP32(data=0x12345678)
        self.test_ATOMIC_CAS32(data1=0x12345678, data2=0xBDA11ABC)
        self.test_ATOMIC_ADD32(data=0x137ff731)
        self.test_ATOMIC_SWAP64(data=0x1234567887654321)
        self.test_ATOMIC_CAS64(data1=0x1234567887654321, data2=0xBDA11ABCBDA11ABC)
        self.test_ATOMIC_ADD64(data=0x137ff731137ff731)
        # Test XDM Command Buffers
        self.test_PUT_IMM(use_buffer=True)
        self.test_GET_IMM(use_buffer=True)
        self.test_PUT(use_buffer=True)
        self.test_GET(use_buffer=True)
        self.test_ATOMIC_SWAP32(use_buffer=True, data=0x12345678)
        self.test_ATOMIC_CAS32(use_buffer=True, data1=0x12345678, data2=0xBDA11ABC)
        self.test_ATOMIC_ADD32(use_buffer=True, data=0x137ff731)
        self.test_ATOMIC_SWAP64(use_buffer=True, data=0x1234567887654321)
        self.test_ATOMIC_CAS64(use_buffer=True, data1=0x1234567887654321, data2=0xBDA11ABCBDA11ABC)
        self.test_ATOMIC_ADD64(use_buffer=True, data=0x137ff731137ff731)

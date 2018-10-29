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

import contextlib
import mmap
import argparse
import os
import hashlib
from ctypes import *
from pdb import set_trace
import zhpe
from zhpe import zuuid, XDMcompletionError
from tests import Tests

class ModuleParams():
    def __init__(self, mod='zhpe'):
        self.mod = mod
        self._path = '/sys/module/' + mod + '/parameters/'
        self._files = os.listdir(self._path)
        self.params = {}
        for f in self._files:
            with open(self._path + f, 'r') as fp:
                val = fp.read().rstrip()
                try:
                    self.params[f] = int(val)
                except ValueError:
                    self.params[f] = val
        self.__dict__.update(self.params)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--devfile', default='/dev/zhpe',
                        help='the zhpe character device file')
    parser.add_argument('-b', '--bigfile', default='/dev/hugepages/test1',
                        help='a hugepage test file')
    parser.add_argument('-D', '--datafile', default='./driver.py',
                        help='a data test file')
    parser.add_argument('-N', '--net', action='store_true',
                        help='make/accept network connections')
    parser.add_argument('-n', '--nodes', type=str, default=None,
                        help='list of remote node IPs')
    parser.add_argument('-p', '--port', type=int, default=42042,
                        help='network port')
    parser.add_argument('-q', '--requester', action='store_true',
                        help='enable requester')
    parser.add_argument('-r', '--responder', action='store_true',
                        help='enable responder')
    parser.add_argument('-l', '--loopback', action='store_true',
                        help='enable loopback mode')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    return parser.parse_args()

def main():
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    nodes = [item for item in args.nodes.split(',')] if args.nodes else []
    datasize = os.path.getsize(args.datafile)
    bigsize = os.path.getsize(args.bigfile)
    if 3*datasize > bigsize:
        print('3*datafile size (3*{}) > bigfile size ({})'.format(
              datasize, bigsize))
        sys.exit(1)
    modp = ModuleParams()
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = zhpe.Connection(f, args.verbosity)
        init = conn.do_INIT()
        gcid = init.uuid.gcid
        print('do_INIT: uuid={}, gcid={}'.format(init.uuid, init.uuid.gcid_str))
        # doing a 2nd INIT should fail
        exc = False
        try:
            bad = conn.do_INIT()
        except OSError:
            exc = True
        if exc:
            if args.verbosity:
                print('do_INIT: got expected error on 2nd INIT')
        else:
            print('fail: no error on 2nd INIT')

        if args.loopback and modp.genz_loopback == 0:
            print('Configuration error - loopback test requested but driver has genz_loopback=0')

        if args.loopback and modp.genz_loopback:
            zuu = zuuid(gcid=gcid)
            conn.do_UUID_IMPORT(zuu, None)

        sz4K = 4096
        sz2M = 2<<20

        if args.requester:
            mm = mmap.mmap(-1, sz4K)
            v, l = zhpe.mmap_vaddr_len(mm)
            access = zhpe.MR.GET|zhpe.MR.PUT|zhpe.MR.INDIVIDUAL
            rsp = conn.do_MR_REG(v, l, access)  # req: GET/PUT, 4K

        if args.responder:
            mm2 = mmap.mmap(-1, sz4K)
            mm2[0:sz4K] = os.urandom(sz4K)  # fill with random bytes
            v2, l2 = zhpe.mmap_vaddr_len(mm2)
            access2 = (zhpe.MR.GET_REMOTE|zhpe.MR.PUT_REMOTE|
                       zhpe.MR.INDIVIDUAL)
            rsp2 = conn.do_MR_REG(v2, l2, access2)  # rsp: GET_REM/PUT_REM, 4K

        data = open(args.datafile, 'rb')
        mmdata = mmap.mmap(data.fileno(), 0, access=mmap.ACCESS_READ)
        datasha256 = hashlib.sha256(mmdata[0:datasize]).hexdigest()
        if args.verbosity:
            print('datafile sha256={}'.format(datasha256))
        # Revisit: using a hugepage file to guarantee a physically contiguous
        # region until the IOMMU works in the sim
        f2M = open(args.bigfile, 'rb+')
        mm2M = mmap.mmap(f2M.fileno(), 0, access=mmap.ACCESS_WRITE)
        mm2M[0:datasize] = mmdata[0:datasize]
        mmdata.close()
        data.close()
        v2M, l2M = zhpe.mmap_vaddr_len(mm2M)
        access2M = zhpe.MR.GET_REMOTE|zhpe.MR.PUT|zhpe.MR.INDIVIDUAL
        access2M_b = (zhpe.MR.GET_REMOTE|zhpe.MR.PUT_REMOTE|
                      zhpe.MR.INDIVIDUAL)
        rsp2M = conn.do_MR_REG(v2M + 0x1242, l2M - 0x5000, access2M_b) # GET_REM/PUT_REM, 2M
        access2M_c = access2M_b|zhpe.MR.REQ_CPU
        access2M_l = zhpe.MR.GET|zhpe.MR.PUT

        rsp2M_l = conn.do_MR_REG(v2M, l2M, access2M_l)  # GET/PUT, 2M

        if args.responder:
            rsp2M_b = conn.do_MR_REG(v2M, l2M, access2M_b) # rsp: GET_REM/PUT_REM, 2M

        if args.loopback and modp.genz_loopback:
            rsp_rmr = conn.do_RMR_IMPORT(zuu, rsp2M_b.rsp_zaddr, sz4K,
                                         access2M_b)
            rsp_rmr_c = conn.do_RMR_IMPORT(zuu, rsp2M_b.rsp_zaddr, sz4K,
                                           access2M_c)
            rmm = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr_c.offset)

            access2_c = access2|zhpe.MR.REQ_CPU
            rsp_rmr2 = conn.do_RMR_IMPORT(zuu, rsp2.rsp_zaddr, sz4K, access2_c)
            rmm2 = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr2.offset)
            v_rmm2, l_rmm2 = zhpe.mmap_vaddr_len(rmm2)

            access2_ro = access2_c&~zhpe.MR.PUT_REMOTE
            rsp_rmr_ro = conn.do_RMR_IMPORT(zuu, rsp2.rsp_zaddr, sz4K,
                                            access2_ro)
            rmm2_ro = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr_ro.offset)
            v_rmm2_ro, l_rmm2_ro = zhpe.mmap_vaddr_len(rmm2_ro)
            # Revisit: why does trying to write rmm2_ro (to test that it's
            # really RO) cause a python3 segfault?
            # rmm2_ro[0:3] = b'Joe'

            # individual, cpu-visible, 2M mapping allowing
            # GET/PUT/GET_REMOTE/PUT_REMOTE
            access2M_d = access2M_b|zhpe.MR.PUT|zhpe.MR.GET
            rsp2M_r = conn.do_MR_REG(v2M, sz2M, access2M_d) # loop: ALL, 2M
            rsp_rmr2M = conn.do_RMR_IMPORT(zuu, rsp2M_r.rsp_zaddr, sz2M,
                                           access2M_c)
            rmm2M = mmap.mmap(f.fileno(), sz2M, offset=rsp_rmr2M.offset)

        xdm = zhpe.XDM(conn, 256, 256, slice_mask=0x1)
        rdm = zhpe.RDM(conn, 1024, slice_mask=0x2)

        if args.net:
            if args.verbosity:
                print('Starting networking - this is very slow in sim')
            import network as net
            factory = net.MyFactory(conn, rsp2M_l, mm2M, xdm,
                                    args.verbosity, modp.no_iommu)
            try:
                factory.setup(args.port, nodes)
            except net.CannotListenError:
                print('Error: Address in use')

        str1 = b'Jim & Betty '
        str2 = b'making PF awesome!'
        str3 = b'Carbon is awesome too!'
        str4 = b'But sometimes, madness is the only path forward.'
        str5 = b'Interrupts are distractions.'
        len1 = len(str1)
        len2 = len(str2)
        len3 = len(str3)
        len4 = len(str4)
        len5 = len(str5)
        len1_2 = len1 + len2
        mm2[0:len1] = str1
        if args.verbosity:
            print('mm2 (initial)="{}"'.format(mm2[0:len1].decode()))
        if args.loopback and modp.genz_loopback:
            if args.verbosity:
                print('rmm2 (remote)="{}"'.format(rmm2[0:len1].decode()))
            if mm2[0:len1] != rmm2[0:len1]:
                print('Error: mm2 "{}" != rmm2 "{}"'.format(
                    mm2[0:len1].decode(), rmm2[0:len1].decode()))
            rmm2[len1:len1_2] = str2
            # flush rmm2 writes, so mm2 reads will see new data
            zhpe.pmem_flush(v_rmm2+len1, len2)
            if args.verbosity:
                print('mm2 after remote update="{}"'.format(
                      mm2[0:len1_2].decode()))
            if mm2[0:len1_2] != rmm2[0:len1_2]:
                print('Error: mm2 "{}" != rmm2 "{}"'.format(
                    mm2[0:len1_2].decode(), rmm2[0:len1_2].decode()))

        sync = zhpe.xdm_cmd()
        sync.opcode = zhpe.XDM_CMD.SYNC|zhpe.XDM_CMD.FENCE

        if args.loopback and modp.genz_loopback:
            # test PUT_IMM
            put_imm_offset = len1_2 + 1
            rem_addr = rsp_rmr2.req_addr + put_imm_offset
            put_imm = zhpe.xdm_cmd()
            put_imm.opcode = zhpe.XDM_CMD.PUT_IMM
            put_imm.getput_imm.size = len3
            put_imm.getput_imm.rem_addr = rem_addr
            put_imm.getput_imm.payload[0:len3] = str3
            xdm.queue_cmd(put_imm)
            try:
                put_imm_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('PUT_IMM cmpl: {}'.format(put_imm_cmpl))
            except XDMcompletionError as e:
                print('PUT_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            # Revisit: need fence/sync to ensure visibility
            if args.verbosity:
                print('mm2 after PUT_IMM="{}"'.format(
                    mm2[put_imm_offset:put_imm_offset+len3].decode()))

            # test GET_IMM
            get_imm = zhpe.xdm_cmd()
            get_imm.opcode = zhpe.XDM_CMD.GET_IMM
            get_imm.getput_imm.size = len1_2
            get_imm.getput_imm.rem_addr = rsp_rmr2.req_addr
            xdm.queue_cmd(get_imm)
            try:
                get_imm_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('GET_IMM cmpl: {}'.format(get_imm_cmpl.getimm))
            except XDMcompletionError as e:
                print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))

            # test PUT
            put_offset = datasize
            if modp.no_iommu:
                local_addr = rsp2M_r.physaddr  # Revisit: physaddr temporary
            else:
                local_addr = v2M
            rem_addr = rsp_rmr2M.req_addr + put_offset
            put = zhpe.xdm_cmd()
            put.opcode = zhpe.XDM_CMD.PUT|zhpe.XDM_CMD.FENCE
            put.getput.size = datasize
            put.getput.read_addr = local_addr
            put.getput.write_addr = rem_addr
            xdm.queue_cmd(put)
            try:
                put_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('PUT cmpl: {}'.format(put_cmpl))
            except XDMcompletionError as e:
                print('PUT cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            # Revisit: need fence/sync to ensure visibility
            mm2Msha256p = hashlib.sha256(
                mm2M[put_offset:put_offset+datasize]).hexdigest()
            if args.verbosity:
                print('mm2M sha256 after PUT="{}"'.format(mm2Msha256p))
                if mm2Msha256p != datasha256:
                    print('PUT sha mismatch: {} != {}'.format(datasha256, mm2Msha256p))

            # test GET+SYNC
            get_offset = 2 * datasize
            if modp.no_iommu:
                local_addr = rsp2M_r.physaddr + get_offset # Revisit: physaddr temporary
            else:
                local_addr = v2M + get_offset
            rem_addr = rsp_rmr2M.req_addr + put_offset
            get = zhpe.xdm_cmd()
            get.opcode = zhpe.XDM_CMD.GET|zhpe.XDM_CMD.FENCE
            get.getput.size = datasize
            get.getput.read_addr = rem_addr
            get.getput.write_addr = local_addr
            xdm.queue_cmds([get, sync])
            try:
                get_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('GET cmpl: {}'.format(get_cmpl))
            except XDMcompletionError as e:
                print('GET cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            try:
                sync_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SYNC cmpl: {}'.format(sync_cmpl))
            except XDMcompletionError as e:
                print('SYNC cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            mm2Msha256g = hashlib.sha256(
                mm2M[get_offset:get_offset+datasize]).hexdigest()
            if args.verbosity:
                print('mm2M sha256 after GET="{}"'.format(mm2Msha256g))
            if mm2Msha256g != datasha256:
                print('GET sha mismatch: {} != {}'.format(
                    datasha256, mm2Msha256g))

            # Do the atomic tests at the 1M point in the 2M region
            atomic_offset = rsp_rmr2M.req_addr + 1048576

            # test atomic 32 bit SWAP
            swap32 = zhpe.xdm_cmd()
            swap32.opcode = zhpe.XDM_CMD.ATM_SWAP
            swap32.atomic_one_op32.r = 1  # return a value
            swap32.atomic_one_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
            swap32.atomic_one_op32.rem_addr = atomic_offset
            swap32.atomic_one_op32.operand = 1
            xdm.queue_cmd(swap32)
            try:
                swap32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP32 cmpl: {}'.format(swap32_cmpl))
            except XDMcompletionError as e:
                print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP32 return value: {}'.format(
                      swap32_cmpl.atomic32))

            # test the same atomic 32 bit SWAP to see if the prev val is now 1
            swap32 = zhpe.xdm_cmd()
            swap32.opcode = zhpe.XDM_CMD.ATM_SWAP
            swap32.atomic_one_op32.r = 1  # return a value
            swap32.atomic_one_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
            swap32.atomic_one_op32.rem_addr = atomic_offset
            swap32.atomic_one_op32.operand = 2
            xdm.queue_cmd(swap32)
            try:
                swap32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP32 cmpl: {}'.format(swap32_cmpl))
            except XDMcompletionError as e:
                print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP32 return value: {}'.format(
                      swap32_cmpl.atomic32))
            if swap32_cmpl.atomic32.retval != 1:
                print('FAIL: SWAP32: retval is {:#x} and should be 1'.format(
                      swap32_cmpl.atomic32.retval))

            # test atomic 32 bit COMPARE AND SWAP - val is now 2
            cas32 = zhpe.xdm_cmd()
            cas32.opcode = zhpe.XDM_CMD.ATM_CAS
            cas32.atomic_two_op32.r = 1  # return a value
            cas32.atomic_two_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
            cas32.atomic_two_op32.rem_addr = atomic_offset
            cas32.atomic_two_op32.operand1 = 2
            cas32.atomic_two_op32.operand2 = 3
            xdm.queue_cmd(cas32)
            try:
                cas32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('CAS32 cmpl: {}'.format(cas32_cmpl))
            except XDMcompletionError as e:
                print('CAS32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('CAS32 return value: {}'.format(
                      cas32_cmpl.atomic32))
            if cas32_cmpl.atomic32.retval != 2:
                print('FAIL: CAS32: retval is {:#x} and should be 2'.format(
                      cas32_cmpl.atomic32.retval))

            # test atomic 32 bit FETCH AND ADD - val is now 3
            add32 = zhpe.xdm_cmd()
            add32.opcode = zhpe.XDM_CMD.ATM_ADD
            add32.atomic_one_op32.r = 1  # return a value
            add32.atomic_one_op32.size = zhpe.ATOMIC_SIZE.SIZE_32BIT
            add32.atomic_one_op32.rem_addr = atomic_offset
            add32.atomic_one_op32.operand = 1
            xdm.queue_cmd(add32)
            try:
                add32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ADD32 cmpl: {}'.format(add32_cmpl))
            except XDMcompletionError as e:
                print('ADD32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('ADD32 return value: {}'.format(
                      add32_cmpl.atomic32))
            if add32_cmpl.atomic32.retval != 3:
                print('FAIL: ADD32: retval is {:#x} and should be 3'.format(
                      add32_cmpl.atomic32.retval))

            # test atomic 64 bit SWAP 
            swap64 = zhpe.xdm_cmd()
            swap64.opcode = zhpe.XDM_CMD.ATM_SWAP
            swap64.atomic_one_op64.r = 1  # return a value
            swap64.atomic_one_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
            swap64.atomic_one_op64.rem_addr = atomic_offset
            swap64.atomic_one_op64.operand = 1
            xdm.queue_cmd(swap64)
            try:
                swap64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP64 cmpl: {}'.format(swap64_cmpl))
            except XDMcompletionError as e:
                print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP64 return value: {}'.format(
                      swap64_cmpl.atomic64))
            # second test atomic 64 bit SWAP - val is now 1
            swap64 = zhpe.xdm_cmd()
            swap64.opcode = zhpe.XDM_CMD.ATM_SWAP
            swap64.atomic_one_op64.r = 1  # return a value
            swap64.atomic_one_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
            swap64.atomic_one_op64.rem_addr = atomic_offset
            swap64.atomic_one_op64.operand = 2
            xdm.queue_cmd(swap64)
            try:
                swap64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP64 cmpl: {}'.format(swap64_cmpl))
            except XDMcompletionError as e:
                print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP64 return value: {}'.format(
                      swap64_cmpl.atomic64))
            if swap64_cmpl.atomic64.retval != 1:
                print('FAIL: SWAP64: retval is {:#x} and should be 1'.format(
                      swap64_cmpl.atomic64.retval))
               
            # test atomic 64 bit COMPARE AND SWAP - val is now 2
            cas64 = zhpe.xdm_cmd()
            cas64.opcode = zhpe.XDM_CMD.ATM_CAS
            cas64.atomic_two_op64.r = 1  # return a value
            cas64.atomic_two_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
            cas64.atomic_two_op64.rem_addr = atomic_offset
            cas64.atomic_two_op64.operand1 = 2
            cas64.atomic_two_op64.operand2 = 3
            xdm.queue_cmd(cas64)
            try:
                cas64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('CAS64 cmpl: {}'.format(cas64_cmpl))
            except XDMcompletionError as e:
                print('CAS64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('CAS64 return value: {}'.format(
                      cas64_cmpl.atomic64))
            if cas64_cmpl.atomic64.retval != 2:
                print('FAIL: CAS64: retval is {:#x} and should be 2'.format(
                      cas64_cmpl.atomic64.retval))

            # test atomic 64 bit FETCH AND ADD - val is now 3
            add64 = zhpe.xdm_cmd()
            add64.opcode = zhpe.XDM_CMD.ATM_ADD
            add64.atomic_one_op64.r = 1  # return a value
            add64.atomic_one_op64.size = zhpe.ATOMIC_SIZE.SIZE_64BIT
            add64.atomic_one_op64.rem_addr = atomic_offset
            add64.atomic_one_op64.operand = 1
            xdm.queue_cmd(add64)
            try:
                add64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ADD64 cmpl: {}'.format(add64_cmpl))
            except XDMcompletionError as e:
                print('ADD64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('ADD64 return value: {}'.format(
                      add64_cmpl.atomic64))
            if add64_cmpl.atomic64.retval != 3:
                print('FAIL: ADD64: retval is {:#x} and should be 3'.format(
                      add64_cmpl.atomic64.retval))

            # test EnqA/RDM
            enqa = zhpe.xdm_cmd()
            enqa.opcode = zhpe.XDM_CMD.ENQA
            enqa.enqa.dgcid = zuu.gcid
            enqa.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa.enqa.payload[0:len4] = str4
            xdm.queue_cmd(enqa)
            try:
                enqa_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpl = rdm.get_cmpl()
            if args.verbosity:
                print('RDM cmpl: {}'.format(rdm_cmpl.enqa))
            if enqa.enqa.payload[0:52] != rdm_cmpl.enqa.payload[0:52]:
                print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpl.enqa.payload[0:52], enqa.enqa.payload[0:52]))
            # Revisit: check other cmpl fields

            # test EnqA/RDM with poll
            enqa = zhpe.xdm_cmd()
            enqa.opcode = zhpe.XDM_CMD.ENQA
            enqa.enqa.dgcid = zuu.gcid
            enqa.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa.enqa.payload[0:len4] = str4
            xdm.queue_cmd(enqa)
            try:
                enqa_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpls = rdm.get_poll()
            if args.verbosity:
                for c in range(len(rdm_cmpls)):
                    if c != None:
                         print('RDM cmpl: {}'.format(rdm_cmpls[c].enqa))
            for c in range(len(rdm_cmpls)):
                if enqa.enqa.payload[0:52] != rdm_cmpls[c].enqa.payload[0:52]:
                    print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpls[c].enqa.payload[0:52], enqa.enqa.payload[0:52]))

            # second test EnqA/RDM with poll
            print('SECOND EnqA/RDM poll test')
            enqa2 = zhpe.xdm_cmd()
            enqa2.opcode = zhpe.XDM_CMD.ENQA
            enqa2.enqa.dgcid = zuu.gcid
            enqa2.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa2.enqa.payload[0:len5] = str5
            xdm.queue_cmd(enqa2)
            try:
                enqa_cmpl2 = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl2))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpls2 = rdm.get_poll()
            if args.verbosity:
                for c in range(len(rdm_cmpls2)):
                    if c != None:
                         print('RDM cmpl: {}'.format(rdm_cmpls2[c].enqa))
            for c in range(len(rdm_cmpls2)):
                if enqa2.enqa.payload[0:52] != rdm_cmpls2[c].enqa.payload[0:52]:
                    print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpls[c].enqa.payload[0:52], enqa.enqa.payload[0:52]))

        if args.net:
            if args.verbosity:
                print('Waiting for network connections')
            net.reactor.run()
        if args.keyboard:
            set_trace()
        conn.do_XQUEUE_FREE(xdm.rsp_xqa.info)
        conn.do_RQUEUE_FREE(rdm.rsp_rqa.info)
        if args.requester:
            conn.do_MR_FREE(v, l, access, rsp.rsp_zaddr)
        conn.do_MR_FREE(v2M, l2M, access2M_l, rsp2M_l.rsp_zaddr)
        conn.do_MR_FREE(v2M + 0x1242, l2M - 0x5000, access2M_b, rsp2M.rsp_zaddr)

        # we do not MR_FREE rsp2M_b, to see if it is cleaned up at close
        # same for RMR_FREE of rsp_rmr
        if args.loopback and modp.genz_loopback:
            conn.do_RMR_FREE(zuu, rsp2M_b.rsp_zaddr, sz4K, access2M_c,
                             rsp_rmr_c.req_addr)
            exc = False
            try:
                conn.do_UUID_FREE(zuu)
            except OSError:
                exc = True
            if exc:
                if args.verbosity:
                    print('do_UUID_FREE of zuu: got expected error')
            else:
                print('fail: no error on UUID_FREE of zuu')
        exc = False
        try:
            conn.do_UUID_FREE(init.uuid)
        except OSError:
            exc = True
        if exc:
            if args.verbosity:
                print('do_UUID_FREE of init.uuid: got expected error')
        else:
            print('fail: no error on UUID_FREE of init.uuid')
    # end with

if __name__ == '__main__':
    main()

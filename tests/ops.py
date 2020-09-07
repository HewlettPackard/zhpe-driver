#!/usr/bin/env python3

# Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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
import errno
import hashlib
from ctypes import *
from pdb import set_trace
from pdb import post_mortem
import time
import zhpe
from zhpe import MR, UU
from zhpe import zuuid, XDMcompletionError
from tests import Tests

class Queue():
    def __init__(self, xdm, cmds):
        self.xdm = xdm
        self.cmds = cmds
        self.cmps = cmds
        self.start = 0

def runtime_err(*arg):
    raise RuntimeError(*arg)
# Think about something like this, perhaps.
#    if args.verbosity:
#        raise RuntimeError(*arg)
#    else:
#        print(*arg)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--devfile', default='/dev/zhpe',
                        help='the zhpe character device file')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-c', '--commands', default=4096, type=int,
                        help='total number of commands')
    parser.add_argument('-f', '--fence', action='store_true',
                        help='fence every comand')
    parser.add_argument('-l', '--len', default=1024, type=int,
                        help='length of data transfer operations')
    parser.add_argument('-o', '--op', default='nop',
                        help='operation get, put, get_imm, put_imm, nop, sync')
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    parser.add_argument('-q', '--queues', default=1, type=int,
                        help='number of xdm queues')
    parser.add_argument('-s', '--slice', default=0, type=int,
                        help='slice 0-3')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    parser.add_argument('-w', '--window', default=0, type=int,
                        help='window, defaults to queue size - 1')
    parser.add_argument('-x', '--xdmq_size', default=1024, type=int,
                        help='size of XDM queue. must be power of 2')
    return parser.parse_args()

def main():
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))

    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = zhpe.Connection(f, args.verbosity)

        init = conn.do_INIT()
        gcid = init.uuid.gcid
        if args.verbosity:
            print('do_INIT: uuid={}, gcid={}'.format(
                init.uuid, init.uuid.gcid_str))

        zuu = zuuid(gcid=gcid)
        conn.do_UUID_IMPORT(zuu, 0, None)

        mm = mmap.mmap(-1, args.len * 2)
        v, l = zhpe.mmap_vaddr_len(mm)
        rsp = conn.do_MR_REG(v, l, MR.GPGRPRI)
        mm[0:args.len] = os.urandom(args.len)  # fill with random bytes
        rsp_rmr = conn.do_RMR_IMPORT(zuu, rsp.rsp_zaddr, args.len * 2, MR.GRPRI)

        if (args.xdmq_size & (args.xdmq_size - 1)) != 0:
            raise_err('-x option must specify a power of 2')

        qmask = args.xdmq_size - 1

        if args.window == 0:
            args.window = qmask
        if args.window >= args.xdmq_size:
            raise_err('-w option must be <= queue size')
            
        queues = []
        smask = 1 << args.slice
        smask |= 0x80
        for q in range(args.queues):
            xdm = zhpe.XDM(conn, args.xdmq_size, args.xdmq_size,
                           slice_mask=smask)
            if args.verbosity:
                print('XDM queue = {} slice = {}'.format(
                    xdm.rsp_xqa.info.queue, xdm.rsp_xqa.info.slice))
            queues.append(Queue(xdm, args.commands))

        cmd = zhpe.xdm_cmd()

        cmd.opcode = args.op
        if args.fence:
            cmd.opcode = cmd.opcode | zhpe.XDM_CMD.FENCE
        if cmd.opcode == zhpe.XDM_CMD.PUT_IMM:
            args.len = min(args.len, 32)
            cmd.getput_imm.size = args.len
            cmd.getput_imm.rem_addr = rsp_rmr.req_addr + args.len
            cmd.getput_imm.payload[0:args.len] = mm[0:args.len]
        elif cmd.opcode == zhpe.XDM_CMD.GET_IMM:
            args.len = min(args.len, 32)
            cmd.getput_imm.size = args.len
            cmd.getput_imm.rem_addr = rsp_rmr.req_addr
        elif cmd.opcode == zhpe.XDM_CMD.PUT:
            cmd.getput.size = args.len
            cmd.getput.read_addr = v
            cmd.getput.write_addr = rsp_rmr.req_addr + args.len
        elif cmd.opcode == zhpe.XDM_CMD.GET:
            cmd.getput.size = args.len
            cmd.getput.read_addr = rsp_rmr.req_addr
            cmd.getput.write_addr = v + args.len

        if args.verbosity:
            print("cmd: {}".format(cmd))

        # Fill the queue with the commands
        for i in range(args.xdmq_size):
            for q in queues:
                q.xdm.queue_cmd(cmd, False)

        if args.keyboard:
            set_trace()

        working = queues.copy()
        while working:
            for q in working:
                cmps = 0
                while True:
                    cmpl = q.xdm.get_cmpl(wait=False)
                    if cmpl == None:
                        break
                    cmps += 1
                if cmps != 0:
                    q.cmps -= cmps
                    if q.cmps == 0:
                        working.remove(q)
                    if args.verbosity:
                        print("queue {} completed {}".format(
                            q.xdm.rsp_xqa.info.queue, cmps))
                qavail = qmask - (q.cmps - q.cmds)
                qavail = min(qavail, q.cmds, args.window)
                if qavail != 0 and (qavail == args.window or qavail == q.cmds):
                    q.xdm.ring2(qavail)
                    q.cmds -= qavail
                    if args.verbosity:
                        print("queue {} started {}".format(
                            q.xdm.rsp_xqa.info.queue, qavail))

        if args.keyboard:
            set_trace()

    # end with

if __name__ == '__main__':
    try:
        main()
    except:
        if args.post_mortem:
            post_mortem()
        else:
            raise


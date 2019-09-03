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
    parser.add_argument('-c', '--commands', default=1048576, type=int,
                        help='total number of commands')
    parser.add_argument('-f', '--fence', action='store_true',
                        help='fence every instruction')
    parser.add_argument('-l', '--len', default=1024, type=int,
                        help='length of data transfer operations')
    parser.add_argument('-o', '--op', default='get',
                        help='operation get, put, get_imm, put_imm, nop, sync')
    parser.add_argument('-q', '--queues', default=2, type=int,
                        help='number of xdm queuees')
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    parser.add_argument('-w', '--window', default=1024, type=int,
                        help='maximum number of commands at one time')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
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

        if args.keyboard:
            set_trace()

        queues = []
        for q in range(args.queues):
            xdm = zhpe.XDM(conn, 8192, 8192, slice_mask=0x1)
            queues.append(Queue(xdm, args.commands))

        cmd = zhpe.xdm_cmd()

        if args.keyboard:
            set_trace()

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

        if args.keyboard:
            set_trace()

        args.window = min(args.commands, args.window)
        
        working = len(queues)
        waiting = working
        while working != 0:
            if waiting == len(queues):
                if args.keyboard:
                    set_trace()
                for q in queues:
                    n = min(args.window, q.cmds)
                    for i in range(n):
                        q.xdm.queue_cmd(cmd, False)
                    q.cmds -= n
                for q in queues:
                    q.xdm.ring()
                waiting = 0
            for q in queues:
                cmpl = q.xdm.get_cmpl(False)
                if cmpl != None:
                    q.cmps -= 1
                    if q.cmps == 0:
                        working -= 1
                    elif q.cmps == q.cmds:
                        waiting += 1

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


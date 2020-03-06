#!/usr/bin/env python3

# Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
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
    parser.add_argument('-c', '--commands', default=1, type=int,
                        help='total number of commands')
    parser.add_argument('-d', '--dgcid', default=-1, type=int,
                        help='Destination Global Component ID')
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    parser.add_argument('-R', '--RDM_only', action='store_true',
                        help='only do RDM allocation and receive')
    parser.add_argument('-s', '--slice', default=0, type=int,
                        help='slice 0-3')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    parser.add_argument('-X', '--XDM_only', action='store_true',
                        help='only do XDM allocation and transmit')
    return parser.parse_args()

def rdm_check(rdm_cmpl, enqa):
    if args.verbosity:
        print('RDM cmpl: {}'.format(rdm_cmpl.enqa))
    if enqa.enqa.payload[0:52] != rdm_cmpl.enqa.payload[0:52]:
        runtime_err('FAIL: RDM: payload is {} and should be {}'.format(
            rdm_cmpl.enqa.payload[0:52], enqa.enqa.payload[0:52]))

def main():
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    if (args.XDM_only and args.RDM_only):
        runtime_err('Only one of XDM-only and RDM-only allowed')
    if (args.XDM_only or args.RDM_only):
        if args.dgcid == -1:
            runtime_err('Require dgcid with XDM_only or RDM_only')
    elif args.dgcid != -1:
        runtime_err('dgcid requires XDM_only or RDM_only')
        
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = zhpe.Connection(f, args.verbosity)

        init = conn.do_INIT()
        gcid = init.uuid.gcid
        if args.verbosity:
            print('do_INIT: uuid={}, gcid={}'.format(
                init.uuid, init.uuid.gcid_str))
        if args.dgcid != -1:
            gcid = args.dgcid


        smask = 1 << args.slice
        smask |= 0x80
        if not args.RDM_only:
            xdm = zhpe.XDM(conn, 256, 256, slice_mask=smask)
        if not args.XDM_only:
            rdm = zhpe.RDM(conn, 1024, slice_mask=smask)

        enqa = zhpe.xdm_cmd()
        enqa.opcode = zhpe.XDM_CMD.ENQA
        enqa.enqa.dgcid = gcid
        enqa.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
        str1 = b'hello, world'
        len1 = len(str1)
        enqa.enqa.payload[0:len1] = str1
        enqa.enqa.payload[len1:52] = os.urandom(52 - len1)

        if args.verbosity:
            print("cmd: {}".format(enqa))

        xdm.queue_cmd(enqa)
        if args.keyboard:
            set_trace()
        try:
            enqa_cmpl = xdm.get_cmpl()
            if args.verbosity:
                print('ENQA cmpl: {}'.format(enqa_cmpl))
        except XDMcompletionError as e:
            print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        if args.keyboard:
            set_trace()
        rdm_cmpls= rdm.get_poll(verbosity=args.verbosity)
        if args.verbosity:
            for c in range(len(rdm_cmpls)):
                rdm_check(rdm_cmpls[c], enqa)
        enqa.enqa.payload[len1:52] = os.urandom(52 - len1)
        xdm.queue_cmd(enqa)
        rdm_cmpl = rdm.get_cmpl()
        rdm_check(rdm_cmpl, enqa)

    # end with

if __name__ == '__main__':
    try:
        main()
    except:
        if args.post_mortem:
            post_mortem()
        else:
            raise


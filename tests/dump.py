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

def runtime_err(*arg):
    raise RuntimeError(*arg)
# Think about something like this, perhaps.
#    if args.verbosity:
#        raise RuntimeError(*arg)
#    else:
#        print(*arg)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+',
                        help='<cmdfile> <cmpfile>')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    return parser.parse_args()

def main():
    global args
    args = parse_args()
                       
    cmdfname = args.files.pop(0)
    cmdfsize = os.path.getsize(cmdfname)
    cmpfname = args.files.pop(0)
    cmpfsize = os.path.getsize(cmpfname)

    with open(cmdfname, 'rb+') as f:
        mm = mmap.mmap(f.fileno(), cmdfsize, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE)
        cmdent = cmdfsize // sizeof(zhpe.xdm_cmd)
        cmds = zhpe.xdm_cmd * cmdent
        cmd = cmds.from_buffer(mm, 0)
        for i in range(0, cmdent):
            print('{:#x} {}'.format(i, cmd[i]))
    # end with

    with open(cmpfname, 'rb+') as f:
        mm = mmap.mmap(f.fileno(), cmdfsize, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE)
        cmpent = cmpfsize // sizeof(zhpe.xdm_cmpl)
        cmps = zhpe.xdm_cmpl * cmpent
        cmp = cmps.from_buffer(mm, 0)
        for i in range(0, cmpent):
            print('{:#x} {}'.format(i, cmp[i]))
    # end with

if __name__ == '__main__':
    try:
        main()
    except:
        if args.post_mortem:
            post_mortem()
        else:
            raise


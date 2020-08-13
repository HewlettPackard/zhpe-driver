#!/usr/bin/env python3

# Copyright (C) 2018-2020 Hewlett Packard Enterprise Development LP.
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
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    return parser.parse_args()

def main():
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    modp = ModuleParams()
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = zhpe.Connection(f, args.verbosity)
        init = conn.do_INIT()
        gcid = init.uuid.gcid
        if args.verbosity:
            print('do_INIT: uuid={}, gcid={}'.format(
                init.uuid, init.uuid.gcid_str))

        feat = conn.do_FEATURE(zhpe.FEATURES.FEATURE_DUMP_Q0)
        if args.verbosity:
            print('do_FEATURE: features={:#x}'.format(feat.features))
        if args.keyboard:
            set_trace()
    # end with

if __name__ == '__main__':
    try:
        main()
    except Exception as post_err:
        if args.post_mortem:
            post_mortem()
        else:
            raise


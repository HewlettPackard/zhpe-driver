#!/bin/bash
set -e

# dkms_post_install.sh

HNAME="zhpe_helper"
HDIR="/usr/local/libexec"   # optional on Debian/Ubuntu
HPATH="${HDIR}/${HNAME}"
PCONF="dkms/modprobe_zhpe.conf"
PPATH="/etc/modprobe.d/zhpe.conf"
MCONF="dkms/modules_zhpe.conf"
MPATH="/etc/modules-load.d/zhpe.conf"

(( $# == 2 )) || exit 1

ZHPE_HELPER=$1/$HNAME
KERNELVER=$2

# Setup on first version
if [ ! -f $HPATH ] ; then
    mkdir -p $HDIR
    cp $ZHPE_HELPER $HDIR
    cp $PCONF $PPATH
    cp $MCONF $MPATH
fi

ln $HPATH ${HPATH}-${KERNELVER}

exit 0

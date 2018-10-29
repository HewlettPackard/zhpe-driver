#!/bin/bash

(( $# == 2 )) || exit 1

HNAME="zhpe_helper"
cp $1/bin/$HNAME $2
rm -rf build $1

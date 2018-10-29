#!/bin/bash

(( $# == 2 )) || exit 1

rm -rf build $1
./prep.sh -k $2 $1
make driver


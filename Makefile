SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
KVERSION := $(shell uname -r)
RHEL := $(shell !(lsb_release -is | grep -qi 'centos\|redhat' ) || \
	  echo "-DHAVE_RHEL" )

obj-m += zhpe.o
zhpe-objs += zhpe_core.o zhpe_uuid.o zhpe_zmmu.o zhpe_memreg.o zhpe_pasid.o zhpe_queue.o zhpe_rkey.o zhpe_msg.o zhpe_intr.o zhpe_mmun.o

ccflags-y += -I$ $(src)/include -Wno-date-time -mpreferred-stack-boundary=4
ccflags-y += $(RHEL)

all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

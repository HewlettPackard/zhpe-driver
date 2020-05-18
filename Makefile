SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
KVERSION := $(shell uname -r)
RHEL := $(shell !(lsb_release -is | grep -qi 'centos\|redhat' ) || \
	  echo "-DHAVE_RHEL" )

obj-m += zhpe.o
zhpe-objs += zhpe_core.o zhpe_uuid.o zhpe_zmmu.o zhpe_memreg.o zhpe_pasid.o zhpe_queue.o zhpe_rkey.o zhpe_msg.o zhpe_intr.o

ccflags-y += -I$ $(src)/include -Wno-date-time -mpreferred-stack-boundary=4
ccflags-y += $(RHEL)

VERSION=zhpe_version.h

all:
	@if [[ -n "$(RHEL)" ]]; then					\
	    env - scl enable devtoolset-7 -- make all2;			\
	else								\
	    make all2;							\
	fi

all2: version
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	$(MAKE) -C tests

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -f $(VERSION)*

.PHONY: version

version: $(zhpe_objs:.o=.c) Makefile
	@V="0:0";							\
	if S=$$(git status --porcelain 2>/dev/null); then		\
	    V+=:$$(git describe --all --long | cut -d - -f 3);		\
	    V+=:$$(git config --get remote.origin.url);			\
	    [[ -z "$$S" ]] || V+=:dirty;				\
	fi;								\
	V+=$${V:+:}$${HOSTNAME%%.*}:$$(pwd);				\
	echo "#define ZHPE_VERSION \"$$V\"" >$(VERSION).tmp;		\
	cmp -s $(VERSION).tmp $(VERSION) || mv -f $(VERSION).tmp $(VERSION)

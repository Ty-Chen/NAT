ifneq ($(KERNELRELEASE),)
DROPHOOK ?= m
endif

obj-$(DROPHOOK) += DropHook.o
#udp_drop_filter.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

build:
	make -C $(KERNELDIR)  M=`pwd` modules

install:modules_install

modules_install:
	make -C $(KERNELDIR)  M=`pwd` modules_install
	
clean:
	rm -rf *.o *.cmd *.ko *.mod.c .tmp_versions *.order *.symvers

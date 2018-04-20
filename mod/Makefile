KERNEL_SOURCE=/tmp/compile/pgardner/linux_source/linux

INCLUDE_DIR=$(PWD)/../include
EXTRA_CFLAGS += -DMODULE=1 -D__KERNEL__=1 -I$(INCLUDE_DIR)

paging-objs := $(paging-y)
obj-m := paging.o

PHONY: all

all:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- M=$(PWD) clean 

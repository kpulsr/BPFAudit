KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/')

# Kernel module
obj-m := bpfledger.o

all: module

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Load / unload helpers
load:
	sudo insmod bpfledger.ko
	@echo "Ledger module loaded. /dev/bpfledger is ready."

unload:
	sudo rmmod bpfledger

reload: unload load

log:
	sudo dmesg | grep bpfledger | tail -20

.PHONY: all module clean load unload reload log

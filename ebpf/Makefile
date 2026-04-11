KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/')

# Kernel module
obj-m := bpfledger.o

# BPF object
BPF_SRC  := audit.bpf.c
BPF_OBJ  := audit.bpf.o

all: module bpf

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

bpf: vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-D__BPF__ \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Generate vmlinux.h from running kernel BTF
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(BPF_OBJ) vmlinux.h

# Load / unload helpers
load:
	sudo insmod bpfledger.ko
	@echo "Ledger module loaded. /dev/bpfledger is ready."

unload:
	sudo rmmod bpfledger

reload: unload load

log:
	sudo dmesg | grep bpfledger | tail -20

.PHONY: all module bpf clean load unload reload log

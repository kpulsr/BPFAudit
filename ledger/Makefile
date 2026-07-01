KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/')
BUILD   := $(PWD)/build

# Include headers
ccflags-y += -I$(src)/include

# Kernel module
obj-m := bpfledger.o
bpfledger-y := \
    src/bpfledger_main.o \
    src/bpfledger_ring.o \
    src/bpfaudit_crypto.o \
    src/bpfaudit_heartbeat.o \
    src/common/emit.o \
    src/common/process.o \
    src/common/filter.o \
    src/paths/program.o \
    src/paths/attach/link.o \
    src/paths/attach/legacy/prog_attach.o \
    src/paths/attach/legacy/setsockopt.o

debug: ccflags-y += -DDEBUG

debug: module

all: module

module:
	mkdir -p $(BUILD)
	$(MAKE) -C $(KDIR) M=$(PWD) MO=$(BUILD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) MO=$(BUILD) clean
	rm -rf $(BUILD)

# Load / unload helpers
load:
	sudo insmod $(BUILD)/bpfledger.ko
	@echo "Ledger module loaded."

unload:
	sudo rmmod bpfledger

reload: unload load

log:
	sudo dmesg | grep bpfledger | tail -20

.PHONY: all module clean load unload reload log



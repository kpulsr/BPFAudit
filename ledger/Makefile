KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/')
BUILD   := $(PWD)/build

# Include headers
ccflags-y += -I$(src)/include

# Kernel module
obj-m := bpfledger.o
bpfledger-y := src/bpfledger_main.o \
               src/bpfledger_ring.o \
               src/bpfaudit_crypto.o \
               src/bpfaudit_heartbeat.o

debug: ccflags-y += -DDEBUG
debug: module
all: module

ifeq ($(CC),clang)
KBUILD_EXTRA := CC=clang HOSTCC=clang \
                KCFLAGS="-fno-sanitize=bounds-strict -fno-conserve-stack" \
                KBUILD_CFLAGS_MODULE=""
else
KBUILD_EXTRA :=
endif

module:
	mkdir -p $(BUILD)
	$(MAKE) -C $(KDIR) M=$(PWD) MO=$(BUILD) $(KBUILD_EXTRA) modules

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

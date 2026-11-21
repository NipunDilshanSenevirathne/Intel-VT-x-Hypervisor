KDIR ?= /lib/modules/$(shell uname -r)/build
FUZZ_TIME ?= 60
CACHE := $(CURDIR)/.cache

all: modules tools

modules:
	$(MAKE) -C kmod KDIR=$(KDIR)

tools:
	$(MAKE) -C tools/vtxctl

check: modules
	python3 scripts/check_host_isolation.py kmod/vtxhv_root.ko

test-unit:
	$(MAKE) -C tests/unit run

test-fuzz:
	$(MAKE) -C tests/fuzz run FUZZ_TIME=$(FUZZ_TIME)

test-vm:
	./scripts/build-bochs.sh $(CACHE)/bochs
	eval "$$(./scripts/build-test-kernel.sh)" && \
	BOCHS=$(CACHE)/bochs/bin/bochs BXSHARE=$(CACHE)/bochs/share/bochs \
	KERNEL=$$KERNEL KDIR=$$KDIR ./tests/vm/matrix.sh

test: check test-unit

load: modules
	sudo insmod kmod/vtxhv_root.ko
	sudo insmod kmod/vtxhv.ko $(PARAMS)

unload:
	sudo rmmod vtxhv
	sudo rmmod vtxhv_root

install: modules tools
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kmod modules_install
	$(MAKE) -C tools/vtxctl install

clean:
	$(MAKE) -C kmod clean KDIR=$(KDIR) || true
	$(MAKE) -C tools/vtxctl clean
	$(MAKE) -C tests/unit clean
	$(MAKE) -C tests/fuzz clean
	-$(MAKE) -C tests/attack clean KDIR=$(KDIR)

.PHONY: all modules tools check test-unit test-fuzz test-vm test load unload install clean

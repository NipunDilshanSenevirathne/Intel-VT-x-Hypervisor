KDIR ?= /lib/modules/$(shell uname -r)/build

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

check: modules
	python3 $(CURDIR)/../scripts/check_host_isolation.py $(CURDIR)/vtxhv_root.ko

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all modules check clean

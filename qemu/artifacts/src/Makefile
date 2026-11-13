obj-m += escape.o

KV := $(shell uname -r)
KDIR ?= /lib/modules/$(KV)/build

# Use CURDIR, not PWD: under `make -C <dir>` the PWD env var still points at
# the caller's directory, which breaks the out-of-tree module build.
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean

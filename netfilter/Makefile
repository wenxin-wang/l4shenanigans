ifneq ($(KERNELRELEASE),)
# Called by kernel
include Kbuild

else
# CLI invokation
KERNELDIR  ?= /lib/modules/$(shell uname -r)/build

MODULE_TARGETS = modules modules_install clean help

.PHONY: default $(MODULE_TARGETS) test install

default:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

$(MODULE_TARGETS):
	$(MAKE) -C $(KERNELDIR) M=$$PWD $@

endif

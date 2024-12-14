# Prefix all modules with gb-
gb-device-y := greybus-generic-device.o greybus-hdlc.o

obj-m += gb-device.o

KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
INSTALL_MOD_PATH	?= /..
PWD			:= $(shell pwd)

# kernel config option that shall be enable
CONFIG_OPTIONS_ENABLE := GREYBUS

# kernel config option that shall be disable
CONFIG_OPTIONS_DISABLE :=

# this only run in kbuild part of the makefile
ifneq ($(KERNELRELEASE),)
# This function returns the argument version if current kernel version is minor
# than the passed version, return 1 if equal or the current kernel version if it
# is greater than argument version.
kvers_cmp=$(shell [ "$(KERNELVERSION)" = "$(1)" ] && echo 1 || printf "$(1)\n$(KERNELVERSION)" | sort -V | tail -1)

$(foreach opt,$(CONFIG_OPTIONS_ENABLE),$(if $(CONFIG_$(opt)),, \
     $(error CONFIG_$(opt) is disabled in the kernel configuration and must be enable \
     to continue compilation)))
$(foreach opt,$(CONFIG_OPTIONS_DISABLE),$(if $(filter m y, $(CONFIG_$(opt))), \
     $(error CONFIG_$(opt) is enabled in the kernel configuration and must be disable \
     to continue compilation),))
endif

# add -Wall to try to catch everything we can.
ccflags-y := -Wall

# needed for trace events
ccflags-y += -I$(src)
ccflags-y += -I$(KERNELDIR)/drivers/staging/greybus

all: module

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

check:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__"

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	$(MAKE) -C tools clean

coccicheck:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) coccicheck

install: module
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVER)/kernel/drivers/greybus/
	cp -f *.ko $(INSTALL_MOD_PATH)/lib/modules/$(KERNELVER)/kernel/drivers/greybus/
	depmod -b $(INSTALL_MOD_PATH) -a $(KERNELVER)

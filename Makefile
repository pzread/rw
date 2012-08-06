ifneq (${KERNELRELEASE},)
	rw-objs := rw_mod.o rw_hook.o rw_cache.o
	obj-m := rw.o
else
	KERNEL_SOURCE := /usr/lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif

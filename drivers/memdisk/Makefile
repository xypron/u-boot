ifeq ($(CONFIG_MEMDISK),y)

obj-y += \
	memdisk.o \
	memdisk_file.o

MEMDISK_FILE := $(subst $\",,$(CONFIG_MEMDISK_FILE))
$(obj)/memdisk_file.o: $(srctree)/$(MEMDISK_FILE)

endif

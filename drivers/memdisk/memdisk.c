// SPDX-License-Identifier: GPL-2.0+
/*
 * Memory disk image
 *
 * Copyright (c) 2022, Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#include <common.h>
#include <blk.h>
#include <dm.h>
#include <memdisk.h>
#include <asm/sections.h>

#define LOG_BLK_SIZE 9
#define BLK_SIZE (1 << LOG_BLK_SIZE)

/**
 * initr_memdisk() - Initialize embedded memory disk
 */
int initr_memdisk(void)
{
	memdisk_create(__memdisk_file_begin,
		       __memdisk_file_end - __memdisk_file_begin);

	return 0;
}

/**
 * Read from block device
 *
 * @dev:	device
 * @blknr:	first block to be read
 * @blkcnt:	number of blocks to read
 * @buffer:	output buffer
 * Return:	number of blocks transferred
 */
static ulong mem_bl_read(struct udevice *dev, lbaint_t blknr, lbaint_t blkcnt,
			 void *buffer)
{
	struct memdisk_plat *plat = dev_get_plat(dev);
	char *start = plat->start;

	if (blknr + blkcnt > ((lbaint_t)plat->size >> LOG_BLK_SIZE))
		return 0;
	start += blknr << LOG_BLK_SIZE;
	memcpy(buffer, start, blkcnt << LOG_BLK_SIZE);

	return blkcnt;
}

/**
 * Write to block device
 *
 * @dev:	device
 * @blknr:	first block to be write
 * @blkcnt:	number of blocks to write
 * @buffer:	input buffer
 * Return:	number of blocks transferred
 */
static ulong mem_bl_write(struct udevice *dev, lbaint_t blknr, lbaint_t blkcnt,
			  const void *buffer)
{
	struct memdisk_plat *plat = dev_get_plat(dev);
	char *start = plat->start;

	if (blknr + blkcnt > ((lbaint_t)plat->size >> LOG_BLK_SIZE))
		return 0;
	start += blknr << LOG_BLK_SIZE;
	memcpy(start, buffer, blkcnt << LOG_BLK_SIZE);

	return blkcnt;
}

/**
 * memdisk_create() - create memory disk
 *
 * @start:	start address
 * @size	size
 * Return:	0 on success
 */
int memdisk_create(void *start, size_t size)
{
	struct udevice *dev;
	struct memdisk_plat *plat;
	char dev_name[20], *str;
	int devnum;
	int ret;

	log_info("Creating memdisk size 0x%zx @ 0x%p\n", size, start);

	devnum = blk_next_free_devnum(IF_TYPE_MEMDISK);
	snprintf(dev_name, sizeof(dev_name), "memdsk%d", devnum);
	str = strdup(dev_name);
	if (!str)
		return -ENOMEM;

	ret = blk_create_device(gd->dm_root, "memdsk", str,
				IF_TYPE_MEMDISK, -1, BLK_SIZE,
				size / BLK_SIZE, &dev);
	if (ret)
		goto err;

	plat = dev_get_plat(dev);
	plat->start = start;
	plat->size = size;

	ret = blk_probe_or_unbind(dev);

err:
	return ret;
}

/* Block device driver operators */
static const struct blk_ops mem_blk_ops = {
	.read	= mem_bl_read,
	.write	= mem_bl_write,
};

/* Identify as block device driver */
U_BOOT_DRIVER(memdsk) = {
	.name		= "memdsk",
	.id		= UCLASS_BLK,
	.ops		= &mem_blk_ops,
	.plat_auto	= sizeof(struct memdisk_plat),

};

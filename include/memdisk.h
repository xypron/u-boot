/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Embedded disk image
 *
 * Copyright (c) 2022, Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

/**
 * initr_memdisk() - Initialize embedded memory disk
 */
int initr_memdisk(void);

/**
 * Read from block device
 *
 * @dev:	device
 * @blknr:	first block to be read
 * @blkcnt:	number of blocks to read
 * @buffer:	output buffer
 * Return:	number of blocks transferred
 */
int memdisk_create(void *start, size_t size);

struct memdisk_plat {
	char *start;
	size_t size;
};

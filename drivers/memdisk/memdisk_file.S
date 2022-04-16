/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Embedded disk image
 *
 * Copyright (c) 2022, Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#include <config.h>

.section .rodata.memdisk.init,"a"
.balign 16
.global __memdisk_file_begin
__memdisk_file_begin:
.incbin CONFIG_MEMDISK_FILE
.global __memdisk_file_end
__memdisk_file_end:
.balign 16

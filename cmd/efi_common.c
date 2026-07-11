// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for EFI commands
 *
 * Copyright 2023 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 */

#include <efi.h>
#include <efi_api.h>
#include <u-boot/uuid.h>

static const char *const efi_mem_type_string[] = {
	[EFI_RESERVED_MEMORY_TYPE] = "RESERVED",
	[EFI_LOADER_CODE] = "LOADER CODE",
	[EFI_LOADER_DATA] = "LOADER DATA",
	[EFI_BOOT_SERVICES_CODE] = "BOOT CODE",
	[EFI_BOOT_SERVICES_DATA] = "BOOT DATA",
	[EFI_RUNTIME_SERVICES_CODE] = "RUNTIME CODE",
	[EFI_RUNTIME_SERVICES_DATA] = "RUNTIME DATA",
	[EFI_CONVENTIONAL_MEMORY] = "CONVENTIONAL",
	[EFI_UNUSABLE_MEMORY] = "UNUSABLE MEM",
	[EFI_ACPI_RECLAIM_MEMORY] = "ACPI RECLAIM",
	[EFI_ACPI_MEMORY_NVS] = "ACPI NVS",
	[EFI_MMAP_IO] = "IO",
	[EFI_MMAP_IO_PORT] = "IO PORT",
	[EFI_PAL_CODE] = "PAL",
	[EFI_PERSISTENT_MEMORY_TYPE] = "PERSISTENT",
	[EFI_UNACCEPTED_MEMORY_TYPE] = "UNACCEPTED",
};

static const struct efi_mem_attrs {
	const u64 bit;
	const char *text;
} efi_mem_attrs[] = {
	{EFI_MEMORY_UC, "UC"},
	{EFI_MEMORY_WC, "WC"},
	{EFI_MEMORY_WT, "WT"},
	{EFI_MEMORY_WB, "WB"},
	{EFI_MEMORY_UCE, "UCE"},
	{EFI_MEMORY_WP, "WP"},
	{EFI_MEMORY_RP, "RP"},
	{EFI_MEMORY_XP, "XP"},
	{EFI_MEMORY_NV, "NV"},
	{EFI_MEMORY_MORE_RELIABLE, "REL"},
	{EFI_MEMORY_RO, "RO"},
	{EFI_MEMORY_SP, "SP"},
	{EFI_MEMORY_CPU_CRYPTO, "CRYPT"},
	{EFI_MEMORY_HOT_PLUGGABLE, "HOTPL"},
	{EFI_MEMORY_RUNTIME, "RT"},
};

void efi_show_tables(struct efi_system_table *systab)
{
	int i;

	for (i = 0; i < systab->nr_tables; i++) {
		struct efi_configuration_table *tab = &systab->tables[i];

		printf("%p  %pUl  %s\n", tab->table, tab->guid.b,
		       uuid_guid_get_str(tab->guid.b) ?: "(unknown)");
	}
}

const char *efi_mem_type_name(u32 type)
{
	if (type >= ARRAY_SIZE(efi_mem_type_string))
		return NULL;

	return efi_mem_type_string[type];
}

void efi_print_mem_attrs(u64 attributes)
{
	int sep, i;

	for (sep = 0, i = 0; i < ARRAY_SIZE(efi_mem_attrs); i++)
		if (attributes & efi_mem_attrs[i].bit) {
			if (sep) {
				putc('|');
			} else {
				putc(' ');
				sep = 1;
			}
			puts(efi_mem_attrs[i].text);
		}
}

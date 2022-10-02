// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020, Heinrich Schuchardt <xypron.glpk@gmx.de>
 *
 * dtbdump.efi saves the device tree provided as a configuration table
 * to a file.
 */

#include <common.h>
#include <efi_api.h>
#include <part_efi.h>

struct guid_text {
	efi_guid_t guid;
	u16 *text;
};

#define EFI_PARTITION_INFO_PROTOCOL_GUID \
	EFI_GUID(0x8cf2f62c, 0xbc9b, 0x4821, \
		 0x80, 0x8d, 0xec, 0x9e, 0xc4, 0x21, 0xa1, 0xa0)

/*
#define EFI_DISK_IO_PROTOCOL_GUID \
	EFI_GUID(0xCE345171, 0xBA0B, 0x11d2, \
		 0x8e, 0x4F, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
*/

static const efi_guid_t block_io_guid = EFI_BLOCK_IO_PROTOCOL_GUID;
static const efi_guid_t device_path_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
static const efi_guid_t device_path_to_text_guid =
		EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;

#define efi_size_in_pages(size) ((size + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT)

static struct efi_simple_text_output_protocol *cerr;
static struct efi_simple_text_output_protocol *cout;
static struct efi_boot_services *bs;

/**
 * print() - print string
 *
 * @string:	text
 */
static void print(const u16 *string)
{
	cout->output_string(cout, string);
}

/**
 * error() - print error string
 *
 * @string:	error text
 */
static void error(u16 *string)
{
	cout->set_attribute(cout, EFI_LIGHTRED | EFI_BACKGROUND_BLACK);
	print(string);
	cout->set_attribute(cout, EFI_LIGHTBLUE | EFI_BACKGROUND_BLACK);
}

/**
 * printx() - print hexadecimal number to an u16 string
 *
 * @p:		value to print
 * @prec:	minimum number of digits to print
 * @buf:	pointer to buffer address,
 *		on return position of terminating zero word
 */
static void printx(u64 p, int prec, u16 **buf)
{
	int i;
	u16 c;
	u16 *pos = *buf;

	for (i = 2 * sizeof(p) - 1; i >= 0; --i) {
		c = (p >> (4 * i)) & 0x0f;
		if (c || pos != *buf || !i || i < prec) {
			c += '0';
			if (c > '9')
				c += 'a' - '9' - 1;
			*pos++ = c;
		}
	}
	*pos = 0;
	*buf = pos;
}

/**
 * print_guid() - print GUID to an u16 string
 *
 * @p:		GUID to print
 * @buf:	pointer to buffer address,
 *		on return position of terminating zero word
 */
static void print_uuid(u8 *p, u16 **buf)
{
	int i;
	const u8 seq[] = {
		3, 2, 1, 0, '-', 5, 4, '-', 7, 6, '-',
		8, 9, 10, 11, 12, 13, 14, 15 };

	for (i = 0; i < sizeof(seq); ++i) {
		if (seq[i] == '-')
			*(*buf)++ = u'-';
		else
			printx(p[seq[i]], 2, buf);
	}
}

/**
 * print_guid() - print GUID
 *
 * @guid:	GUID
 */
void print_guid(efi_guid_t *guid)
{
	u16 buf[38];
	u16 *pos = buf;
	struct guid_text guid_text[] = {
		{ EFI_DEVICE_PATH_PROTOCOL_GUID, u"EFI_DEVICE_PATH_PROTOCOL_GUID" },
		{ EFI_BLOCK_IO_PROTOCOL_GUID, u"EFI_BLOCK_IO_PROTOCOL" },
		{ PARTITION_SYSTEM_GUID, u"EFI System Partition" },
		{ EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, u"EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID"},
		{ EFI_PARTITION_INFO_PROTOCOL_GUID, u"EFI_PARTITION_INFO_PROTOCOL"},
		{ EFI_DISK_IO_PROTOCOL_GUID, u"EFI_DISK_IO_PROTOCOL"},
		{ {} , NULL},
	};

	print_uuid((void *)guid, &pos);
	*pos++ = ' ';
	*pos++ = '\0';
	print(buf);

	for (struct guid_text *gpos = guid_text; gpos->text; ++gpos) {
		if (!memcmp(&gpos->guid, guid, 16)) {
			print(gpos->text);
			break;
		}
	}
	print(u"\r\n");
}

/**
 * print_u32() - print u32
 *
 * @val:	value
 */
void print_u32(u32 val)
{
	u16 buf[13];
	u16 *pos = buf;

	*pos++ = '0';
	*pos++ = 'x';
	printx(val, 8, &pos);
	*pos++ = '\r';
	*pos++ = '\n';
	*pos++ = '\0';
	print(buf);
}

/**
 * print_attributes() - print attributes
 *
 * @val:	value
 */
void print_attributes(u32 val)
{
	struct guid_text attr_text[] = {
		{{}, u"EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL"},
		{{}, u"EFI_OPEN_PROTOCOL_GET_PROTOCOL"},
		{{}, u"EFI_OPEN_PROTOCOL_TEST_PROTOCOL"},
		{{}, u"EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER"},
		{{}, u"EFI_OPEN_PROTOCOL_BY_DRIVER"},
		{{}, u"EFI_OPEN_PROTOCOL_EXCLUSIVE"},
		{{}, NULL},
	};
	u32 mask = 1;
	int first = 0;

	for (struct guid_text *pos = attr_text; pos->text; ++pos, mask <<= 1) {
		if (mask & val) {
			if (first) {
				print(u" | ");
				++first;
			}
			print(pos->text);
		}
	}
	print(u"\r\n");
}

/**
 * print_handle() - print handle
 *
 * @handle:	handle
 */
void print_handle(efi_handle_t handle)
{
	u16 buf[19];
	u16 *pos = buf;
	struct efi_device_path *dp;
	struct efi_device_path_to_text_protocol *dpt;
	u16 *dp_text;
	efi_uintn_t ret;

	printx((uintptr_t)handle, 2 * sizeof(long), &pos);
	*pos++ = ' ';
	*pos++ = '\0';
	print(buf);

	ret = bs->open_protocol(handle, &device_path_guid, (void **)&dp, NULL,
				NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (ret != EFI_SUCCESS)
		goto out;
	ret = bs->locate_protocol(&device_path_to_text_guid, NULL, (void **)&dpt);
	if (ret != EFI_SUCCESS)
		goto out;

	dp_text = dpt->convert_device_path_to_text(dp, false, false);

	if (dp_text) {
		print(dp_text);
		bs->free_pool(dp_text);
	}

out:
	print(u"\r\n");
}

/**
 * print_open_protocol_information() print open protocol information
 *
 * @handle:	handle
 * @prot:	protocol GUID
 */
void print_open_protocol_information(efi_handle_t handle, efi_guid_t *prot)
{
	efi_status_t ret;
	struct efi_open_protocol_info_entry *buffer;
	efi_uintn_t count;

	ret = bs->open_protocol_information(handle, prot, &buffer, &count);
	if (ret == EFI_NOT_FOUND) {
		error(u"Handle doesn't support specified protocol\r\n");
		return;
	}
	if (ret != EFI_SUCCESS) {
		error(u"Failed to get open protocol information\r\n");
		return;
	}

	for (efi_uintn_t i = 0; i < count; ++i) {
		struct efi_open_protocol_info_entry *info = &buffer[i];	

		print(u"    AgentHandle - ");
		print_handle(info->agent_handle);
		print(u"    ControllerHandle - ");
		print_handle(info->controller_handle);
		print(u"    Attributes - ");
		print_attributes(info->attributes);
		print(u"    OpenCount - ");
		print_u32(info->open_count);
	}

	if (buffer) {
		ret = bs->free_pool(buffer);
		if (ret != EFI_SUCCESS)
			error(u"Could not free buffer\r\n");
	}
}

/**
 * print_handle() - print protocols installed on handle
 *
 * @handle:	handle
 */
void print_protocols(efi_handle_t handle)
{
	efi_guid_t **buffer = NULL;
	efi_uintn_t count;
	efi_status_t ret;

	ret = bs->protocols_per_handle(handle, &buffer, &count);
	if (ret != EFI_SUCCESS) {
		error(u"Can't get protocols\n\n");
		return;
	}
	for (efi_uintn_t i = 0; i < count; ++i) {
		efi_guid_t *prot = buffer[i];

		print(u"  protocol - ");
		print_guid(prot);
		print_open_protocol_information(handle, prot);
	}
	if (buffer) {
		ret = bs->free_pool(buffer);
		if (ret != EFI_SUCCESS)
			error(u"Could not free buffer\r\n");
	}
}

/**
 * efi_main() - entry point of the EFI application.
 *
 * @handle:	handle of the loaded image
 * @systab:	system table
 * Return:	status code
 */
efi_status_t EFIAPI efi_main(efi_handle_t image_handle,
			     struct efi_system_table *systab)
{
	efi_status_t ret;
	efi_handle_t *handles = NULL;
	efi_uintn_t no_handles;

	cerr = systab->std_err;
	cout = systab->con_out;
	bs = systab->boottime;

	cout->set_attribute(cout, EFI_LIGHTBLUE | EFI_BACKGROUND_BLACK);
	cout->set_attribute(cout, EFI_WHITE | EFI_BACKGROUND_BLACK);
	print(u"Block Devices Dump\r\n==================\r\n\r\n");
	cout->set_attribute(cout, EFI_LIGHTBLUE | EFI_BACKGROUND_BLACK);

	ret = bs->locate_handle_buffer(BY_PROTOCOL, &block_io_guid, NULL,
				       &no_handles, &handles);
	if (ret != EFI_SUCCESS) {
		error(u"Could not locate handles\r\n");
		goto out;
	}

	for (efi_uintn_t i = 0; i < no_handles; ++i) {
		efi_handle_t h = handles[i];

		print_handle(h);
		print_protocols(h);
		print(u"\r\n");
	}

out:
	if (handles) {
		ret = bs->free_pool(handles);
		if (ret != EFI_SUCCESS)
			error(u"Could not free handles\r\n");
	}
	cout->set_attribute(cout, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
	return EFI_SUCCESS;
}

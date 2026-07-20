// SPDX-License-Identifier: GPL-2.0+
/*
 * The 'sbi' command displays information about the SBI implementation.
 *
 * Copyright (c) 2020, Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#include <efi_api.h>
#include <errno.h>
#include <asm/sbi.h>
#include <vsprintf.h>

struct sbi_imp {
	const long id;
	const char *name;
};

struct sbi_ext {
	const u32 id;
	const char *name;
};

static struct efi_boot_services *bs;
static struct efi_simple_text_input_protocol *cin;
static struct efi_simple_text_output_protocol *cout;

static struct sbi_imp implementations[] = {
	{ 0, "Berkeley Boot Loader (BBL)" },
	{ 1, "OpenSBI" },
	{ 2, "Xvisor" },
	{ 3, "KVM" },
	{ 4, "RustSBI" },
	{ 5, "Diosix" },
	{ 6, "Coffer" },
	{ 7, "Xen Project" },
	{ 8, "PolarFire Hart Software Services" },
	{ 9, "coreboot" },
	{ 10, "oreboot" },
	{ 11, "bhyve" },
};

static struct sbi_ext extensions[] = {
	{ SBI_EXT_0_1_SET_TIMER,	      "Set Timer" },
	{ SBI_EXT_0_1_CONSOLE_PUTCHAR,	      "Console Putchar" },
	{ SBI_EXT_0_1_CONSOLE_GETCHAR,	      "Console Getchar" },
	{ SBI_EXT_0_1_CLEAR_IPI,	      "Clear IPI" },
	{ SBI_EXT_0_1_SEND_IPI,		      "Send IPI" },
	{ SBI_EXT_0_1_REMOTE_FENCE_I,	      "Remote FENCE.I" },
	{ SBI_EXT_0_1_REMOTE_SFENCE_VMA,      "Remote SFENCE.VMA" },
	{ SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID, "Remote SFENCE.VMA with ASID" },
	{ SBI_EXT_0_1_SHUTDOWN,		      "System Shutdown" },
	{ SBI_EXT_BASE,			      "SBI Base Functionality" },
	{ SBI_EXT_TIME,			      "Timer Extension" },
	{ SBI_EXT_IPI,			      "IPI Extension" },
	{ SBI_EXT_RFENCE,		      "RFENCE Extension" },
	{ SBI_EXT_HSM,			      "Hart State Management Extension" },
	{ SBI_EXT_SRST,			      "System Reset Extension" },
	{ SBI_EXT_PMU,			      "Performance Monitoring Unit Extension" },
	{ SBI_EXT_DBCN,			      "Debug Console Extension" },
	{ SBI_EXT_SUSP,			      "System Suspend Extension" },
	{ SBI_EXT_CPPC,			      "Collaborative Processor Performance Control Extension" },
	{ SBI_EXT_NACL,			      "Nested Acceleration Extension" },
	{ SBI_EXT_STA,			      "Steal-time Accounting Extension" },
	{ SBI_EXT_SSE,			      "Supervisor Software Events" },
	{ SBI_EXT_FWFT,			      "Firmware Features Extension" },
	{ SBI_EXT_DBTR,			      "Debug Triggers Extension" },
	{ SBI_EXT_MPXY,			      "Message Proxy Extension" },
};

static struct sbiret xbi_ecall(int ext, int fid, unsigned long arg0,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5)
{
	struct sbiret ret;

	register uintptr_t a0 asm ("a0") = (uintptr_t)(arg0);
	register uintptr_t a1 asm ("a1") = (uintptr_t)(arg1);
	register uintptr_t a2 asm ("a2") = (uintptr_t)(arg2);
	register uintptr_t a3 asm ("a3") = (uintptr_t)(arg3);
	register uintptr_t a4 asm ("a4") = (uintptr_t)(arg4);
	register uintptr_t a5 asm ("a5") = (uintptr_t)(arg5);
	register uintptr_t a6 asm ("a6") = (uintptr_t)(fid);
	register uintptr_t a7 asm ("a7") = (uintptr_t)(ext);
	asm volatile ("ecall"
		      : "+r" (a0), "+r" (a1)
		      : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
		      : "memory");
	ret.error = a0;
	ret.value = a1;

	return ret;
}

/**
 * xbi_get_spec_version() - get current SBI specification version
 *
 * Return: version id
 */
static long xbi_get_spec_version(void)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION,
			0, 0, 0, 0, 0, 0);
	if (!ret.error)
		if (ret.value)
			return ret.value;

	return -ENOTSUPP;
}

/**
 * xbi_get_impl_id() - get SBI implementation ID
 *
 * Return: implementation ID
 */
static int xbi_get_impl_id(void)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID,
			0, 0, 0, 0, 0, 0);
	if (!ret.error)
		if (ret.value)
			return ret.value;

	return -ENOTSUPP;
}

/**
 * xbi_get_impl_version() - get SBI implementation version
 *
 * @version:	pointer to receive version
 * Return:	0 on success, -ENOTSUPP otherwise
 */
static int xbi_get_impl_version(long *version)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		return -ENOTSUPP;
	if (version)
		*version = ret.value;
	return 0;
}

/**
 * xbi_probe_extension() - Check if an SBI extension ID is supported or not.
 * @extid: The extension ID to be probed.
 *
 * Return: Extension specific nonzero value f yes, -ENOTSUPP otherwise.
 */
static int xbi_probe_extension(int extid)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid,
			0, 0, 0, 0, 0);
	if (!ret.error)
		if (ret.value)
			return ret.value;

	return -ENOTSUPP;
}

/**
 * xbi_get_mvendorid() - get machine vendor ID
 *
 * @mimpid:	on return machine vendor ID
 * Return:	0 on success
 */
static int xbi_get_mvendorid(long *mvendorid)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MVENDORID,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		return -ENOTSUPP;

	if (mvendorid)
		*mvendorid = ret.value;

	return 0;
}

/**
 * xbi_get_marchid() - get machine architecture ID
 *
 * @mimpid:	on return machine architecture ID
 * Return:	0 on success
 */
static int xbi_get_marchid(long *marchid)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MARCHID,
			0, 0, 0, 0, 0, 0);

	if (ret.error)
		return -ENOTSUPP;

	if (marchid)
		*marchid = ret.value;

	return 0;
}

/**
 * xbi_get_mimpid() - get machine implementation ID
 *
 * @mimpid:	on return machine implementation ID
 * Return:	0 on success
 */
static int xbi_get_mimpid(long *mimpid)
{
	struct sbiret ret;

	ret = xbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MIMPID,
			0, 0, 0, 0, 0, 0);

	if (ret.error)
		return -ENOTSUPP;

	if (mimpid)
		*mimpid = ret.value;

	return 0;
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
 * uint2dec() - print an unsigned 32bit value as decimal number to an u16 string
 *
 * @value:	value to be printed
 * @prec:	minimum number of digits to display
 * @buf:	pointer to buffer address,
 *		on return position of terminating zero word
 */
static void uint2dec(u32 value, int prec, u16 **buf)
{
	u16 *pos = *buf;
	int i;
	u16 c;
	u64 f;

	/*
	 * Increment by .5 and multiply with
	 * (2 << 60) / 1,000,000,000 = 0x44B82FA0.9B5A52CC
	 * to move the first digit to bit 60-63.
	 */
	f = 0x225C17D0;
	f += (0x9B5A52DULL * value) >> 28;
	f += 0x44B82FA0ULL * value;

	for (i = 0; i < 10; ++i) {
		/* Write current digit */
		c = f >> 60;
		if (c || pos != *buf || 10 - i <= prec)
			*pos++ = c + '0';
		/* Eliminate current digit */
		f &= 0xfffffffffffffff;
		/* Get next digit */
		f *= 0xaULL;
	}
	if (pos == *buf)
		*pos++ = '0';
	*pos = 0;
	*buf = pos;
}

/**
 * int2dec() - print a signed 32bit value as decimal number to an u16 string
 *
 * @value:	value to be printed
 * @prec:	minimum number of digits to display
 * @buf:	pointer to buffer address,
 *		on return position of terminating zero word
 */
static void int2dec(s32 value, int prec, u16 **buf)
{
	u32 u;
	u16 *pos = *buf;

	if (value < 0) {
		*pos++ = '-';
		u = -value;
	} else {
		u = value;
	}
	uint2dec(u, prec, &pos);
	*buf = pos;
}

/**
 * printf() - print a message
 *
 * @fmt:	printf style format string
 * @...:	arguments to be printed
 */
int printf(const char *fmt, ...)
{
	va_list args;
	u16 buf[160];
	const char *c;
	u16 *pos = buf;
	const char *s;
	u16 *u;
	int prec;
	int lflag = 0;

	va_start(args, fmt);

	c = fmt;
	for (; *c; ++c) {
		switch (*c) {
		case '\\':
			++c;
			switch (*c) {
			case '\0':
				--c;
				break;
			case 'n':
				*pos++ = '\n';
				break;
			case 'r':
				*pos++ = '\r';
				break;
			case 't':
				*pos++ = '\t';
				break;
			default:
				*pos++ = *c;
			}
			break;
		case '%':
			++c;
			if (*c == 'l') {
				lflag = 1;
				++c;
			}
			/* Parse precision */
			if (*c == '.') {
				++c;
				prec = *c - '0';
				++c;
			} else {
				prec = 0;
			}
			switch (*c) {
			case '\0':
				--c;
				break;
			case 'p':
				++c;
				switch (*c) {
				/* u16 string */
				case 's':
					u = va_arg(args, u16*);
					if (pos > buf) {
						*pos = 0;
						cout->output_string(cout,
								       buf);
					}
					cout->output_string(cout, u);
					pos = buf;
					break;
				default:
					--c;
					printx((uintptr_t)va_arg(args, void *),
					       2 * sizeof(void *), &pos);
					break;
				}
				break;
			case 's':
				s = va_arg(args, const char *);
				for (; *s; ++s)
					*pos++ = *s;
				break;
			case 'd':
				if (lflag)
					int2dec(va_arg(args, s64), prec, &pos);
				else
					int2dec(va_arg(args, s32), prec, &pos);
				break;
			case 'u':
				if (lflag)
					uint2dec(va_arg(args, s64), prec, &pos);
				else
					uint2dec(va_arg(args, s32), prec, &pos);
				break;
			case 'x':
				if (lflag)
					printx((u64)va_arg(args, unsigned long),
				 	      prec, &pos);
				else
					printx((u64)va_arg(args, unsigned int),
				 	      prec, &pos);
				break;
			default:
				break;
			}
			break;
		default:
			*pos++ = *c;
		}
	}
	va_end(args);
	*pos = 0;
	cout->output_string(cout, buf);

	return 0;
}

/**
 * efi_input() - read string from console
 *
 * @buffer:		input buffer
 * @buffer_size:	buffer size
 * Return:		status code
 */
static efi_status_t efi_input(char *buffer, efi_uintn_t buffer_size)
{
	struct efi_input_key key = {0};
	efi_uintn_t index;
	efi_uintn_t pos = 0;
	char outbuf[2] = " ";
	efi_status_t ret;

	*buffer = 0;
	for (;;) {
		ret = bs->wait_for_event(1, &cin->wait_for_key, &index);
		if (ret != EFI_SUCCESS)
			continue;
		ret = cin->read_key_stroke(cin, &key);
		if (ret != EFI_SUCCESS)
			continue;
		switch (key.scan_code) {
		case 0x17: /* Escape */
			printf("\r\nAborted\r\n");
			return EFI_ABORTED;
		default:
			break;
		}
		switch (key.unicode_char) {
		case 0x08: /* Backspace */
			if (pos) {
				buffer[pos--] = 0;
				printf("\b \b");
			}
			break;
		case 0x0a: /* Linefeed */
		case 0x0d: /* Carriage return */
			printf("\r\n");
			return EFI_SUCCESS;
		default:
			break;
		}
		/* Ignore surrogate codes */
		if (key.unicode_char >= 0xD800 && key.unicode_char <= 0xDBFF)
			continue;
		if (key.unicode_char >= 0x20 &&
		    pos < buffer_size - 1) {
			*outbuf = key.unicode_char;
			buffer[pos++] = key.unicode_char;
			buffer[pos] = 0;
			printf(outbuf);
		}
	}
}

void do_sbi(void)
{
	int i, impl_id;
	long ret;
	long mvendorid, marchid, mimpid;

	ret = xbi_get_spec_version();
	if (ret < 0) {
		printf("No SBI 0.2+\r\n");
		return;
	}
	printf("SBI %lu.%lu", ret >> 24, ret & 0xffffff);
	impl_id = xbi_get_impl_id();
	if (impl_id >= 0) {
		for (i = 0; i < ARRAY_SIZE(implementations); ++i) {
			if (impl_id == implementations[i].id) {
				long vers;

				printf("\n%s ", implementations[i].name);
				ret = xbi_get_impl_version(&vers);
				if (ret < 0)
					break;
				switch (impl_id) {
				case 1: /* OpenSBI */
				case 8: /* PolarFire Hart Software Services */
					printf("%lu.%lu",
					       vers >> 16, vers & 0xffff);
					break;
				case 3: /* KVM */
				case 4: /* RustSBI */
					printf("%lu.%lu.%lu",
					       vers >> 16,
					       (vers >> 8) & 0xff,
					       vers & 0xff);
					break;
				default:
					printf("0x%lx", vers);
					break;
				}
				break;
			}
		}
		if (i == ARRAY_SIZE(implementations))
			printf("\nUnknown implementation ID 0x%x", impl_id);
	}
	printf("\nMachine:\n");
	ret = xbi_get_mvendorid(&mvendorid);
	if (!ret)
		printf("  Vendor ID %lx\n", mvendorid);
	ret = xbi_get_marchid(&marchid);
	if (!ret)
		printf("  Architecture ID %lx\n", marchid);
	ret = xbi_get_mimpid(&mimpid);
	if (!ret)
		printf("  Implementation ID %lx\n", mimpid);
	printf("Extensions:\n");
	for (i = 0; i < ARRAY_SIZE(extensions); ++i) {
		ret = xbi_probe_extension(extensions[i].id);
		if (ret > 0)
			printf("  %s\n", extensions[i].name);
	}
	return;
}

/**
 * efi_drain_input() - drain console input
 */
static void efi_drain_input(void)
{
	cin->reset(cin, true);
}

/**
 * skip_whitespace() - skip over leading whitespace
 *
 * @pos:	UTF-16 string
 * Return:	pointer to first non-whitespace
 */
static char *skip_whitespace(char *pos)
{
	for (; *pos && *pos <= 0x20; ++pos)
		;
	return pos;
}

/**
 * starts_with() - check if @string starts with @keyword
 *
 * @string:	string to search for keyword
 * @keyword:	keyword to be searched
 * Return:	true fi @string starts with the keyword
 */
static bool starts_with(char *string, char *keyword)
{
	if (!string || !keyword)
		return false;

	for (; *keyword; ++string, ++keyword) {
		if (*string != *keyword)
			return false;
	}
	return true;
}

/**
 * do_help() - print help
 */
static void do_help(void)
{
	printf("dump     - show SBI information\r\n");
	printf("reboot   - reboot the device\r\n");
	printf("poweroff - power off the device\r\n");
	printf("exit     - exit\r\n");
}

static void do_reboot(void)
{
	xbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET,
		  SBI_SRST_RESET_TYPE_COLD_REBOOT, SBI_SRST_RESET_REASON_NONE,
		  0, 0, 0, 0);
}

static void do_poweroff(void)
{
	xbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET,
		  SBI_SRST_RESET_TYPE_SHUTDOWN, SBI_SRST_RESET_REASON_NONE,
		  0, 0, 0, 0);
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
	cin = systab->con_in;
	cout = systab->con_out;
	bs = systab->boottime;

	printf("\r\nSBI Dump\r\n========\r\n\r\n");

	for (;;) {
		char command[64];
		char *pos;
		efi_uintn_t ret;

		efi_drain_input();
		printf("$ ");
		ret = efi_input(command, sizeof(command));
		if (ret == EFI_ABORTED)
			break;
		pos = skip_whitespace(command);
		if (starts_with(pos, "exit"))
			break;
		else if (starts_with(pos, "dump"))
			do_sbi();
		else if (starts_with(pos, "reboot"))
			do_reboot();
		else if (starts_with(pos, "poweroff"))
			do_poweroff();
		else
			do_help();
	}

	return EFI_SUCCESS;
}

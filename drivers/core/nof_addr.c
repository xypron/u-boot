// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file contains dummy function implementations that are only needed
 * when compiling with -Og. In this case the optimizer does not remove
 * function calls based on CONFIG_$(PHASE_)OF_LIVE.
 */

#include <dm/of_addr.h>
#include <linux/errno.h>

const __be32 *of_get_address(const struct device_node *dev, int index,
			     u64 *size, unsigned int *flags)
{
	return NULL;
}

u64 of_translate_address(const struct device_node *dev, const __be32 *in_addr)
{
	return -ENOSYS;
}

u64 of_translate_dma_address(const struct device_node *dev, const __be32 *in_addr)
{
	return -ENOSYS;
}

int of_get_dma_range(const struct device_node *dev, phys_addr_t *cpu,
		     dma_addr_t *bus, u64 *size)
{
	return -ENOSYS;
}

int of_address_to_resource(const struct device_node *dev, int index,
			   struct resource *r)
{
	return -ENOSYS;
}

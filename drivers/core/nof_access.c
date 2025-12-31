// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file contains dummy function implementations that are only needed
 * when compiling with -Og. In this case the optimizer does not remove
 * function calls based on CONFIG_$(PHASE_)OF_LIVE.
 */

#include <dm/of_access.h>
#include <linux/errno.h>

int of_n_addr_cells(const struct device_node *np)
{
	return -ENOSYS;
}

int of_n_size_cells(const struct device_node *np)
{
	return -ENOSYS;
}

int of_simple_addr_cells(const struct device_node *np)
{
	return -ENOSYS;
}

int of_simple_size_cells(const struct device_node *np)
{
	return -ENOSYS;
}

struct property *of_find_property(const struct device_node *np,
				  const char *name, int *lenp)
{
	return NULL;
}

struct device_node *of_find_all_nodes(struct device_node *prev)
{
	return NULL;
}

const void *of_get_property(const struct device_node *np, const char *name,
			    int *lenp)
{
	return NULL;
}

const struct property *of_get_first_property(const struct device_node *np)
{
	return NULL;
}

const struct property *of_get_next_property(const struct device_node *np,
					    const struct property *property)
{
	return NULL;
}

const void *of_get_property_by_prop(const struct device_node *np,
				    const struct property *property,
				    const char **name,
				    int *lenp)
{
	return NULL;
}

int of_device_is_compatible(const struct device_node *device,
			    const char *compat, const char *type,
			    const char *name)
{
	return -ENOSYS;
}

bool of_device_is_available(const struct device_node *device)
{
	return false;
}

struct device_node *of_get_parent(const struct device_node *node)
{
	return NULL;
}

struct device_node *of_find_node_opts_by_path(struct device_node *root,
					      const char *path,
					      const char **opts)
{
	return NULL;
}

struct device_node *of_find_compatible_node(struct device_node *from,
		const char *type, const char *compatible)
{
	return NULL;
}

struct device_node *of_find_node_by_prop_value(struct device_node *from,
					       const char *propname,
					       const void *propval, int proplen)
{
	return NULL;
}

struct device_node *of_find_node_by_phandle(struct device_node *root,
					    phandle handle)
{
	return NULL;
}

int of_read_u8(const struct device_node *np, const char *propname, u8 *outp)
{
	return -ENOSYS;
}

int of_read_u16(const struct device_node *np, const char *propname, u16 *outp)
{
	return -ENOSYS;
}

int of_read_u32(const struct device_node *np, const char *propname, u32 *outp)
{
	return -ENOSYS;
}

int of_read_u32_array(const struct device_node *np, const char *propname,
		      u32 *out_values, size_t sz)
{
	return -ENOSYS;
}

int of_read_u32_index(const struct device_node *np, const char *propname,
		      int index, u32 *outp)
{
	return -ENOSYS;
}

int of_read_u64_index(const struct device_node *np, const char *propname,
		      int index, u64 *outp)
{
	return -ENOSYS;
}

int of_read_u64(const struct device_node *np, const char *propname, u64 *outp)
{
	return -ENOSYS;
}

int of_property_match_string(const struct device_node *np, const char *propname,
			     const char *string)
{
	return -ENOSYS;
}

int of_property_read_string_helper(const struct device_node *np,
				   const char *propname, const char **out_strs,
				   size_t sz, int skip)
{
	return -ENOSYS;
}

struct device_node *of_root_parse_phandle(struct device_node *root,
					  const struct device_node *np,
					  const char *phandle_name, int index)
{
	return NULL;
}

int of_root_parse_phandle_with_args(struct device_node *root,
				    const struct device_node *np,
				    const char *list_name, const char *cells_name,
				    int cell_count, int index,
				    struct of_phandle_args *out_args)
{
	return -ENOSYS;
}

int of_root_count_phandle_with_args(struct device_node *root,
				    const struct device_node *np,
				    const char *list_name, const char *cells_name,
				    int cell_count)
{
	return -ENOSYS;
}

struct device_node *of_parse_phandle(const struct device_node *np,
				     const char *phandle_name, int index)
{
	return NULL;
}

int of_parse_phandle_with_args(const struct device_node *np,
			       const char *list_name, const char *cells_name,
			       int cell_count, int index,
			       struct of_phandle_args *out_args)
{
	return -ENOSYS;
}

int of_count_phandle_with_args(const struct device_node *np,
			       const char *list_name, const char *cells_name,
			       int cell_count)
{
	return -ENOSYS;
}

int of_alias_scan(void)
{
	return -ENOSYS;
}

int of_alias_get_id(const struct device_node *np, const char *stem)
{
	return -ENOSYS;
}

int of_alias_get_highest_id(const char *stem)
{
	return -ENOSYS;
}

struct device_node *of_get_stdout(void)
{
	return NULL;
}

int of_write_prop(struct device_node *np, const char *propname, int len,
		  const void *value)
{
	return -ENOSYS;
}

int of_add_subnode(struct device_node *parent, const char *name, int len,
		   struct device_node **childp)
{
	return -ENOSYS;
}

int of_remove_property(struct device_node *np, struct property *prop)
{
	return -ENOSYS;
}

int of_remove_node(struct device_node *to_remove)
{
	return -ENOSYS;
}

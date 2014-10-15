/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2013 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBE_PIPELINE_H_
#define _IXGBE_PIPELINE_H_

#include <uapi/linux/if_flow.h>

struct hw_flow_field ethernet_fields[3] = {
	{ .name = "src_mac", .uid = 0, .bitwidth = 48},
	{ .name = "dst_mac", .uid = 1, .bitwidth = 48},
	{ .name = "ethertype", .uid = 2, .bitwidth = 16},
};

const struct hw_flow_header ethernet = {
	.name = "ethernet",
	.uid = 0,
	.field_sz = 3,
	.fields = ethernet_fields,
};

struct hw_flow_field vlan_fields[4] = {
	{ .name = "pcp", .uid = 0, .bitwidth = 3,},
	{ .name = "cfi", .uid = 1, .bitwidth = 1,},
	{ .name = "vid", .uid = 2, .bitwidth = 1,},
	{ .name = "ethertype", .uid = 3, .bitwidth = 16,},
};

const struct hw_flow_header vlan = {
	.name = "vlan",
	.uid = 1,
	.field_sz = 4,
	.fields = vlan_fields,
};

struct hw_flow_field ipv4_fields[14] = {
	{ .name = "version",
	  .uid = 0,
	  .bitwidth = 4,},
	{ .name = "ihl",
	  .uid = 1,
	  .bitwidth = 4,},
	{ .name = "dscp",
	  .uid = 2,
	  .bitwidth = 6,},
	{ .name = "ecn",
	  .uid = 3,
	  .bitwidth = 2,},
	{ .name = "length",
	  .uid = 4,
	  .bitwidth = 8,},
	{ .name = "identification",
	  .uid = 5,
	  .bitwidth = 8,},
	{ .name = "flags",
	  .uid = 6,
	  .bitwidth = 3,},
	{ .name = "fragment_offset",
	  .uid = 7,
	  .bitwidth = 13,},
	{ .name = "ttl",
	  .uid = 8,
	  .bitwidth = 1,},
	{ .name = "protocol",
	  .uid = 9,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 10,
	  .bitwidth = 8,},
	{ .name = "src_ip",
	  .uid = 11,
	  .bitwidth = 32,},
	{ .name = "dst_ip",
	  .uid = 12,
	  .bitwidth = 32,},
	{ .name = "options",
	  .uid = 13,
	  .bitwidth = -1,},
};

const struct hw_flow_header ipv4 = {
	.name = "ipv4",
	.uid = 2,
	.field_sz = 14,
	.fields = ipv4_fields,
};

struct hw_flow_field tcp_fields[10] = {
	{ .name = "src_port",
	  .uid = 0,
	  .bitwidth = 16,
	},
	{ .name = "dst_port",
	  .uid = 1,
	  .bitwidth = 16,
	},
	{ .name = "seq",
	  .uid = 2,
	  .bitwidth = 32,
	},
	{ .name = "ack",
	  .uid = 3,
	  .bitwidth = 32,
	},
	{ .name = "offset",
	  .uid = 4,
	  .bitwidth = 4,
	},
	{ .name = "reserved",
	  .uid = 5,
	  .bitwidth = 3},
	{ .name = "flags",
	  .uid = 6,
	  .bitwidth = 9},
	{ .name = "window",
	  .uid = 7,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 8,
	  .bitwidth = 16,},
	{ .name = "urgent",
	  .uid = 9,
	  .bitwidth = 16},
};

const struct hw_flow_header tcp = {
	.name = "tcp",
	.uid = 3,
	.field_sz = 10,
	.fields = tcp_fields,
};

struct hw_flow_field metadata_fields[2] = {
	{ .name = "egress_port",
	  .uid = 0,
	  .bitwidth = 32,
	},
	{ .name = "egress_queue",
	  .uid = 1,
	  .bitwidth = 32,
	}
};

const struct hw_flow_header metadata_t = {
	.name = "metadata_t",
	.uid = 4,
	.field_sz = 2,
	.fields = metadata_fields,
};

struct hw_flow_action_arg l2_action_args[2] = {
	{
		.name = "port_id",
		.type = HW_FLOW_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = HW_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct hw_flow_action l2_actions[2] =
{
	{
		.name = "set_egress_port",
		.uid = 0,
		.args = l2_action_args,
	},
	{
		.name = "",
		.uid = 0,
		.args = NULL,
	},
};

struct hw_flow_action_arg meta_action_egress_args[2] = {
	{
		.name = "queue",
		.type = HW_FLOW_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = HW_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct hw_flow_action_arg meta_action_drop_args[1] = {
	{
		.name = "",
		.type = HW_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct hw_flow_action meta_action[3] =
{
	{
		.name = "set_egress_queue",
		.uid = 0,
		.args = meta_action_egress_args,
	},
	{
		.name = "drop_packet",
		.uid = 1,
		.args = meta_action_drop_args,
	},
	{
		.name = "",
		.uid = 0,
		.args = NULL,
	},
};

struct hw_flow_field_ref fdir_matches[8] =
{
	{ .header = 1, .field = 2},
	{ .header = 1, .field = 3},
	{ .header = 2, .field = 11},
	{ .header = 2, .field = 12},
	{ .header = 3, .field = 0},
	{ .header = 3, .field = 1},
	{ .header = 3, .field = 6},
	{ .header = 0, .field = 0},
};

struct hw_flow_field_ref l2_matches[2] =
{
	{ .header = 0, .field = 1, .type = 0 },
	{ .header = 0, .field = 0, .type = 0 },
};

#define IXGBE_L2_TABLE		0
#define IXGBE_FDIR_TABLE	1

struct hw_flow_table ixgbe_table_list[2] =
{
	{
		.name = "l2_table",
		.uid = IXGBE_L2_TABLE,
		.source = 0,
		.size = 128,
		.matches = l2_matches,
		.actions = l2_actions,
		.flows = NULL,
	},
	{
		.name = "fdir_table",
		.uid = IXGBE_FDIR_TABLE,
		.source = 0,
		.size = 2000,
		.matches = fdir_matches,
		.actions = meta_action,
		.flows = NULL,
	},
};

struct hw_flow_tables ixgbe_tables = {
	.table_sz = 2,
	.tables = ixgbe_table_list,
};

const struct hw_flow_header nill = {.name = "", .uid = 0, .field_sz=0, .fields = NULL};

const struct hw_flow_header *ixgbe_header_list[6] =
{
	&ethernet,
	&vlan,
	&ipv4,
	&tcp,
	&metadata_t,
	&nill,
};

struct hw_flow_headers ixgbe_headers =
{
	.hw_flow_headers = ixgbe_header_list,
};

#endif /*_IXGBE_PIPELINE_H_*/

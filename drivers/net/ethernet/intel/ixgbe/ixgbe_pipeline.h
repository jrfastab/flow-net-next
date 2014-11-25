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

#define HEADER_INSTANCE_ETHERNET 1
#define HEADER_INSTANCE_VLAN_OUTER 2
#define HEADER_INSTANCE_VLAN_INNER 3
#define HEADER_INSTANCE_IP 4
#define HEADER_INSTANCE_TCP 5

#define HEADER_ETHERNET_SRC_MAC 1
#define HEADER_ETHERNET_DST_MAC 2
#define HEADER_ETHERNET_ETHERTYPE 3
struct net_flow_field ethernet_fields[3] = {
	{ .name = "src_mac", .uid = HEADER_ETHERNET_SRC_MAC, .bitwidth = 48},
	{ .name = "dst_mac", .uid = HEADER_ETHERNET_DST_MAC, .bitwidth = 48},
	{ .name = "ethertype", .uid = HEADER_ETHERNET_ETHERTYPE, .bitwidth = 16},
};

#define HEADER_ETHERNET 1
struct net_flow_header ethernet = {
	.name = "ethernet",
	.uid = 1,
	.field_sz = 3,
	.fields = ethernet_fields,
};

#define HEADER_VLAN_PCP 1
#define HEADER_VLAN_CFI 2
#define HEADER_VLAN_VID 3
#define HEADER_VLAN_ETHERTYPE 4
struct net_flow_field vlan_fields[4] = {
	{ .name = "pcp", .uid = HEADER_VLAN_PCP, .bitwidth = 3,},
	{ .name = "cfi", .uid = HEADER_VLAN_CFI, .bitwidth = 1,},
	{ .name = "vid", .uid = HEADER_VLAN_VID, .bitwidth = 12,},
	{ .name = "ethertype", .uid = HEADER_VLAN_ETHERTYPE, .bitwidth = 16,},
};

#define HEADER_VLAN 2
struct net_flow_header vlan = {
	.name = "vlan",
	.uid = 2,
	.field_sz = 4,
	.fields = vlan_fields,
};

#define HEADER_IPV4_VERSION 1
#define HEADER_IPV4_IHL 2
#define HEADER_IPV4_DSCP 3
#define HEADER_IPV4_ECN 4
#define HEADER_IPV4_LENGTH 5
#define HEADER_IPV4_IDENTIFICATION 6
#define HEADER_IPV4_FLAGS 7
#define HEADER_IPV4_FRAGMENT_OFFSET 8
#define HEADER_IPV4_TTL 9
#define HEADER_IPV4_PROTOCOL 10
#define HEADER_IPV4_CSUM 11
#define HEADER_IPV4_SRC_IP 12
#define HEADER_IPV4_DST_IP 13
#define HEADER_IPV4_OPTIONS 14
struct net_flow_field ipv4_fields[14] = {
	{ .name = "version",
	  .uid = 1,
	  .bitwidth = 4,},
	{ .name = "ihl",
	  .uid = 2,
	  .bitwidth = 4,},
	{ .name = "dscp",
	  .uid = 3,
	  .bitwidth = 6,},
	{ .name = "ecn",
	  .uid = 4,
	  .bitwidth = 2,},
	{ .name = "length",
	  .uid = 5,
	  .bitwidth = 8,},
	{ .name = "identification",
	  .uid = 6,
	  .bitwidth = 8,},
	{ .name = "flags",
	  .uid = 7,
	  .bitwidth = 3,},
	{ .name = "fragment_offset",
	  .uid = 8,
	  .bitwidth = 13,},
	{ .name = "ttl",
	  .uid = 9,
	  .bitwidth = 1,},
	{ .name = "protocol",
	  .uid = 10,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 11,
	  .bitwidth = 8,},
	{ .name = "src_ip",
	  .uid = 12,
	  .bitwidth = 32,},
	{ .name = "dst_ip",
	  .uid = 13,
	  .bitwidth = 32,},
	{ .name = "options",
	  .uid = 14,
	  .bitwidth = -1,},
};

#define HEADER_IPV4 3
struct net_flow_header ipv4 = {
	.name = "ipv4",
	.uid = 3,
	.field_sz = 14,
	.fields = ipv4_fields,
};

#define HEADER_TCP_SRC_PORT 1
#define HEADER_TCP_DST_PORT 2
#define HEADER_TCP_SEQ 3
#define HEADER_TCP_ACK 4
#define HEADER_TCP_OFFSET 5
#define HEADER_TCP_RESERVED 6
#define HEADER_TCP_FLAGS 7
#define HEADER_TCP_WINDOW 8
#define HEADER_TCP_CSUM 9
#define HEADER_TCP_URGENT 10
struct net_flow_field tcp_fields[10] = {
	{ .name = "src_port",
	  .uid = 1,
	  .bitwidth = 16,
	},
	{ .name = "dst_port",
	  .uid = 2,
	  .bitwidth = 16,
	},
	{ .name = "seq",
	  .uid = 3,
	  .bitwidth = 32,
	},
	{ .name = "ack",
	  .uid = 4,
	  .bitwidth = 32,
	},
	{ .name = "offset",
	  .uid = 5,
	  .bitwidth = 4,
	},
	{ .name = "reserved",
	  .uid = 6,
	  .bitwidth = 3},
	{ .name = "flags",
	  .uid = 7,
	  .bitwidth = 9},
	{ .name = "window",
	  .uid = 8,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = 9,
	  .bitwidth = 16,},
	{ .name = "urgent",
	  .uid = 10,
	  .bitwidth = 16},
};

#define HEADER_TCP 4
struct net_flow_header tcp = {
	.name = "tcp",
	.uid = 4,
	.field_sz = 10,
	.fields = tcp_fields,
};

struct net_flow_field metadata_fields[2] = {
	{ .name = "egress_port",
	  .uid = 1,
	  .bitwidth = 32,
	},
	{ .name = "egress_queue",
	  .uid = 2,
	  .bitwidth = 32,
	}
};

struct net_flow_header metadata_t = {
	.name = "metadata_t",
	.uid = 5,
	.field_sz = 2,
	.fields = metadata_fields,
};

struct net_flow_action_arg l2_action_args[2] = {
	{
		.name = "port_id",
		.type = NET_FLOW_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action set_egress_port = {
	.name = "set_egress_port",
	.uid = 1,
	.args = l2_action_args,
};

struct net_flow_action_arg meta_action_egress_args[2] = {
	{
		.name = "queue",
		.type = NET_FLOW_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action_arg meta_action_drop_args[1] = {
	{
		.name = "",
		.type = NET_FLOW_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action set_egress_queue = {
	.name = "set_egress_queue",
	.uid = 2,
	.args = meta_action_egress_args,
};

struct net_flow_action drop_packet = {
	.name = "drop_packet",
	.uid = 3,
	.args = meta_action_drop_args,
};

struct net_flow_action nil_action = {
	.name = "",
	.uid = 0,
	.args = NULL
};

struct net_flow_field_ref fdir_matches[8] =
{
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = 3},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER, .header = HEADER_VLAN, .field = 4},
	{ .instance = HEADER_INSTANCE_IP, .header = HEADER_IPV4, .field = 12},
	{ .instance = HEADER_INSTANCE_IP, .header = HEADER_IPV4, .field = 13},
	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = 1},
	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = 2},
	{ .instance = HEADER_INSTANCE_TCP, .header = HEADER_TCP, .field = 7},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref l2_matches[2] =
{
	{ .instance = HEADER_INSTANCE_ETHERNET, .header = HEADER_ETHERNET, .field = 2, },
	{ .instance = 0, .field = 0, },
};


struct net_flow_action *ixgbe_action_list[4] =
{
	&drop_packet,
	&set_egress_queue,
	&set_egress_port,
	&nil_action,
};

net_flow_action_ref ixgbe_l2_actions[2] = {1,0};
net_flow_action_ref ixgbe_fdir_actions[3] = {2,3,0};

#define IXGBE_L2_TABLE		1
#define IXGBE_FDIR_TABLE	2

struct net_flow_table ixgbe_l2_table = {
	.name = "l2_table",
	.uid = IXGBE_L2_TABLE,
	.source = 0,
	.size = 128,
	.matches = l2_matches,
	.actions = ixgbe_l2_actions,
};

struct net_flow_table ixgbe_fdir_table = {
	.name = "fdir_table",
	.uid = IXGBE_FDIR_TABLE,
	.source = 1,
	.size = 2000,
	.matches = fdir_matches,
	.actions = ixgbe_fdir_actions,
};

struct net_flow_table ixgbe_nil_table = {.name = "", .uid = 0};

struct net_flow_table *ixgbe_table_list[3] =
{
	&ixgbe_l2_table,
	&ixgbe_fdir_table,
	&ixgbe_nil_table,
};

struct net_flow_header nill = {.name = "", .uid = 0, .field_sz=0, .fields = NULL};

struct net_flow_header *ixgbe_header_list[6] =
{
	&ethernet,
	&vlan,
	&ipv4,
	&tcp,
	&metadata_t,
	&nill,
};

/* Maybe headers could be inferred from jump table? */
net_flow_header_ref ixgbe_ethernet_headers[2] = {1, 0};
struct net_flow_jump_table ixgbe_ethernet_jump[3] =
{
	{
		.field = {
		   .header = 1,
		   .field = 3,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x8100,
		},
		.node = HEADER_INSTANCE_VLAN_OUTER,
	},
	{
		.field = {
		   .header = 1,
		   .field = 3,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x0800,
		},
		.node = HEADER_INSTANCE_IP,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_header_node ixgbe_header_node_ethernet = {
	.name = "ethernet",
	.uid = HEADER_INSTANCE_ETHERNET,
	.hdrs = ixgbe_ethernet_headers,
	.jump = ixgbe_ethernet_jump,
};

net_flow_header_ref ixgbe_vlan_headers[2] = {2, 0};
struct net_flow_jump_table ixgbe_vlan_outer_jump[3] = {
	{
		.field = {
		   .header = 2,
		   .field = 3,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x8100,
		},
		.node = HEADER_INSTANCE_VLAN_INNER,
	},
	{
		.field = {
		   .header = 2,
		   .field = 3,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x0800,
		},
		.node = HEADER_INSTANCE_IP,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_jump_table ixgbe_vlan_inner_jump[2] = {
	{
		.field = {
		   .header = 1,
		   .field = 3,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = 0x0800,
		},
		.node = 4,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_header_node ixgbe_header_node_vlan_outer = {
	.name = "vlan_outer",
	.uid = HEADER_INSTANCE_VLAN_OUTER,
	.hdrs = ixgbe_vlan_headers,
	.jump = ixgbe_vlan_outer_jump,
};

struct net_flow_header_node ixgbe_header_node_vlan_inner = {
	.name = "vlan_inner",
	.uid = HEADER_INSTANCE_VLAN_INNER,
	.hdrs = ixgbe_vlan_headers,
	.jump = ixgbe_vlan_inner_jump,
};

net_flow_header_ref ixgbe_ip_headers[2] = {3, 0};
struct net_flow_jump_table ixgbe_ip_jump[2] = {
	{
		.field = {
		   .header = 3,
		   .field = 10,
		   .type = NET_FLOW_FIELD_REF_ATTR_TYPE_U8,
		   .value_u8 = 0x06,
		},
		.node = 5,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_header_node ixgbe_header_node_ip = {
	.name = "ip",
	.uid = HEADER_INSTANCE_IP,
	.hdrs = ixgbe_ip_headers,
	.jump = ixgbe_ip_jump,	
};

net_flow_header_ref ixgbe_tcp_headers[2] = {4, 0};
struct net_flow_jump_table ixgbe_tcp_jump[2] = {
	{
		.field = {0},
		.node = NET_FLOW_JUMP_TABLE_DONE,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_header_node ixgbe_header_node_tcp = {
	.name = "tcp",
	.uid = HEADER_INSTANCE_TCP,
	.hdrs = ixgbe_tcp_headers,
	.jump = ixgbe_tcp_jump,	
};

struct net_flow_header_node ixgbe_header_nil = {.name = "", .uid = 0,};

struct net_flow_header_node *ixgbe_header_nodes[6] = {
	&ixgbe_header_node_ethernet,
	&ixgbe_header_node_vlan_outer,
	&ixgbe_header_node_vlan_inner,
	&ixgbe_header_node_ip,
	&ixgbe_header_node_tcp,
	&ixgbe_header_nil,
};

struct net_flow_jump_table ixgbe_table_node_l2_jump[2] = {
	{
		.field = {0},
		.node = 2,
	},
	{
		.field = {0},
		.node = 0,
	},
};

struct net_flow_table_graph_node ixgbe_table_node_l2 = {
	.uid = 1,
	.jump = ixgbe_table_node_l2_jump,
};

struct net_flow_jump_table ixgbe_table_node_fdir_jump[2] = {
	{
		.field = {0},
		.node = NET_FLOW_JUMP_TABLE_DONE,
	},
	{
		.field = {0},
		.node = 0,
}
};

struct net_flow_table_graph_node ixgbe_table_node_fdir = {
	.uid = 2,
	.jump = ixgbe_table_node_fdir_jump,
};

struct net_flow_table_graph_node ixgbe_table_node_nil = {
	.uid = 0,
	.jump = NULL,
};

struct net_flow_table_graph_node *ixgbe_table_graph_nodes[3] = {
	&ixgbe_table_node_l2,
	&ixgbe_table_node_fdir,
	&ixgbe_table_node_nil,
};

#endif /*_IXGBE_PIPELINE_H_*/

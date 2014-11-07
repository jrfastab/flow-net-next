/*
 * include/uapi/linux/if_flow.h - Flow table interface for Switch devices
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Author: John Fastabend <john.r.fastabend@intel.com>
 */

/* Netlink description:
 *
 * Table definition used to describe running tables. The following
 * describes the netlink message returned from a get tables request.
 * For ADD_FLOW, DELETE_FLOW, and UPDATE Flow only the following
 * attributes need to be provided, NET_FLOW_TABLE_ATTR_UID and at least
 * one complete NET_FLOW_FLOW attribute.
 *
 * 
 * [NET_FLOW_TABLE_IDENTIFIER_TYPE]
 * [NET_FLOW_TABLE_IDENTIFIER]
 * [NET_FLOW_TABLE_TABLES]
 *     [NET_FLOW_TABLE]
 *       [NET_FLOW_TABLE_ATTR_NAME]
 *       [NET_FLOW_TABLE_ATTR_UID]
 *       [NET_FLOW_TABLE_ATTR_SOURCE]
 *       [NET_FLOW_TABLE_SIZE]
 *	 [NET_FLOW_TABLE_ATTR_MATCHES]
 *	   [NET_FLOW_FIELD_REF]
 *	   [NET_FLOW_FIELD_REF]
 *	     [...]
 *	   [...]
 *	 [NET_FLOW_TABLE_ATTR_ACTIONS]
 *	   [NET_FLOW_ACTION]
 *	     [NET_FLOW_ACTION_ATTR_NAME]
 *	     [NET_FLOW_ACTION_ATTR_UID]
 *	     [NET_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	 [NET_FLOW_ACTION_ARG]
 *	         [NET_FLOW_ACTION_ARG]
 *	         [...]
 *	   [NET_FLOW_ACTION]
 *	     [...]
 *	   [...]
 *     [NET_FLOW_TABLE]
 *       [...]
 *
 * Header definitions used to define headers with user friendly
 * names.
 *
 * [NET_FLOW_TABLE_HEADERS]
 *   [NET_FLOW_HEADER]
 *   	[NET_FLOW_HEADER_ATTR_NAME]
 *   	[NET_FLOW_HEADER_ATTR_UID]
 *   	[NET_FLOW_HEADER_ATTR_FIELDS]
 *	  [NET_FLOW_HEADER_ATTR_FIELD]
 *	    [NET_FLOW_FIELD_ATTR_NAME]
 *	    [NET_FLOW_FIELD_ATTR_UID]
 *	    [NET_FLOW_FIELD_ATTR_BITWIDTH]
 *	  [NET_FLOW_HEADER_ATTR_FIELD]
 *	    [...]
 *	  [...]
 *   [NET_FLOW_HEADER]
 *      [...]
 *   [...]
 *
 * Action definitions supported by tables
 * 
 * [NET_FLOW_TABLE_ACTIONS]
 *   [NET_FLOW_TABLE_ATTR_ACTIONS]
 *	[NET_FLOW_ACTION]
 *	  [NET_FLOW_ACTION_ATTR_NAME]
 *	  [NET_FLOW_ACTION_ATTR_UID]
 *	  [NET_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	 [NET_FLOW_ACTION_ARG]
 *	         [NET_FLOW_ACTION_ARG]
 *               [...]
 *	[NET_FLOW_ACTION]
 *	     [...]
 *
 * Parser definition used to unambiguously define match headers.
 *
 * [NET_FLOW_TABLE_PARSE_GRAPH]
 *
 * Primitive Type descriptions
 *
 *
 * Graph of Table topology 
 *
 * [NET_FLOW_TABLE_TABLE_GRAPH]
 *   [TABLE_GRAPH_NODE]
 *	[TABLE_GRAPH_NODE_UID]
 *	[TABLE_GRAPH_NODE_JUMP]
 *	  [NET_FLOW_JUMP_TABLE_ENTRY]
 *	    [NET_FLOW_JUMP_TABLE_FIELD]
 *	    [NET_FLOW_JUMP_TABLE_NODE]
 *	  [NET_FLOW_JUMP_TABLE_ENTRY]
 *	    [...]
 *   [TABLE_GRAPH_NODE]
 *	[..]
 *
 * Get Flow <REQUEST> description
 *
 * [NET_FLOW_TABLE_FLOWS]
 *   [NET_FLOW_TABLE_FLOWS_TABLE]
 *   [NET_FLOW_TABLE_FLOWS_MINPRIO]
 *   [NET_FLOW_TABLE_FLOWS_MAXPRIO]
 *
 * Get Flow <REPLY> description
 *
 * [NET_FLOW_TABLE_FLOWS]
 *   [NET_FLOW_TABLE_FLOWS_TABLE]
 *   [NET_FLOW_TABLE_FLOWS_FLOWS]
 *      [NET_FLOW_FLOW]
 *           [NET_FLOW_NET_FLOW_ATTR_TABLE]
 *	     [NET_FLOW_NET_FLOW_ATTR_UID]
 *	     [NET_FLOW_NET_FLOW_ATTR_PRIORITY]
 *	     [NET_FLOW_NET_FLOW_ATTR_MATCHES]
 *	       [NET_FLOW_FIELD_REF]
 *	       [NET_FLOW_FIELD_REF]
 *	       [...]
 *	     [NET_FLOW_NET_FLOW_ATTR_ACTIONS]
 *	       [NET_FLOW_ACTION]
 *	         [NET_FLOW_ACTION_ATTR_UID]
 *	         [NET_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	   [NET_FLOW_ACTION_ARG]
 *	           [...]
 *	       [NET_FLOW_ACTION]
 *	         [..]
 *	       [...]
 *    [NET_FLOW_FLOW]
 *    	    [...]
 *      
 *
 * Add Flow descriptions
 *
 * [IFLA_NET_FLOW_FLOW]
 *     [NET_FLOW_TABLE]
 *       [NET_FLOW_TABLE_ATTR_UID]
 *	 [NET_FLOW_TABLE_ATTR_FLOWS]
 *	   [NET_FLOW_FLOW]
 *	     [NET_FLOW_NET_FLOW_ATTR_UID]
 *	     [NET_FLOW_NET_FLOW_ATTR_PRIORITY]
 *	     [NET_FLOW_NET_FLOW_ATTR_MATCHES]
 *	       [NET_FLOW_FIELD_REF]
 *	       [NET_FLOW_FIELD_REF]
 *	       [...]
 *	     [NET_FLOW_NET_FLOW_ATTR_ACTIONS]
 *	       [NET_FLOW_ACTION]
 *		 [NET_FLOW_ACTION_ATTR_NAME]
 *	         [NET_FLOW_ACTION_ATTR_UID]
 *	         [NET_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	   [NET_FLOW_ACTION_ARG]
 *	           [NET_FLOW_ACTION_ARG]
 *	             [...]
 *	       [NET_FLOW_ACTION]
 *	         [..]
 *	       [...]
 */

#ifndef _UAPI_LINUX_IF_FLOW
#define _UAPI_LINUX_IF_FLOW

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if.h>

/**
 * @struct net_flow_fields
 * @brief defines a field in a header
 */
struct net_flow_field {
	char name[IFNAMSIZ];
	int uid;
	int bitwidth;
};

enum {
	NET_FLOW_FIELD_UNSPEC,
	NET_FLOW_FIELD,
	__NET_FLOW_FIELD_MAX,
};
#define NET_FLOW_FIELD_MAX (__NET_FLOW_FIELD_MAX - 1)

enum {
	NET_FLOW_FIELD_ATTR_UNSPEC,
	NET_FLOW_FIELD_ATTR_NAME,
	NET_FLOW_FIELD_ATTR_UID,
	NET_FLOW_FIELD_ATTR_BITWIDTH,
	__NET_FLOW_FIELD_ATTR_MAX,
};
#define NET_FLOW_FIELD_ATTR_MAX (__NET_FLOW_FIELD_ATTR_MAX - 1)

/**
 * @struct net_flow_header
 * @brief defines a match (header/field) an endpoint can parse
 *
 * @uid unique identifier for header
 * @field_sz number of fields are in the set
 * @fields the set of fields in the net_flow_header
 */
struct net_flow_header {
	char name[IFNAMSIZ];
	int uid;
	int field_sz;
	struct net_flow_field *fields;
};

enum {
	NET_FLOW_HEADER_UNSPEC,
	NET_FLOW_HEADER,
	__NET_FLOW_HEADER_MAX,
};
#define NET_FLOW_HEADER_MAX (__NET_FLOW_HEADER_MAX - 1)

enum {
	NET_FLOW_HEADER_ATTR_UNSPEC,
	NET_FLOW_HEADER_ATTR_NAME,
	NET_FLOW_HEADER_ATTR_UID,
	NET_FLOW_HEADER_ATTR_FIELDS,
	__NET_FLOW_HEADER_ATTR_MAX,
};
#define NET_FLOW_HEADER_ATTR_MAX (__NET_FLOW_HEADER_ATTR_MAX - 1)

/**
 * @struct net_flow_headers
 * @brief null terminated set of net_flow_header definitions
 */
struct net_flow_headers {
	struct net_flow_header **net_flow_headers;
};

#if 0
enum {
	NET_FLOW_HEADERS_UNSPEC,
	NET_FLOW_HEADERS,
	__NET_FLOW_HEADERS_UNSPEC,
};
#endif

/**
 * @struct net_flow_field_ref
 * @brief uniquely identify field as header:field tuple
 */
struct net_flow_field_ref {
	int header;
	int field;
	int type;
	union {	/* Are these all the required data types */
		__u8 value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	};
	union {	/* Are these all the required data types */
		__u8 mask_u8;
		__u16 mask_u16;
		__u32 mask_u32;
		__u64 mask_u64;
	};
};

enum {
	NET_FLOW_FIELD_REF_UNSPEC,
	NET_FLOW_FIELD_REF,
	__NET_FLOW_FIELD_REF_MAX,
};
#define NET_FLOW_FIELD_REF_MAX (__NET_FLOW_FIELD_REF_MAX - 1)

enum {
	NET_FLOW_FIELD_REF_ATTR_TYPE_UNSPEC,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U8,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U16,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U32,
	NET_FLOW_FIELD_REF_ATTR_TYPE_U64,
	/* Need more types for ether.addrs, ip.addrs, ... */
};

enum net_flow_action_arg_type {
	NET_FLOW_ACTION_ARG_TYPE_NULL,
	NET_FLOW_ACTION_ARG_TYPE_U8,
	NET_FLOW_ACTION_ARG_TYPE_U16,
	NET_FLOW_ACTION_ARG_TYPE_U32,
	NET_FLOW_ACTION_ARG_TYPE_U64,
	__NET_FLOW_ACTION_ARG_TYPE_VAL_MAX,
};

struct net_flow_action_arg {
	char name[IFNAMSIZ];
	enum net_flow_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	};
};

enum {
	NET_FLOW_ACTION_ARG_UNSPEC,
	NET_FLOW_ACTION_ARG,
	__NET_FLOW_ACTION_ARG_MAX,
};
#define NET_FLOW_ACTION_ARG_MAX (__NET_FLOW_ACTION_ARG_MAX - 1)

typedef int net_flow_action_ref;

/**
 * @struct net_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @types NET_FLOW_ACTION_TYPE_NULL terminated list of action types
 */
struct net_flow_action {
	char name[IFNAMSIZ];
	net_flow_action_ref uid;
	struct net_flow_action_arg *args;
};

enum {
	NET_FLOW_ACTION_UNSPEC,
	NET_FLOW_ACTION,
	__NET_FLOW_ACTION_MAX,
};
#define NET_FLOW_ACTION_MAX (__NET_FLOW_ACTION_MAX - 1)

enum {
	NET_FLOW_ACTION_ATTR_UNSPEC,
	NET_FLOW_ACTION_ATTR_NAME,
	NET_FLOW_ACTION_ATTR_UID,
	NET_FLOW_ACTION_ATTR_SIGNATURE,
	__NET_FLOW_ACTION_ATTR_MAX,
};
#define NET_FLOW_ACTION_ATTR_MAX (__NET_FLOW_ACTION_ATTR_MAX - 1)

/**
 * @struct net_flow_actions
 * @brief a set of supported action types
 *
 * @net_flow_actions null terminated list of actions
 */
struct net_flow_actions {
	struct net_flow_action **actions;
};

enum {
	NET_FLOW_ACTION_SET_UNSPEC,
	NET_FLOW_ACTION_SET_ACTIONS,
	__NET_FLOW_ACTION_SET_MAX,
};
#define NET_FLOW_ACTION_SET_MAX (__NET_FLOW_ACTION_SET_MAX - 1)

/**
 * @struct net_flow_flow
 * @brief describes the match/action entry
 *
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @actoin null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct net_flow_flow {
	int table_id;
	int uid;
	int priority;
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
};

enum {
	NET_FLOW_NET_FLOW_UNSPEC,
	NET_FLOW_FLOW,
	__NET_FLOW_NET_FLOW_MAX,
};
#define NET_FLOW_NET_FLOW_MAX (__NET_FLOW_NET_FLOW_MAX - 1)

enum {
	NET_FLOW_TABLE_FLOWS_UNSPEC,
	NET_FLOW_TABLE_FLOWS_TABLE,
	NET_FLOW_TABLE_FLOWS_MINPRIO,
	NET_FLOW_TABLE_FLOWS_MAXPRIO,
	NET_FLOW_TABLE_FLOWS_FLOWS,
	__NET_FLOW_TABLE_FLOWS_MAX,
};
#define NET_FLOW_TABLE_FLOWS_MAX (__NET_FLOW_TABLE_FLOWS_MAX - 1)

enum {
	NET_FLOW_ATTR_UNSPEC,
	NET_FLOW_ATTR_TABLE,
	NET_FLOW_ATTR_UID,
	NET_FLOW_ATTR_PRIORITY,
	NET_FLOW_ATTR_MATCHES,
	NET_FLOW_ATTR_ACTIONS,
	__NET_FLOW_ATTR_MAX,
};
#define NET_FLOW_ATTR_MAX (__NET_FLOW_ATTR_MAX - 1)

/**
 * @struct net_flow_table
 * @brief define flow table with supported match/actions
 *
 * @uid unique identifier for table
 * @source uid of parent table
 * @size max number of entries for table or -1 for unbounded
 * @matches null terminated set of supported match types given by match uid
 * @actions null terminated set of supported action types given by action uid
 * @flows set of flows
 */
struct net_flow_table {
	char name[IFNAMSIZ];
	int uid;
	int source;
	int size;
	struct net_flow_field_ref *matches;
	net_flow_action_ref *actions;
	struct net_flow_flow *flows;
};

enum {
	NET_FLOW_TABLE_UNSPEC,
	NET_FLOW_TABLE,
	__NET_FLOW_TABLE_MAX,
};
#define NET_FLOW_TABLE_MAX (__NET_FLOW_TABLE_MAX - 1)

enum {
	NET_FLOW_TABLE_ATTR_UNSPEC,
	NET_FLOW_TABLE_ATTR_NAME,
	NET_FLOW_TABLE_ATTR_UID,
	NET_FLOW_TABLE_ATTR_SOURCE,
	NET_FLOW_TABLE_ATTR_SIZE,
	NET_FLOW_TABLE_ATTR_MATCHES,
	NET_FLOW_TABLE_ATTR_ACTIONS,
	NET_FLOW_TABLE_ATTR_FLOWS,
	__NET_FLOW_TABLE_ATTR_MAX,
};
#define NET_FLOW_TABLE_ATTR_MAX (__NET_FLOW_TABLE_ATTR_MAX - 1)

/**
 * @struct net_flow_tables
 * @brief a set of tables
 *
 * @table_sz number of tables at endpoint
 * @net_flow_table set of table entries
 */
struct net_flow_tables {
	int table_sz;
	struct net_flow_table *tables;
};

struct net_flow_offset {
	int offset;
	int length;
};

enum {
	NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_UNSPEC,
	NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_OFFSET,
	NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_LENGTH,
	__NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX,
};
#define NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX (__NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX - 1)

union net_flow_set_un {
	int value;
	struct net_flow_field_ref ref;
	struct net_flow_offset curr;
};

enum {
	NET_FLOW_PARSER_NODE_SET_ATTR_UNSPEC,
	NET_FLOW_PARSER_NODE_SET_ATTR_VALUE,
	NET_FLOW_PARSER_NODE_SET_ATTR_REF,
	NET_FLOW_PARSER_NODE_SET_ATTR_CURRENT,
	__NET_FLOW_PARSER_NODE_SET_ATTR_MAX,
};
#define NET_FLOW_PARSER_NODE_SET_ATTR_MAX (__NET_FLOW_PARSER_NODE_SET_ATTR_MAX - 1)

enum net_flow_set_type {
	NET_FLOW_PARSER_SET_TYPE_VALUE,
	NET_FLOW_PARSER_SET_TYPE_REF,
	NET_FLOW_PARSER_SET_TYPE_CURRENT,
};

struct net_flow_set {
	struct net_flow_field_ref ref;
	enum net_flow_set_type set_type;
	union net_flow_set_un set;
};

enum {
	NET_FLOW_PARSER_NODE_SET_UNSPEC,
	NET_FLOW_PARSER_NODE_SET_REF,
	NET_FLOW_PARSER_NODE_SET_TYPE,
	NET_FLOW_PARSER_NODE_SET_ATTR,
	__NET_FLOW_PARSER_NODE_SET_MAX,
};
#define NET_FLOW_PARSER_NODE_SET_MAX (__NET_FLOW_PARSER_NODE_SET_MAX - 1)

typedef int net_flow_header_ref;

enum {
	NET_FLOW_PARSER_NODE_HDRS_UNSPEC,
	NET_FLOW_PARSER_NODE_HDRS_REF,
	NET_FLOW_PARSER_NODE_HDRS_MAX,
};
#define NET_FLOW_PARSER_NODE_HDRS_MAX (__NET_FLOW_PARSER_NODE_HDRS_MAX - 1)

struct net_flow_jump_table {
	struct net_flow_field_ref field;
	int node; /* <0 is a parser error */
};

#define NET_FLOW_JUMP_TABLE_DONE	-1

enum {
	NET_FLOW_JUMP_TABLE_ENTRY_UNSPEC,
	NET_FLOW_JUMP_TABLE_ENTRY,
	__NET_FLOW_JUMP_TABLE_ENTRY_MAX,
};
	
enum {
	NET_FLOW_JUMP_TABLE_UNSPEC,
	NET_FLOW_JUMP_TABLE_NODE,
	NET_FLOW_JUMP_TABLE_FIELD_REF,
	__NET_FLOW_JUMP_TABLE_MAX,
};
#define NET_FLOW_JUMP_TABLE_MAX (__NET_FLOW_JUMP_TABLE_MAX - 1)

/* net_flow_parser_node
 * @flwo_header_ref : identify the hdrs that are parsed in this node
 * @net_flow_set : identify if any metadata fields are set by parser
 * @net_flow_jump_table : give a case jump statement
 */
struct net_flow_parser_node {
	int uid;
	net_flow_header_ref *hdrs;
	struct net_flow_set *sets;
	struct net_flow_jump_table *jump;
};

enum {
	NET_FLOW_PARSER_NODE_UNSPEC,
	NET_FLOW_PARSER_NODE_UID,
	NET_FLOW_PARSER_NODE_HDRS,
	NET_FLOW_PARSER_NODE_SETS,
	NET_FLOW_PARSER_NODE_JUMP,
	__NET_FLOW_PARSER_NODE_MAX,
};
#define NET_FLOW_PARSER_NODE_MAX (__NET_FLOW_PARSER_NODE_MAX - 1)

struct net_flow_parser_nodes {
	int node_count;
	struct net_flow_parser_node **nodes;
};

enum {
	NET_FLOW_PARSER_UNSPEC,
	NET_FLOW_PARSER_NODE_COUNT,
	NET_FLOW_PARSER_NODES,
	__NET_FLOW_PARSER_MAX,
};
#define NET_FLOW_PARSER_MAX (__NET_FLOW_PARSER_MAX - 1)

struct net_flow_table_graph_node {
	int uid;
	struct net_flow_jump_table *jump;
};

enum {
	NET_FLOW_TABLE_GRAPH_NODE_UNSPEC,
	NET_FLOW_TABLE_GRAPH_NODE_UID,
	NET_FLOW_TABLE_GRAPH_NODE_JUMP,
	__NET_FLOW_TABLE_GRAPH_NODE_MAX,
};
#define NET_FLOW_TABLE_GRAPH_NODE_MAX (__NET_FLOW_TABLE_GRAPH_NODE_MAX - 1)

struct net_flow_table_graph_nodes {
	int node_count;
	struct net_flow_table_graph_node **nodes;
};

enum {
	NET_FLOW_TABLE_GRAPH_UNSPEC,
	NET_FLOW_TABLE_GRAPH_NODE,
	__NET_FLOW_TABLE_GRAPH_MAX,
};
#define NET_FLOW_TABLE_GRAPH_MAX (__NET_FLOW_TABLE_GRAPH_MAX - 1)

enum {
	NET_FLOW_IDENTIFIER_IFINDEX, /* net_device ifindex */
};

enum {
	NET_FLOW_UNSPEC,
	NET_FLOW_IDENTIFIER_TYPE,
	NET_FLOW_IDENTIFIER,

	NET_FLOW_TABLES,
	NET_FLOW_HEADERS,
	NET_FLOW_ACTIONS,
	NET_FLOW_PARSE_GRAPH,
	NET_FLOW_TABLE_GRAPH,
	NET_FLOW_FLOWS,

	__NET_FLOW_MAX,
	NET_FLOW_MAX = (__NET_FLOW_MAX - 1),
};

enum {
	NET_FLOW_TABLE_CMD_GET_TABLES,
	NET_FLOW_TABLE_CMD_GET_HEADERS,
	NET_FLOW_TABLE_CMD_GET_ACTIONS,
	NET_FLOW_TABLE_CMD_GET_PARSE_GRAPH,
	NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH,

	NET_FLOW_TABLE_CMD_GET_FLOWS,
	NET_FLOW_TABLE_CMD_SET_FLOWS,
	NET_FLOW_TABLE_CMD_DEL_FLOWS,
	NET_FLOW_TABLE_CMD_UPDATE_FLOWS,

	NET_FLOW_TABLE_CMD_CREATE_TABLE,
	NET_FLOW_TABLE_CMD_DESTROY_TABLE,
	__NET_FLOW_CMD_MAX,
	NET_FLOW_CMD_MAX = (__NET_FLOW_CMD_MAX - 1),
};

#define NET_FLOW_GENL_NAME "net_flow_table"
#define NET_FLOW_GENL_VERSION 0x1
#endif /* _UAPI_LINUX_IF_FLOW */

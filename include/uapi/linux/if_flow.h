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
 * attributes need to be provided, HW_FLOW_TABLE_ATTR_UID and at least
 * one complete HW_FLOW_FLOW attribute.
 *
 * [BRIDGE_TABLES] (TBD may move to different container at top level)
 *
 *   [HW_FLOW_TABLES_SIZE]
 *   [HW_FLOW_TABLES_TABLE]
 *     [HW_FLOW_TABLE]
 *       [HW_FLOW_TABLE_ATTR_NAME]
 *       [HW_FLOW_TABLE_ATTR_UID]
 *       [HW_FLOW_TABLE_ATTR_SOURCE]
 *       [HW_FLOW_TABLE_SIZE]
 *	 [HW_FLOW_TABLE_ATTR_MATCHES]
 *	   [HW_FLOW_FIELD_REF]
 *	     [HW_FLOW_FIELD_REF_ATTR_HEADER]
 *	     [HW_FLOW_FIELD_REF_ATTR_FIELD]
 *	     [HW_FLOW_FIELD_REF_ATTR_TYPE]
 *	   [HW_FLOW_FIELD_REF]
 *	     [...]
 *	   [...]
 *	 [HW_FLOW_TABLE_ATTR_ACTIONS]
 *	   [HW_FLOW_ACTION]
 *	     [HW_FLOW_ACTION_ATTR_NAME]
 *	     [HW_FLOW_ACTION_ATTR_UID]
 *	     [HW_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	 [HW_FLOW_ACTION_ARG]
 *	         	[HW_FLOW_ACTION_ARG_NAME]
 *        	[HW_FLOW_ACTION_ARG_TYPE]
 *	         	[HW_FLOW_ACTION_ARG_VALUE]
 *	         [HW_FLOW_ACTION_ARG]
 *	           [...]
 *	   [HW_FLOW_ACTION]
 *	     [...]
 *	   [...]
 *	 [HW_FLOW_TABLE_ATTR_FLOWS]
 *	   [HW_FLOW_FLOW]
 *	     [HW_FLOW_FLOW_ATTR_UID]
 *	     [HW_FLOW_FLOW_ATTR_PRIORITY]
 *	     [HW_FLOW_FLOW_ATTR_MATCHES]
 *	       [HW_FLOW_FIELD_REF]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_HEADER]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_FIELD]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_TYPE]
 *	           [HW_FLOW_FIELD_REF_ATTR_VALUE]
 *	           [HW_FLOW_FIELD_REF_ATTR_MASK]
 *	       [HW_FLOW_FIELD_REF]
 *	         [...]
 *	       [...]
 *	     [HW_FLOW_FLOW_ATTR_ACTIONS]
 *	       [HW_FLOW_ACTION]
 *	         [HW_FLOW_ACTION_ATTR_NAME]
 *	         [HW_FLOW_ACTION_ATTR_UID]
 *	         [HW_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	   [HW_FLOW_ACTION_ARG]
 *	         	[HW_FLOW_ACTION_ARG_NAME]
 *	         	[HW_FLOW_ACTION_ARG_TYPE]
 *	         	[HW_FLOW_ACTION_ARG_VALUE]
 *	           [...]
 *	       [HW_FLOW_ACTION]
 *	         [..]
 *	       [...]
 *     [HW_FLOW_TABLE]
 *       [...]
 *
 * Header definitions used to define headers with user friendly
 * names.
 *
 * [IFLA_HW_FLOW_HEADERS]
 *   [HW_FLOW_HEADER]
 *   	[HW_FLOW_HEADER_ATTR_NAME]
 *   	[HW_FLOW_HEADER_ATTR_UID]
 *   	[HW_FLOW_HEADER_ATTR_FIELDS]
 *	  [HW_FLOW_HEADER_ATTR_FIELDS]
 *	    [HW_FLOW_FIELD_ATTR_NAME]
 *	    [HW_FLOW_FIELD_ATTR_UID]
 *	    [HW_FLOW_FIELD_ATTR_BITWIDTH]
 *	  [HW_FLOW_HEADER_ATTR_FIELDS]
 *	    [...]
 *	  [...]
 *   [HW_FLOW_HEADER]
 *      [...]
 *   [...]
 *
 * Parser definition used to unambiguously define match headers.
 * (tbd)
 *
 * Primitive Type descriptions
 * (tbd)
 *
 * Add Flow descriptions
 *
 * [IFLA_HW_FLOW_FLOW]
 *     [HW_FLOW_TABLE]
 *       [HW_FLOW_TABLE_ATTR_UID]
 *	 [HW_FLOW_TABLE_ATTR_FLOWS]
 *	   [HW_FLOW_FLOW]
 *	     [HW_FLOW_FLOW_ATTR_UID]
 *	     [HW_FLOW_FLOW_ATTR_PRIORITY]
 *	     [HW_FLOW_FLOW_ATTR_MATCHES]
 *	       [HW_FLOW_FIELD_REF]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_HEADER]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_FIELD]
 *	     	   [HW_FLOW_FIELD_REF_ATTR_TYPE]
 *	           [HW_FLOW_FIELD_REF_ATTR_VALUE]
 *	           [HW_FLOW_FIELD_REF_ATTR_MASK]
 *	       [HW_FLOW_FIELD_REF]
 *	         [...]
 *	       [...]
 *	     [HW_FLOW_FLOW_ATTR_ACTIONS]
 *	       [HW_FLOW_ACTION]
 *		 [HW_FLOW_ACTION_ATTR_NAME]
 *	         [HW_FLOW_ACTION_ATTR_UID]
 *	         [HW_FLOW_ACTION_ATTR_SIGNATURE]
 *	       	   [HW_FLOW_ACTION_ARG]
 *	         	[HW_FLOW_ACTION_ARG_NAME]
 *	         	[HW_FLOW_ACTION_ARG_TYPE]
 *	         	[HW_FLOW_ACTION_ARG_VALUE]
 *	           [HW_FLOW_ACTION_ARG]
 *	             [...]
 *	       [HW_FLOW_ACTION]
 *	         [..]
 *	       [...]
 */

#ifndef _UAPI_LINUX_IF_FLOW
#define _UAPI_LINUX_IF_FLOW

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if.h>

/**
 * @struct hw_flow_fields
 * @brief defines a field in a header
 */
struct hw_flow_field {
	char name[IFNAMSIZ];
	int uid;
	int bitwidth;
};

enum {
	HW_FLOW_FIELD_UNSPEC,
	HW_FLOW_FIELD,
	__HW_FLOW_FIELD_MAX,
};
#define HW_FLOW_FIELD_MAX (__HW_FLOW_FIELD_MAX - 1)

enum {
	HW_FLOW_FIELD_ATTR_UNSPEC,
	HW_FLOW_FIELD_ATTR_NAME,
	HW_FLOW_FIELD_ATTR_UID,
	HW_FLOW_FIELD_ATTR_BITWIDTH,
	__HW_FLOW_FIELD_ATTR_MAX,
};
#define HW_FLOW_FIELD_ATTR_MAX (__HW_FLOW_FIELD_ATTR_MAX - 1)

/**
 * @struct hw_flow_header
 * @brief defines a match (header/field) an endpoint can parse
 *
 * @uid unique identifier for header
 * @field_sz number of fields are in the set
 * @fields the set of fields in the hw_flow_header
 */
struct hw_flow_header {
	char name[IFNAMSIZ];
	int uid;
	int field_sz;
	struct hw_flow_field *fields;
};

enum {
	HW_FLOW_HEADER_UNSPEC,
	HW_FLOW_HEADER,
	__HW_FLOW_HEADER_MAX,
};
#define HW_FLOW_HEADER_MAX (__HW_FLOW_HEADER_MAX - 1)

enum {
	HW_FLOW_HEADER_ATTR_UNSPEC,
	HW_FLOW_HEADER_ATTR_NAME,
	HW_FLOW_HEADER_ATTR_UID,
	HW_FLOW_HEADER_ATTR_FIELDS,
	__HW_FLOW_HEADER_ATTR_MAX,
};
#define HW_FLOW_HEADER_ATTR_MAX (__HW_FLOW_HEADER_ATTR_MAX - 1)

/**
 * @struct hw_flow_headers
 * @brief null terminated set of hw_flow_header definitions
 */
struct hw_flow_headers {
	const struct hw_flow_header **hw_flow_headers;
};

#if 0
enum {
	HW_FLOW_HEADERS_UNSPEC,
	HW_FLOW_HEADERS,
	__HW_FLOW_HEADERS_UNSPEC,
};
#endif

/**
 * @struct hw_flow_field_ref
 * @brief uniquely identify field as header:field tuple
 */
struct hw_flow_field_ref {
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
	HW_FLOW_FIELD_REF_UNSPEC,
	HW_FLOW_FIELD_REF,
	__HW_FLOW_FIELD_REF_MAX,
};
#define HW_FLOW_FIELD_REF_MAX (__HW_FLOW_FIELD_REF_MAX - 1)

enum {
	HW_FLOW_FIELD_REF_ATTR_TYPE_UNSPEC,
	HW_FLOW_FIELD_REF_ATTR_TYPE_U8,
	HW_FLOW_FIELD_REF_ATTR_TYPE_U16,
	HW_FLOW_FIELD_REF_ATTR_TYPE_U32,
	HW_FLOW_FIELD_REF_ATTR_TYPE_U64,
	/* Need more types for ether.addrs, ip.addrs, ... */
};

enum {
	HW_FLOW_FIELD_REF_ATTR_UNSPEC,
	HW_FLOW_FIELD_REF_ATTR_HEADER,
	HW_FLOW_FIELD_REF_ATTR_FIELD,
	HW_FLOW_FIELD_REF_ATTR_TYPE,
	HW_FLOW_FIELD_REF_ATTR_VALUE,
	HW_FLOW_FIELD_REF_ATTR_MASK,
	__HW_FLOW_FIELD_REF_ATTR_MAX
};
#define HW_FLOW_FIELD_REF_ATTR_MAX (__HW_FLOW_FIELD_REF_ATTR_MAX - 1)

enum {
	HW_FLOW_ACTION_ARG_TYPE_UNSPEC,
	HW_FLOW_ACTION_ARG_NAME,
	HW_FLOW_ACTION_ARG_TYPE,
	HW_FLOW_ACTION_ARG_VALUE,
	__HW_FLOW_ACTION_ARG_TYPE_MAX
};
#define HW_FLOW_ACTION_ARG_TYPE_MAX (__HW_FLOW_ACTION_ARG_TYPE_MAX - 1)

enum hw_flow_action_arg_type {
	HW_FLOW_ACTION_ARG_TYPE_NULL,
	HW_FLOW_ACTION_ARG_TYPE_U8,
	HW_FLOW_ACTION_ARG_TYPE_U16,
	HW_FLOW_ACTION_ARG_TYPE_U32,
	HW_FLOW_ACTION_ARG_TYPE_U64,
	__HW_FLOW_ACTION_ARG_TYPE_VAL_MAX,
};

struct hw_flow_action_arg {
	char name[IFNAMSIZ];
	enum hw_flow_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	};
};

enum {
	HW_FLOW_ACTION_ARG_UNSPEC,
	HW_FLOW_ACTION_ARG,
	__HW_FLOW_ACTION_ARG_MAX,
};
#define HW_FLOW_ACTION_ARG_MAX (__HW_FLOW_ACTION_ARG_MAX - 1)

/**
 * @struct hw_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @types HW_FLOW_ACTION_TYPE_NULL terminated list of action types
 */
struct hw_flow_action {
	char name[IFNAMSIZ];
	int uid;
	struct hw_flow_action_arg *args;
};

enum {
	HW_FLOW_ACTION_UNSPEC,
	HW_FLOW_ACTION,
	__HW_FLOW_ACTION_MAX,
};
#define HW_FLOW_ACTION_MAX (__HW_FLOW_ACTION_MAX - 1)

enum {
	HW_FLOW_ACTION_ATTR_UNSPEC,
	HW_FLOW_ACTION_ATTR_NAME,
	HW_FLOW_ACTION_ATTR_UID,
	HW_FLOW_ACTION_ATTR_SIGNATURE,
	__HW_FLOW_ACTION_ATTR_MAX,
};
#define HW_FLOW_ACTION_ATTR_MAX (__HW_FLOW_ACTION_ATTR_MAX - 1)

/**
 * @struct hw_flow_actions
 * @brief a set of supported action types
 *
 * @hw_flow_actions null terminated list of actions
 */
struct hw_flow_action_set {
	int action_sz;
	struct hw_flow_action *hw_flow_actions;
};

enum {
	HW_FLOW_ACTION_SET_UNSPEC,
	HW_FLOW_ACTION_SET_ACTIONS,
	__HW_FLOW_ACTION_SET_MAX,
};
#define HW_FLOW_ACTION_SET_MAX (__HW_FLOW_ACTION_SET_MAX - 1)

/**
 * @struct hw_flow_flow
 * @brief describes the match/action entry
 *
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @actoin null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct hw_flow_flow {
	int uid;
	int priority;
	struct hw_flow_field_ref *matches;
	struct hw_flow_action *actions;
};

enum {
	HW_FLOW_FLOW_UNSPEC,
	HW_FLOW_FLOW,
	__HW_FLOW_FLOW_MAX,
};
#define HW_FLOW_FLOW_MAX (__HW_FLOW_FLOW_MAX - 1)

enum {
	HW_FLOW_FLOW_ATTR_UNSPEC,
	HW_FLOW_FLOW_ATTR_UID,
	HW_FLOW_FLOW_ATTR_PRIORITY,
	HW_FLOW_FLOW_ATTR_MATCHES,
	HW_FLOW_FLOW_ATTR_ACTIONS,
	__HW_FLOW_FLOW_ATTR_MAX,
};
#define HW_FLOW_FLOW_ATTR_MAX (__HW_FLOW_FLOW_ATTR_MAX - 1)

/**
 * @struct hw_flow_table
 * @brief define flow table with supported match/actions
 *
 * @uid unique identifier for table
 * @source uid of parent table
 * @size max number of entries for table or -1 for unbounded
 * @matches null terminated set of supported match types given by match uid
 * @actions null terminated set of supported action types given by action uid
 * @flows set of flows
 */
struct hw_flow_table {
	char name[IFNAMSIZ];
	int uid;
	int source;
	int size;
	struct hw_flow_field_ref *matches;
	struct hw_flow_action *actions;
	struct hw_flow_flow *flows;
};

enum {
	HW_FLOW_TABLE_UNSPEC,
	HW_FLOW_TABLE,
	__HW_FLOW_TABLE_MAX,
};
#define HW_FLOW_TABLE_MAX (__HW_FLOW_TABLE_MAX - 1)

enum {
	HW_FLOW_TABLE_ATTR_UNSPEC,
	HW_FLOW_TABLE_ATTR_NAME,
	HW_FLOW_TABLE_ATTR_UID,
	HW_FLOW_TABLE_ATTR_SOURCE,
	HW_FLOW_TABLE_ATTR_SIZE,
	HW_FLOW_TABLE_ATTR_MATCHES,
	HW_FLOW_TABLE_ATTR_ACTIONS,
	HW_FLOW_TABLE_ATTR_FLOWS,
	__HW_FLOW_TABLE_ATTR_MAX,
};
#define HW_FLOW_TABLE_ATTR_MAX (__HW_FLOW_TABLE_ATTR_MAX - 1)

/**
 * @struct hw_flow_tables
 * @brief a set of tables
 *
 * @table_sz number of tables at endpoint
 * @hw_flow_table set of table entries
 */
struct hw_flow_tables {
	int table_sz;
	struct hw_flow_table *tables;
};

enum {
	HW_FLOW_TABLES_UNSPEC,
	HW_FLOW_TABLES_SIZE,
	HW_FLOW_TABLES_TABLE,
	__HW_FLOW_TABLES_MAX,
};
#define HW_FLOW_TABLES_MAX (__HW_FLOW_TABLES_MAX - 1)

struct hw_flow_offset {
	int offset;
	int length;
};

enum {
	HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_UNSPEC,
	HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_OFFSET,
	HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_LENGTH,
	__HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX,
};
#define HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX (__HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT_MAX - 1)

union hw_flow_set_un {
	int value;
	struct hw_flow_field_ref ref;
	struct hw_flow_offset curr;
};

enum {
	HW_FLOW_PARSER_NODE_SET_ATTR_UNSPEC,
	HW_FLOW_PARSER_NODE_SET_ATTR_VALUE,
	HW_FLOW_PARSER_NODE_SET_ATTR_REF,
	HW_FLOW_PARSER_NODE_SET_ATTR_CURRENT,
	__HW_FLOW_PARSER_NODE_SET_ATTR_MAX,
};
#define HW_FLOW_PARSER_NODE_SET_ATTR_MAX (__HW_FLOW_PARSER_NODE_SET_ATTR_MAX - 1)

enum hw_flow_set_type {
	HW_FLOW_PARSER_SET_TYPE_VALUE,
	HW_FLOW_PARSER_SET_TYPE_REF,
	HW_FLOW_PARSER_SET_TYPE_CURRENT,
};

struct hw_flow_set {
	struct hw_flow_field_ref ref;
	enum hw_flow_set_type set_type;
	union hw_flow_set_un set;
};

enum {
	HW_FLOW_PARSER_NODE_SET_UNSPEC,
	HW_FLOW_PARSER_NODE_SET_REF,
	HW_FLOW_PARSER_NODE_SET_TYPE,
	HW_FLOW_PARSER_NODE_SET_ATTR,
	__HW_FLOW_PARSER_NODE_SET_MAX,
};
#define HW_FLOW_PARSER_NODE_SET_MAX (__HW_FLOW_PARSER_NODE_SET_MAX - 1)

typedef int hw_flow_header_ref;

enum {
	HW_FLOW_PARSER_NODE_HDRS_UNSPEC,
	HW_FLOW_PARSER_NODE_HDRS_REF,
	HW_FLOW_PARSER_NODE_HDRS_MAX,
};
#define HW_FLOW_PARSER_NODE_HDRS_MAX (__HW_FLOW_PARSER_NODE_HDRS_MAX - 1)

struct hw_flow_jump_table_switch_case {
	int node_ref;
	int error;
};

enum {
	HW_FLOW_JUMP_TABLE_SWITCH_CASES_UNSPEC,
	HW_FLOW_JUMP_TABLE_SWITCH_CASES_NODE_REF,
	HW_FLOW_JUMP_TABLE_SWITCH_CASES_ERROR,
	__HW_FLOW_JUMP_TABLE_SWITCH_CASES_MAX,
};
#define HW_FLOW_JUMP_TABLE_SWITCH_CASES_MAX (__HW_FLOW_JUMP_TABLE_SWITCH_CASES_MAX - 1)

struct hw_flow_jump_table_switch {
	struct hw_flow_field_ref ref;
	struct hw_flow_jump_table_switch_case *cases;
};

enum {
	HW_FLOW_JUMP_TABLE_SWITCH_UNSPEC,
	HW_FLOW_JUMP_TABLE_SWITCH_REF,
	HW_FLOW_JUMP_TABLE_SWITCH_CASE,
	__HW_FLOW_JUMP_TABLE_SWITCH_MAX,
};

union hw_flow_jump_table_un {
	int node_ref;
	int error;
	struct hw_flow_jump_table_switch c;
};

enum hw_flow_jump_table_type {
	HW_FLOW_JUMP_TYPE_PARSER_REF,
	HW_FLOW_JUMP_TYPE_PARSER_SWITCH,
	HW_FLOW_JUMP_TYPE_PARSER_ERROR,
};

struct hw_flow_jump_table {
	enum hw_flow_jump_table_type type;	
	union hw_flow_jump_table_un table;
};

enum {
	HW_FLOW_PARSER_NODE_JUMP_UNSPEC,
	HW_FLOW_PARSER_NODE_JUMP_TYPE,
	__HW_FLOW_PARSER_NODE_JUMP_MAX,
};
#define HW_FLOW_PARSER_NODE_JUMP_MAX (__HW_FLOW_PARSER_NODE_JUMP_MAX - 1)

struct hw_flow_parser_node {
	int uid;
	struct hw_flow_header_ref *hdrs;
	struct hw_flow_set *sets;
	struct hw_flow_jump_table jump;
};

enum {
	HW_FLOW_PARSER_NODE_UNSPEC,
	HW_FLOW_PARSER_NODE_UID,
	HW_FLOW_PARSER_NODE_HDRS,
	HW_FLOW_PARSER_NODE_SETS,
	HW_FLOW_PARSER_NODE_JUMP,
	__HW_FLOW_PARSER_NODE_MAX,
};
#define HW_FLOW_PARSER_NODE_MAX (__HW_FLOW_PARSER_NODE_MAX - 1)

struct hw_flow_parser_nodes {
	int node_count;
	struct hw_flow_parser_node *nodes;
};

enum {
	HW_FLOW_PARSER_UNSPEC,
	HW_FLOW_PARSER_NODE_COUNT,
	HW_FLOW_PARSER_NODES,
	HW_FLOW_PARSER_MAX,
};
#define HW_FLOW_PARSER_MAX (__HW_FLOW_PARSER_MAX - 1)

#endif /* _UAPI_LINUX_IF_FLOW */

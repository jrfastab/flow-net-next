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

#include <uapi/linux/if_flow.h>
#include <linux/if_bridge.h>
#include <linux/types.h>
#include <net/rtnetlink.h>

const char *flow_table_arg_type_str[__HW_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

static const
struct nla_policy hw_flow_matches_policy[HW_FLOW_FIELD_REF_MAX + 1] = {
	[HW_FLOW_FIELD_REF] = { .type = NLA_NESTED },
};

static const
struct nla_policy hw_flow_flow_policy[HW_FLOW_FLOW_ATTR_MAX + 1] = {
	[HW_FLOW_FLOW_ATTR_UID]		= { .type = NLA_U32 },
	[HW_FLOW_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32 },
	[HW_FLOW_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[HW_FLOW_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

static const
struct nla_policy hw_flow_table_policy[HW_FLOW_TABLE_ATTR_MAX + 1] = {
	[HW_FLOW_TABLE_ATTR_NAME]	= { .type = NLA_STRING,
					    .len = IFNAMSIZ-1 },
	[HW_FLOW_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[HW_FLOW_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
	[HW_FLOW_TABLE_ATTR_FLOWS]	= { .type = NLA_NESTED },
};

static
int hw_flow_field_ref_to_nl(struct sk_buff *skb, struct hw_flow_field_ref *f)
{
	if (nla_put_u32(skb, HW_FLOW_FIELD_REF_ATTR_HEADER, f->header) ||
	    nla_put_u32(skb, HW_FLOW_FIELD_REF_ATTR_FIELD, f->field)   ||
	    nla_put_u32(skb, HW_FLOW_FIELD_REF_ATTR_FIELD, f->type))
		return -EMSGSIZE;

	switch (f->type) {
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U8:
		if (nla_put_u8(skb,
			       HW_FLOW_FIELD_REF_ATTR_VALUE, f->value_u8) ||
		    nla_put_u8(skb,
			       HW_FLOW_FIELD_REF_ATTR_MASK, f->mask_u8))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		if (nla_put_u16(skb,
				HW_FLOW_FIELD_REF_ATTR_VALUE, f->value_u16) ||
		    nla_put_u16(skb,
				HW_FLOW_FIELD_REF_ATTR_MASK, f->mask_u16))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		if (nla_put_u32(skb,
				HW_FLOW_FIELD_REF_ATTR_VALUE, f->value_u32) ||
		    nla_put_u32(skb,
				HW_FLOW_FIELD_REF_ATTR_MASK, f->mask_u32))
			return -EMSGSIZE;
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		if (nla_put_u64(skb,
				HW_FLOW_FIELD_REF_ATTR_VALUE, f->value_u64) ||
		    nla_put_u64(skb,
				HW_FLOW_FIELD_REF_ATTR_MASK, f->mask_u64))
			return -EMSGSIZE;
		break;
	default:
		break;
	}

	return 0;
}

static int hw_flow_act_types_to_nl(struct sk_buff *skb,
				   struct hw_flow_action_arg *args)
{
	struct nlattr *arg;
	struct hw_flow_action_arg *i;

	for (i = &args[0]; strlen(i->name) > 0; i++) {
		arg = nla_nest_start(skb, HW_FLOW_ACTION_ARG);
		if (!arg)
			goto arg_put_failure;

		if (nla_put_string(skb, HW_FLOW_ACTION_ARG_NAME, i->name) ||
		    nla_put_u32(skb, HW_FLOW_ACTION_ARG_TYPE, i->type))
			goto errout;

		if (!i->type)
			goto next_arg;

		switch (i->type) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			if (nla_put_u8(skb,
				       HW_FLOW_ACTION_ARG_VALUE, i->value_u8))
				goto errout;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			if (nla_put_u16(skb,
					HW_FLOW_ACTION_ARG_VALUE, i->value_u16))
				goto errout;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			if (nla_put_u32(skb,
					HW_FLOW_ACTION_ARG_VALUE, i->value_u32))
				goto errout;
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			if (nla_put_u64(skb,
					HW_FLOW_ACTION_ARG_VALUE, i->value_u64))
				goto errout;
			break;
		default:
			break;
		}
next_arg:
		nla_nest_end(skb, arg);
	}

	return 0;
errout:
	nla_nest_cancel(skb, arg);
arg_put_failure:
	return -EMSGSIZE;
}

static const
struct nla_policy hw_flow_action_policy[HW_FLOW_ACTION_ATTR_MAX + 1] = {
	[HW_FLOW_ACTION_ATTR_NAME] = {.type = NLA_STRING, .len = IFNAMSIZ-1 },
	[HW_FLOW_ACTION_ATTR_UID]	      = {.type = NLA_U32 },
	[HW_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

static int hw_flow_action_to_nl(struct sk_buff *skb, struct hw_flow_action *a)
{
	struct nlattr *nest;
	int err;

	if (nla_put_string(skb, HW_FLOW_ACTION_ATTR_NAME, a->name) ||
	    nla_put_u32(skb, HW_FLOW_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	nest = nla_nest_start(skb, HW_FLOW_ACTION_ATTR_SIGNATURE);
	if (!nest)
		goto nest_put_failure;

	err = hw_flow_act_types_to_nl(skb, a->args);
	if (err) {
		nla_nest_cancel(skb, nest);
		return err;
	}
	nla_nest_end(skb, nest);

	return 0;
nest_put_failure:
	return -EMSGSIZE;
}

static const
struct nla_policy hw_flow_field_ref_policy[HW_FLOW_FIELD_REF_ATTR_MAX + 1] = {
	[HW_FLOW_FIELD_REF_ATTR_HEADER] = { .type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_FIELD] = { .type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_TYPE] = {.type = NLA_U32,},
	[HW_FLOW_FIELD_REF_ATTR_VALUE] = {.type = NLA_BINARY, },
	[HW_FLOW_FIELD_REF_ATTR_MASK] = {.type = NLA_BINARY, },
};

int hw_flow_flow_to_nl(struct sk_buff *skb, struct hw_flow_flow *flow)
{
	struct nlattr *flows, *matches, *action, *field;
	struct nlattr *actions = NULL; /* must be null to unwind */
	int j, i = 0;

	flows = nla_nest_start(skb, HW_FLOW_FLOW);
	if (!flows)
		goto flows_put_failure;

	nla_put_u32(skb, HW_FLOW_FLOW_ATTR_UID, flow->uid);
	nla_put_u32(skb, HW_FLOW_FLOW_ATTR_PRIORITY, flow->priority);

	if (flow->matches)
		i = sizeof(struct hw_flow_field_ref) / sizeof(*flow->matches);

	matches = nla_nest_start(skb, HW_FLOW_FLOW_ATTR_MATCHES);
	if (!matches)
		goto matches_put_failure;
	for (j = 0; j < i; j++) {
		struct hw_flow_field_ref *f = &flow->matches[j];

		field = nla_nest_start(skb, HW_FLOW_FIELD_REF);
		if (!field)
			goto field_put_failure;

		hw_flow_field_ref_to_nl(skb, f);
		nla_nest_end(skb, field);
	}
	nla_nest_end(skb, matches);

	if (flow->actions)
		i = sizeof(struct hw_flow_action) / sizeof(*flow->actions);

	actions = nla_nest_start(skb, HW_FLOW_FLOW_ATTR_ACTIONS);
	if (!actions)
		goto field_put_failure;

	for (j = 0; j < i; j++) {
		struct hw_flow_action *a = &flow->actions[j];

		action = nla_nest_start(skb, HW_FLOW_ACTION);
		if (!action)
			goto matches_put_failure;

		hw_flow_action_to_nl(skb, a);
		nla_nest_end(skb, action);
	}
	nla_nest_end(skb, actions);
	nla_nest_end(skb, flows);
	return 0;

field_put_failure:
	nla_nest_cancel(skb, matches);
matches_put_failure:
	nla_nest_cancel(skb, actions);
	nla_nest_cancel(skb, flows);
flows_put_failure:
	return -EMSGSIZE;
}
EXPORT_SYMBOL(hw_flow_flow_to_nl);

static int hw_flow_table_to_nl(struct net_device *dev,
			       struct sk_buff *skb,
			       struct hw_flow_table *t)
{
	struct nlattr *matches, *actions, *flow;
	struct hw_flow_field_ref *m;
	struct hw_flow_action *a;
	int err;

	flow = NULL; /* must null to get unwind correct */

	if (nla_put_string(skb, HW_FLOW_TABLE_ATTR_NAME, t->name) ||
	    nla_put_u32(skb, HW_FLOW_TABLE_ATTR_UID, t->uid) ||
	    nla_put_u32(skb, HW_FLOW_TABLE_ATTR_SOURCE, t->source) ||
	    nla_put_u32(skb, HW_FLOW_TABLE_ATTR_SIZE, t->size))
		return -EMSGSIZE;

	matches = nla_nest_start(skb, HW_FLOW_TABLE_ATTR_MATCHES);
	if (!matches)
		goto matches_put_failure;

	for (m = t->matches; m->header || m->field; m++) {
		struct nlattr *match = nla_nest_start(skb, HW_FLOW_FIELD_REF);

		if (!match) {
			err = -EMSGSIZE;
			goto match_put_failure;
		}

		err = hw_flow_field_ref_to_nl(skb, m);
		if (err)
			goto match_put_failure;
		nla_nest_end(skb, match);
	}
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, HW_FLOW_TABLE_ATTR_ACTIONS);
	if (!actions)
		goto actions_put_failure;

	for (a = t->actions; strlen(a->name) > 0; a++) {
		struct nlattr *action = nla_nest_start(skb, HW_FLOW_ACTION);

		if (!action)
			goto action_put_failure;

		err = hw_flow_action_to_nl(skb, a);

		if (err)
			goto action_put_failure;
		nla_nest_end(skb, action);
	}
	nla_nest_end(skb, actions);

	flow = nla_nest_start(skb, HW_FLOW_TABLE_ATTR_FLOWS);
	if (!flow)
		goto flow_put_failure;

	if (dev->netdev_ops->ndo_bridge_getflows)
		dev->netdev_ops->ndo_bridge_getflows(dev, t->uid, skb);
	nla_nest_end(skb, flow);
	return 0;
matches_put_failure:
actions_put_failure:
flow_put_failure:
	return -EMSGSIZE;
action_put_failure:
	nla_nest_cancel(skb, actions);
	return -EMSGSIZE;
match_put_failure:
	nla_nest_cancel(skb, matches);
	return err;
}

static const struct nla_policy hw_flow_tables_policy[HW_FLOW_TABLES_MAX + 1] = {
	[HW_FLOW_TABLES_SIZE]	= { .type = NLA_U32 },
	[HW_FLOW_TABLES_TABLE]	= { .type = NLA_NESTED },
};

int hw_flow_tables_to_nl(struct net_device *dev,
			 struct sk_buff *skb,
			 const struct hw_flow_tables *tables)
{
	struct nlattr *nest, *t, *bridge;
	int i, err = 0;

	bridge = nla_nest_start(skb, IFLA_BRIDGE_TABLES);
	if (nla_put_u32(skb, HW_FLOW_TABLES_SIZE, tables->table_sz))
		return -EMSGSIZE;

	nest = nla_nest_start(skb, HW_FLOW_TABLES_TABLE);
	for (i = 0; i < tables->table_sz; i++) {
		t = nla_nest_start(skb, HW_FLOW_TABLE);
		err = hw_flow_table_to_nl(dev, skb, &tables->tables[i]);
		if (err)
			goto errout;
		nla_nest_end(skb, t);
	}
	nla_nest_end(skb, nest);
	nla_nest_end(skb, bridge);
	return 0;
errout:
	nla_nest_cancel(skb, nest);
	nla_nest_cancel(skb, bridge);
	return err;
}
EXPORT_SYMBOL(hw_flow_tables_to_nl);

int hw_flow_fields_to_nl(struct sk_buff *skb, const struct hw_flow_header *h)
{
	struct hw_flow_field *f;
	int count = h->field_sz;
	struct nlattr *field;

	for (f = h->fields; count; count--, f++) {
		field = nla_nest_start(skb, HW_FLOW_FIELD);
		if (!field)
			goto field_put_failure;

		if (nla_put_string(skb, HW_FLOW_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(skb, HW_FLOW_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(skb, HW_FLOW_FIELD_ATTR_BITWIDTH, f->bitwidth))
			goto out;

		nla_nest_end(skb, field);
	}

	return 0;
out:
	nla_nest_cancel(skb, field);
field_put_failure:
	return -EMSGSIZE;
}

int hw_flow_headers_to_nl(struct sk_buff *skb,
			const struct hw_flow_headers *headers)
{
	const struct hw_flow_header **h;
	const struct hw_flow_header *this;
	struct nlattr *hdrs, *hdr, *fields;

	hdrs = nla_nest_start(skb, IFLA_HW_FLOW_HEADERS);
	if (!hdrs)
		goto hdrs_put_failure;

	for (h = headers->hw_flow_headers, this = *h;
	     strlen(this->name) > 0; h++, this = *h) {
		hdr = nla_nest_start(skb, HW_FLOW_HEADER);
		if (!hdr)
			goto hdr_put_failure;

		if (nla_put_string(skb, HW_FLOW_HEADER_ATTR_NAME, this->name) ||
		    nla_put_u32(skb, HW_FLOW_HEADER_ATTR_UID, this->uid))
			goto attr_put_failure;

		fields = nla_nest_start(skb, HW_FLOW_HEADER_ATTR_FIELDS);
		if (!fields)
			goto fields_put_failure;
		hw_flow_fields_to_nl(skb, this);
		nla_nest_end(skb, fields);

		nla_nest_end(skb, hdr);
	}

	nla_nest_end(skb, hdrs);
	return 0;
fields_put_failure:
attr_put_failure:
	nla_nest_cancel(skb, hdr);
hdr_put_failure:
	nla_nest_cancel(skb, hdrs);
hdrs_put_failure:
	return -EMSGSIZE;
}
EXPORT_SYMBOL(hw_flow_headers_to_nl);

static int nl_to_sw_field_ref(struct hw_flow_field_ref *field,
			      struct nlattr *attr)
{
	struct nlattr *ref[HW_FLOW_FIELD_REF_ATTR_MAX+1];
	int err;

	if (nla_type(attr) != HW_FLOW_FIELD_REF) {
		pr_warn("%s: error unexpected field\n", __func__);
		return 0;
	}

	err = nla_parse_nested(ref, HW_FLOW_FIELD_REF_ATTR_MAX,
			       attr, hw_flow_field_ref_policy);

	field->header = nla_get_u32(ref[HW_FLOW_FIELD_REF_ATTR_HEADER]);
	field->field = nla_get_u32(ref[HW_FLOW_FIELD_REF_ATTR_FIELD]);
	field->type = nla_get_u32(ref[HW_FLOW_FIELD_REF_ATTR_TYPE]);

	switch (field->type) {
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U8:
		field->value_u8 = nla_get_u8(ref[HW_FLOW_FIELD_REF_ATTR_VALUE]);
		field->mask_u8 = nla_get_u8(ref[HW_FLOW_FIELD_REF_ATTR_MASK]);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U16:
		field->value_u16 = nla_get_u16(ref[HW_FLOW_FIELD_REF_ATTR_VALUE]);
		field->mask_u16 = nla_get_u16(ref[HW_FLOW_FIELD_REF_ATTR_MASK]);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U32:
		field->value_u32 = nla_get_u32(ref[HW_FLOW_FIELD_REF_ATTR_VALUE]);
		field->mask_u32 = nla_get_u32(ref[HW_FLOW_FIELD_REF_ATTR_MASK]);
		break;
	case HW_FLOW_FIELD_REF_ATTR_TYPE_U64:
		field->value_u64 = nla_get_u64(ref[HW_FLOW_FIELD_REF_ATTR_VALUE]);
		field->mask_u64 = nla_get_u64(ref[HW_FLOW_FIELD_REF_ATTR_MASK]);
		break;
	default:
		return 0;
	}

	return 0;
}

static const
struct nla_policy hw_flow_action_arg_policy[HW_FLOW_ACTION_ATTR_MAX + 1] = {
	[HW_FLOW_ACTION_ARG_NAME] = {.type = NLA_STRING, .len = IFNAMSIZ-1 },
	[HW_FLOW_ACTION_ARG_TYPE] = {.type = NLA_U32 },
	[HW_FLOW_ACTION_ARG_VALUE] = {.type = NLA_BINARY, },

};

static int nl_to_sw_action(struct hw_flow_action *a, struct nlattr *attr)
{
	struct nlattr *act[HW_FLOW_ACTION_ATTR_MAX+1];
	struct nlattr *args, *arg[HW_FLOW_ACTION_ARG_TYPE_MAX+1];
	int rem;
	int err, count = 0;

	if (nla_type(attr) != HW_FLOW_ACTION) {
		pr_warn("%s: expected HW_FLOW_ACTION\n", __func__);
		return 0;
	}

	err = nla_parse_nested(act, HW_FLOW_ACTION_ATTR_MAX,
			       attr, hw_flow_action_policy);

	a->uid = nla_get_u32(act[HW_FLOW_ACTION_ATTR_UID]);

	nla_for_each_nested(args, act[HW_FLOW_ACTION_ATTR_SIGNATURE], rem)
		count++; /* unoptimized max possible */

	a->args = kcalloc(count, sizeof(struct hw_flow_action_arg), GFP_KERNEL);
	count = 0;

	nla_for_each_nested(args, act[HW_FLOW_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(args) != HW_FLOW_ACTION_ARG) {
			pr_warn("%s: expected HW_FLOW_ACTION_ATTR_ARG_TYPE\n",
				__func__);
			continue;
		}

		nla_parse_nested(arg, HW_FLOW_ACTION_ARG_TYPE_MAX,
				 args, hw_flow_action_arg_policy);

		if (!arg[HW_FLOW_ACTION_ARG_TYPE] ||
		    !arg[HW_FLOW_ACTION_ARG_VALUE]) {
			pr_warn("%s: expected action type/value\n", __func__);
			continue;
		}

		a->args[count].type = nla_get_u32(arg[HW_FLOW_ACTION_ARG_TYPE]);

		switch (a->args[count].type) {
		case HW_FLOW_ACTION_ARG_TYPE_U8:
			a->args[count].value_u8 =
				nla_get_u8(arg[HW_FLOW_ACTION_ARG_VALUE]);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U16:
			a->args[count].value_u16 =
				nla_get_u16(arg[HW_FLOW_ACTION_ARG_VALUE]);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U32:
			a->args[count].value_u32 =
				nla_get_u32(arg[HW_FLOW_ACTION_ARG_VALUE]);
			break;
		case HW_FLOW_ACTION_ARG_TYPE_U64:
			a->args[count].value_u64 =
				nla_get_u64(arg[HW_FLOW_ACTION_ARG_VALUE]);
			break;
		default:
			break;
		}
		count++;
	}
	return 0;
}

static int nl_to_sw_flow(struct hw_flow_flow *flow, struct nlattr *attr)
{
	struct nlattr *f[HW_FLOW_FLOW_ATTR_MAX+1];
	struct nlattr *attr2;
	int rem, err, uid, priority;
	int count = 0;

	if (nla_type(attr) != HW_FLOW_FLOW) {
		pr_warn("%s: unknown field in table/flows\n", __func__);
		return 0;
	}

	err = nla_parse_nested(f, HW_FLOW_FLOW_ATTR_MAX, attr, hw_flow_flow_policy);
	if (err < 0)
		return 0;

	uid = nla_get_u32(f[HW_FLOW_FLOW_ATTR_UID]);
	priority = nla_get_u32(f[HW_FLOW_FLOW_ATTR_PRIORITY]);

	nla_for_each_nested(attr2, f[HW_FLOW_FLOW_ATTR_MATCHES], rem)
		count++;

	flow->matches = kcalloc(count,
				sizeof(struct hw_flow_field_ref), GFP_KERNEL);
	count = 0;

	nla_for_each_nested(attr2, f[HW_FLOW_FLOW_ATTR_MATCHES], rem) {
		nl_to_sw_field_ref(&flow->matches[count], attr2);
		count++;
	}

	count = 0;
	nla_for_each_nested(attr2, f[HW_FLOW_FLOW_ATTR_ACTIONS], rem)
		count++;
	flow->actions = kcalloc(count, sizeof(struct hw_flow_action), GFP_KERNEL);
	count = 0;

	nla_for_each_nested(attr2, f[HW_FLOW_FLOW_ATTR_ACTIONS], rem) {
		nl_to_sw_action(&flow->actions[count], attr2);
		count++;
	}

	return 0;
}

int nl_to_sw_tables(struct hw_flow_tables *hw_flow, struct nlattr *t)
{
	struct nlattr *attr0, *attr1;
	struct nlattr *tables[HW_FLOW_TABLES_MAX+1];
	struct nlattr *table[HW_FLOW_TABLE_ATTR_MAX+1];
	struct hw_flow_table *hw_table;
	int err, i, j;
	int rem0, rem1;

	err = nla_parse_nested(tables, HW_FLOW_TABLES_MAX, t, hw_flow_tables_policy);
	if (err < 0)
		return -EINVAL;

	i = nla_get_u32(tables[HW_FLOW_TABLES_SIZE]);

	hw_flow->tables = kcalloc(i, sizeof(struct hw_flow_table), GFP_KERNEL);
	if (!hw_flow->tables)
		return -ENOMEM;
	hw_flow->table_sz = i;

	hw_table = hw_flow->tables;

	i = 0;
	nla_for_each_nested(attr0, tables[HW_FLOW_TABLES_TABLE], rem0) {
		nla_parse_nested(table, HW_FLOW_TABLE_ATTR_MAX, attr0, hw_flow_table_policy);

		if (!hw_table) {
			pr_warn("%s: no hw_table\n", __func__);
			continue;
		}

		if (table[HW_FLOW_TABLE_ATTR_NAME])
			nla_strlcpy(hw_table[i].name, table[HW_FLOW_TABLE_ATTR_NAME], IFNAMSIZ);

		hw_table[i].uid = nla_get_u32(table[HW_FLOW_TABLE_ATTR_UID]);

#if 0
		printk("%s: hw_table %i: name %s uid %i\n",
			__func__, i, hw_table[i].name, hw_table[i].uid);
#endif

		j = 0;
		nla_for_each_nested(attr1, table[HW_FLOW_TABLE_ATTR_FLOWS], rem1)
			j++;

		hw_table[i].flows = kcalloc(j, sizeof(struct hw_flow_table),
					    GFP_KERNEL);
		j = 0;
		nla_for_each_nested(attr1,
				    table[HW_FLOW_TABLE_ATTR_FLOWS], rem1) {
			nl_to_sw_flow(&hw_table[i].flows[j], attr1);
			j++;
		}
		i++;
		hw_table++;
	}

	return 0;
}
EXPORT_SYMBOL(nl_to_sw_tables);

static void kfree_hw_flow_actions(struct hw_flow_action *actions)
{
	int j = 0;

	if (!actions)
		return;

	while (strlen(actions[j].name) > 0) {
		int k = 0;

		kfree(actions[j].name);
		while (actions[j].args[k].name) {
			kfree(actions[j].args[k].name);
			k++;
		}
		kfree(actions[j].args);
		j++;
	}
	kfree(actions);
}

static void kfree_hw_flow_flows(struct hw_flow_flow *f)
{
	if (!f)
		return;

	/* TBD leaking memory */

	kfree(f);
}

static void kfree_hw_flow_tables(struct hw_flow_tables *t)
{
	int i;

	if (!t)
		return;

	for (i = 0; i < t->table_sz; i++) {
		kfree(t->tables[i].name);
		kfree(t->tables[i].matches);

		kfree_hw_flow_actions(t->tables[i].actions);
		kfree_hw_flow_flows(t->tables[i].flows);
	}
}

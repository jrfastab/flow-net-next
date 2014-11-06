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
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <linux/module.h>

static struct genl_family net_flow_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= NET_FLOW_GENL_NAME,
	.version	= NET_FLOW_GENL_VERSION,
	.maxattr	= NET_FLOW_MAX,
	.netnsok	= true,
};

const char *net_flow_table_arg_type_str[__NET_FLOW_ACTION_ARG_TYPE_VAL_MAX] = {
	"null",
	"u8",
	"u16",
	"u32",
	"u64",
};

static const
struct nla_policy net_flow_matches_policy[NET_FLOW_FIELD_REF_MAX + 1] = {
	[NET_FLOW_FIELD_REF] = { .len = sizeof(struct net_flow_field_ref) },
};

static const
struct nla_policy net_flow_flow_policy[NET_FLOW_NET_FLOW_ATTR_MAX + 1] = {
	[NET_FLOW_NET_FLOW_ATTR_TABLE]	= { .type = NLA_U32 },
	[NET_FLOW_NET_FLOW_ATTR_UID]		= { .type = NLA_U32 },
	[NET_FLOW_NET_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32 },
	[NET_FLOW_NET_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_FLOW_NET_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

static const
struct nla_policy net_flow_table_policy[NET_FLOW_TABLE_ATTR_MAX + 1] = {
	[NET_FLOW_TABLE_ATTR_NAME]	= { .type = NLA_STRING,
					    .len = IFNAMSIZ-1 },
	[NET_FLOW_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[NET_FLOW_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_ATTR_FLOWS]	= { .type = NLA_NESTED },
};

static int net_flow_act_types_to_nl(struct sk_buff *skb,
				   struct net_flow_action_arg *args, int argcnt)
{
	struct nlattr *arg;
	int i;

	for (i = 0; i < argcnt; i++) {
		struct net_flow_action_arg *this = &args[i];

		arg = nla_nest_start(skb, NET_FLOW_ACTION_ARG);
		if (!arg)
			goto arg_put_failure;

		if (this->type == NET_FLOW_ACTION_ARG_TYPE_NULL)
			goto next_arg;

		if (this->name &&
		    nla_put_string(skb, NET_FLOW_ACTION_ARG_NAME, this->name))
			goto errout;

		if (nla_put_u32(skb, NET_FLOW_ACTION_ARG_TYPE, this->type))
			goto errout;

		switch (this->type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			if (nla_put_u8(skb,
				       NET_FLOW_ACTION_ARG_VALUE, this->value_u8))
				goto errout;
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			if (nla_put_u16(skb,
					NET_FLOW_ACTION_ARG_VALUE, this->value_u16))
				goto errout;
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			if (nla_put_u32(skb,
					NET_FLOW_ACTION_ARG_VALUE, this->value_u32))
				goto errout;
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			if (nla_put_u64(skb,
					NET_FLOW_ACTION_ARG_VALUE, this->value_u64))
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
struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME] = {.type = NLA_STRING, .len = IFNAMSIZ-1 },
	[NET_FLOW_ACTION_ATTR_UID]	      = {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

static int net_flow_action_to_nl(struct sk_buff *skb, struct net_flow_action *a)
{
	struct net_flow_action_arg *this;
	struct nlattr *nest;
	int err, args = 0;

	if (nla_put_string(skb, NET_FLOW_ACTION_ATTR_NAME, a->name) ||
	    nla_put_u32(skb, NET_FLOW_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	for (this = &a->args[0]; strlen(this->name) > 0; this++)
		args++;

	if (args) {
		nest = nla_nest_start(skb, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!nest)
			goto nest_put_failure;

		err = net_flow_act_types_to_nl(skb, a->args, args);
		if (err) {
			nla_nest_cancel(skb, nest);
			return err;
		}
		nla_nest_end(skb, nest);
	}

	return 0;
nest_put_failure:
	return -EMSGSIZE;
}

static int net_flow_actions_to_nl(struct sk_buff *skb, struct net_flow_actions *acts)
{
	struct net_flow_action **a;
	struct net_flow_action *this;
	struct nlattr *actions;
	int err;

	actions = nla_nest_start(skb, NET_FLOW_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (a = acts->actions, this = *a;
	     strlen(this->name) > 0; a++, this = *a) {
		struct nlattr *action = nla_nest_start(skb, NET_FLOW_ACTION);

		if (!action)
			goto action_put_failure;

		err = net_flow_action_to_nl(skb, this);
		if (err)
			goto action_put_failure;
		nla_nest_end(skb, action);
	}
	nla_nest_end(skb, actions);

	return 0;
action_put_failure:
	nla_nest_cancel(skb, actions);
	return -EMSGSIZE;
}

int net_flow_flow_action_to_nl(struct sk_buff *skb, struct net_flow_action *a, int args )
{
	struct nlattr *action = nla_nest_start(skb, NET_FLOW_ACTION);
	struct nlattr *nest;
	int err = 0;

	if (!action)
		return -EMSGSIZE;

	if (nla_put_u32(skb, NET_FLOW_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	if (args > 0) {
		nest = nla_nest_start(skb, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!nest)
			goto nest_put_failure;

		err = net_flow_act_types_to_nl(skb, a->args, args);
		if (err) {
			nla_nest_cancel(skb, action);
			nla_nest_cancel(skb, nest);
			return err;
		}
		nla_nest_end(skb, nest);
	}

	nla_nest_end(skb, action);
	return 0;
nest_put_failure:
	nla_nest_cancel(skb, action);
	return -EMSGSIZE;
}

int net_flow_flow_to_nl(struct sk_buff *skb, struct net_flow_flow *flow, int mcnt, int acnt, int args)
{
	struct nlattr *flows, *matches;
	struct nlattr *actions = NULL; /* must be null to unwind */
	int err, j, i = 0;

	flows = nla_nest_start(skb, NET_FLOW_FLOW);
	if (!flows)
		goto put_failure;

	if (nla_put_u32(skb, NET_FLOW_NET_FLOW_ATTR_TABLE, flow->table_id) ||
	    nla_put_u32(skb, NET_FLOW_NET_FLOW_ATTR_UID, flow->uid) ||
	    nla_put_u32(skb, NET_FLOW_NET_FLOW_ATTR_PRIORITY, flow->priority))
		goto flows_put_failure;

	matches = nla_nest_start(skb, NET_FLOW_NET_FLOW_ATTR_MATCHES);
	if (!matches)
		goto flows_put_failure;
	for (j = 0; j < mcnt; j++) {
		struct net_flow_field_ref *f = &flow->matches[j];

		if (!f->header)
			continue;

		nla_put(skb, NET_FLOW_FIELD_REF, sizeof(*f), f);
	}
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, NET_FLOW_NET_FLOW_ATTR_ACTIONS);
	if (!actions)
		goto flows_put_failure;

	for (i = 0; i < acnt; i++) {
		err = net_flow_flow_action_to_nl(skb, &flow->actions[i], args);
		if (err) {
			nla_nest_cancel(skb, actions);
			goto flows_put_failure;
		}
	}

	nla_nest_end(skb, actions);
	nla_nest_end(skb, flows);
	return 0;

flows_put_failure:
	nla_nest_cancel(skb, flows);
put_failure:
	return -EMSGSIZE;
}
EXPORT_SYMBOL(net_flow_flow_to_nl);

static int net_flow_table_to_nl(struct net_device *dev,
			       struct sk_buff *skb,
			       struct net_flow_table *t)
{
	struct nlattr *matches, *flow, *actions;
	struct net_flow_field_ref *m;
	net_flow_action_ref *ref;

	flow = NULL; /* must null to get unwind correct */

	if (nla_put_string(skb, NET_FLOW_TABLE_ATTR_NAME, t->name) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_UID, t->uid) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_SOURCE, t->source) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_SIZE, t->size))
		return -EMSGSIZE;

	matches = nla_nest_start(skb, NET_FLOW_TABLE_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (m = t->matches; m->header || m->field; m++)
		nla_put(skb, NET_FLOW_FIELD_REF, sizeof(*m), m);
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, NET_FLOW_TABLE_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (ref = t->actions; *ref; ref++) {
		if (nla_put_u32(skb, NET_FLOW_ACTION_ATTR_UID, *ref)) {
			nla_nest_cancel(skb, actions);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, actions);

	flow = nla_nest_start(skb, NET_FLOW_TABLE_ATTR_FLOWS);
	if (!flow)
		return -EMSGSIZE;

	if (dev->netdev_ops->ndo_bridge_getflows)
		dev->netdev_ops->ndo_bridge_getflows(dev, t->uid, skb);
	nla_nest_end(skb, flow);
	return 0;
}

int net_flow_tables_to_nl(struct net_device *dev,
			 struct sk_buff *skb,
			 const struct net_flow_tables *tables)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(skb, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; i < tables->table_sz; i++) {
		t = nla_nest_start(skb, NET_FLOW_TABLE);
		err = net_flow_table_to_nl(dev, skb, &tables->tables[i]);
		if (err)
			goto errout;
		nla_nest_end(skb, t);
	}
	nla_nest_end(skb, nest);
	return 0;
errout:
	nla_nest_cancel(skb, nest);
	return err;
}
EXPORT_SYMBOL(net_flow_tables_to_nl);

struct sk_buff *net_flow_table_build_tables_msg(struct net_flow_tables *t,
					    struct net_device *dev,
					    u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_tables_to_nl(dev, skb, t);
	if (err < 0)
		goto out;
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

int net_flow_fields_to_nl(struct sk_buff *skb, const struct net_flow_header *h)
{
	struct net_flow_field *f;
	int count = h->field_sz;
	struct nlattr *field;

	for (f = h->fields; count; count--, f++) {
		field = nla_nest_start(skb, NET_FLOW_FIELD);
		if (!field)
			goto field_put_failure;

		if (nla_put_string(skb, NET_FLOW_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(skb, NET_FLOW_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(skb, NET_FLOW_FIELD_ATTR_BITWIDTH, f->bitwidth))
			goto out;

		nla_nest_end(skb, field);
	}

	return 0;
out:
	nla_nest_cancel(skb, field);
field_put_failure:
	return -EMSGSIZE;
}

int net_flow_headers_to_nl(struct sk_buff *skb,
			  const struct net_flow_headers *headers)
{
	struct net_flow_header **h;
	struct net_flow_header *this;
	struct nlattr *nest, *hdr, *fields;

	nest = nla_nest_start(skb, NET_FLOW_HEADERS);
	if (!nest)
		goto hdr_put_failure;
		
	for (h = headers->net_flow_headers, this = *h;
	     strlen(this->name) > 0; h++, this = *h) {
		hdr = nla_nest_start(skb, NET_FLOW_HEADER);
		if (!hdr)
			goto hdr_put_failure;

		if (nla_put_string(skb, NET_FLOW_HEADER_ATTR_NAME, this->name) ||
		    nla_put_u32(skb, NET_FLOW_HEADER_ATTR_UID, this->uid))
			goto attr_put_failure;

		fields = nla_nest_start(skb, NET_FLOW_HEADER_ATTR_FIELDS);
		if (!fields)
			goto fields_put_failure;
		net_flow_fields_to_nl(skb, this);
		nla_nest_end(skb, fields);

		nla_nest_end(skb, hdr);
	}
	nla_nest_end(skb, nest);

	return 0;
fields_put_failure:
attr_put_failure:
	nla_nest_cancel(skb, hdr);
hdr_put_failure:
	return -EMSGSIZE;
}

struct sk_buff *net_flow_table_build_headers_msg(struct net_flow_headers *h,
					     struct net_device *dev,
					     u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_headers_to_nl(skb, h);
	if (err < 0)
		goto out;
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int nl_to_sw_field_ref(struct net_flow_field_ref *field,
			      struct nlattr *nla)
{
	if (nla_type(nla) != NET_FLOW_FIELD_REF) {
		pr_warn("%s: error unexpected field\n", __func__);
		return -EINVAL;
	}

	*field = *(struct net_flow_field_ref *) nla_data(nla);
	return 0;
}

static const
struct nla_policy net_flow_action_arg_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ARG_NAME] = {.type = NLA_STRING, .len = IFNAMSIZ-1 },
	[NET_FLOW_ACTION_ARG_TYPE] = {.type = NLA_U32 },
	[NET_FLOW_ACTION_ARG_VALUE] = {.type = NLA_BINARY, },
};

static int nl_to_sw_action(struct net_flow_action *a, struct nlattr *attr)
{
	struct nlattr *act[NET_FLOW_ACTION_ATTR_MAX+1];
	struct nlattr *args, *arg[NET_FLOW_ACTION_ARG_TYPE_MAX+1];
	int rem;
	int err, count = 0;

	if (nla_type(attr) != NET_FLOW_ACTION) {
		pr_warn("%s: expected NET_FLOW_ACTION\n", __func__);
		return 0;
	}

	err = nla_parse_nested(act, NET_FLOW_ACTION_ATTR_MAX,
			       attr, net_flow_action_policy);

	a->uid = nla_get_u32(act[NET_FLOW_ACTION_ATTR_UID]);

	nla_for_each_nested(args, act[NET_FLOW_ACTION_ATTR_SIGNATURE], rem)
		count++; /* unoptimized max possible */

	a->args = kcalloc(count + 1, sizeof(struct net_flow_action_arg), GFP_KERNEL);
	count = 0;

	nla_for_each_nested(args, act[NET_FLOW_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(args) != NET_FLOW_ACTION_ARG) {
			pr_warn("%s: expected NET_FLOW_ACTION_ATTR_ARG_TYPE\n",
				__func__);
			continue;
		}

		nla_parse_nested(arg, NET_FLOW_ACTION_ARG_TYPE_MAX,
				 args, net_flow_action_arg_policy);

		if (!arg[NET_FLOW_ACTION_ARG_TYPE] ||
		    !arg[NET_FLOW_ACTION_ARG_VALUE]) {
			pr_warn("%s: expected action type/value\n", __func__);
			continue;
		}

		a->args[count].type = nla_get_u32(arg[NET_FLOW_ACTION_ARG_TYPE]);

		switch (a->args[count].type) {
		case NET_FLOW_ACTION_ARG_TYPE_U8:
			a->args[count].value_u8 =
				nla_get_u8(arg[NET_FLOW_ACTION_ARG_VALUE]);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U16:
			a->args[count].value_u16 =
				nla_get_u16(arg[NET_FLOW_ACTION_ARG_VALUE]);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U32:
			a->args[count].value_u32 =
				nla_get_u32(arg[NET_FLOW_ACTION_ARG_VALUE]);
			break;
		case NET_FLOW_ACTION_ARG_TYPE_U64:
			a->args[count].value_u64 =
				nla_get_u64(arg[NET_FLOW_ACTION_ARG_VALUE]);
			break;
		default:
			break;
		}
		count++;
	}
	return 0;
}

static int nl_to_sw_flow(struct net_flow_flow *flow, struct nlattr *attr)
{
	struct nlattr *f[NET_FLOW_NET_FLOW_ATTR_MAX+1];
	struct nlattr *attr2;
	int rem, err;
	int count = 0;

	if (nla_type(attr) != NET_FLOW_FLOW) {
		pr_warn("%s: unknown field in table/flows\n", __func__);
		return -EINVAL;
	}

	err = nla_parse_nested(f, NET_FLOW_NET_FLOW_ATTR_MAX, attr, net_flow_flow_policy);
	if (err < 0) { /* TBD remove warns or at least rate lmit */
		pr_warn("%s: flow flow attr parse error\n", __func__);
		return -EINVAL;
	}

	flow->table_id = nla_get_u32(f[NET_FLOW_NET_FLOW_ATTR_TABLE]);
	flow->uid = nla_get_u32(f[NET_FLOW_NET_FLOW_ATTR_UID]);
	flow->priority = nla_get_u32(f[NET_FLOW_NET_FLOW_ATTR_PRIORITY]);

	flow->matches = NULL;
	flow->actions = NULL;

	if (f[NET_FLOW_NET_FLOW_ATTR_MATCHES]) {
		nla_for_each_nested(attr2, f[NET_FLOW_NET_FLOW_ATTR_MATCHES], rem)
			count++;

		/* Null terminated list of matches */
		flow->matches = kcalloc(count + 1,
					sizeof(struct net_flow_field_ref), GFP_KERNEL);
		if (!flow->matches)
			return -ENOMEM;

		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_NET_FLOW_ATTR_MATCHES], rem) {
			nl_to_sw_field_ref(&flow->matches[count], attr2);
			count++;
		}
	}

	if (f[NET_FLOW_NET_FLOW_ATTR_ACTIONS]) {
		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_NET_FLOW_ATTR_ACTIONS], rem)
			count++;

		/* Null terminated list of actions */
		flow->actions = kcalloc(count + 1, sizeof(struct net_flow_action), GFP_KERNEL);
		if (!flow->actions) {
			kfree(flow->matches);
			return -ENOMEM;
		}

		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_NET_FLOW_ATTR_ACTIONS], rem) {
			nl_to_sw_action(&flow->actions[count], attr2);
			count++;
		}
	}

	return 0;
}

static void kfree_flow(struct net_flow_flow *f)
{
	if (!f)
		return;

	if (f->matches)
		kfree(f->matches);
	if (f->actions) {
		if (f->actions->args)
			kfree(f->actions->args);
		kfree(f->actions);
	}
}

static void kfree_net_flow_tables(struct net_flow_tables *t)
{
	int i;

	if (!t)
		return;

	for (i = 0; i < t->table_sz; i++) {
		kfree(t->tables[i].name);
		kfree(t->tables[i].matches);

		kfree_flow(t->tables[i].flows);
	}
}

static struct net_device *net_flow_table_get_dev(struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	int type, ifindex;

	if (!info->attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !info->attrs[NET_FLOW_IDENTIFIER])
		return NULL;

	type = nla_get_u32(info->attrs[NET_FLOW_IDENTIFIER_TYPE]);
	switch (type) {
	case NET_FLOW_IDENTIFIER_IFINDEX:
		ifindex = nla_get_u32(info->attrs[NET_FLOW_IDENTIFIER]);
		break;
	default:
		return NULL;
	}

	return dev_get_by_index(net, ifindex);
}

static int net_flow_table_cmd_get_tables(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct net_flow_tables *tables;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_tables) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	tables = dev->netdev_ops->ndo_flow_table_get_tables(dev);
	if (!tables) /* transient failure should always have some table */
		return -EBUSY;

	msg = net_flow_table_build_tables_msg(tables, dev,
					  info->snd_portid,
					  info->snd_seq,
					  NET_FLOW_TABLE_CMD_GET_TABLES);
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_table_cmd_get_headers(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct net_flow_headers *h;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_headers) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	h = dev->netdev_ops->ndo_flow_table_get_headers(dev);
	if (!h)
		return -EBUSY;

	msg = net_flow_table_build_headers_msg(h, dev,
					   info->snd_portid,
					   info->snd_seq,
					   NET_FLOW_TABLE_CMD_GET_HEADERS); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

struct sk_buff *net_flow_table_build_actions_msg(struct net_flow_actions *a,
					     struct net_device *dev,
					     u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_actions_to_nl(skb, a);
	if (err < 0)
		goto out;
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);

}

static int net_flow_table_cmd_get_actions(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct net_flow_actions *a;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_actions) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	a = dev->netdev_ops->ndo_flow_table_get_actions(dev);
	if (!a)
		return -EBUSY;

	msg = net_flow_table_build_actions_msg(a, dev,
					  info->snd_portid,
					  info->snd_seq,
					  NET_FLOW_TABLE_CMD_GET_ACTIONS); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_table_cmd_get_parse_graph(struct sk_buff *skb,
					  struct genl_info *info)
{
	return -EOPNOTSUPP;
}

static int
net_flow_table_graph_to_nl(struct sk_buff *skb, struct net_flow_table_graph_nodes *g)
{
	struct nlattr *nodes, *node, *jump, *jump_node, *field;
	struct net_flow_table_graph_node *n;
	int err, i = 0;

	nodes = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (n = g->nodes[i]; n->uid; n = g->nodes[++i]) {
		struct net_flow_jump_table *j;

		node = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH_NODE);
		if (!node)
			goto out;

		if (nla_put_u32(skb, NET_FLOW_TABLE_GRAPH_NODE_UID, n->uid))
			goto node_put_failure;

		jump = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH_NODE_JUMP);
		if (!jump)
			goto out;	

		for (j = &n->jump[0]; j->node; j++) {
			jump_node = nla_nest_start(skb, NET_FLOW_JUMP_TABLE_ENTRY);
			if (!jump_node)
				goto jump_put_failure;

			printk("%s: add jump node\n", __func__);

			if (nla_put_u32(skb, NET_FLOW_JUMP_TABLE_NODE, j->node)) {
				printk("%s: table node failed\n", __func__);
				goto jump_node_put_failure;
			}

			field = nla_nest_start(skb, NET_FLOW_JUMP_TABLE_FIELD);
			err = nla_put(skb, NET_FLOW_FIELD_REF, sizeof(j->field), &j->field);
			if (err) {
				printk("%s: warning field ref failed\n", __func__);
				goto field_put_failure;
			}
			nla_nest_end(skb, field);
			nla_nest_end(skb, jump_node);
		}

		nla_nest_end(skb, jump);
		nla_nest_end(skb, node);
	}

	nla_nest_end(skb, nodes);
	return 0;
field_put_failure:
	nla_nest_cancel(skb, field);
jump_node_put_failure:
	nla_nest_cancel(skb, jump_node);
jump_put_failure:
	nla_nest_cancel(skb, jump);	
node_put_failure:
	nla_nest_cancel(skb, node);
out:
	nla_nest_cancel(skb, nodes);	
	return -EMSGSIZE;
}

static
struct sk_buff *net_flow_table_build_table_graph_msg(struct net_flow_table_graph_nodes *g,
						 struct net_device *dev,
						 u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_table_graph_to_nl(skb, g);
	if (err < 0)
		goto out;
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_table_cmd_get_table_graph(struct sk_buff *skb,
					  struct genl_info *info)
{
	struct net_flow_table_graph_nodes *g;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_tbl_graph) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	g = dev->netdev_ops->ndo_flow_table_get_tbl_graph(dev);
	if (!g)
		return -EBUSY;

	msg = net_flow_table_build_table_graph_msg(g, dev,
					       info->snd_portid,
					       info->snd_seq,
					       NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

struct sk_buff *net_flow_table_build_flows_msg(struct net_device *dev,
					   u32 portid, int seq, u8 cmd,
					   int min, int max, int table)
{
	struct genlmsghdr *hdr;
	struct nlattr *flows;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	flows = nla_nest_start(skb, NET_FLOW_FLOWS);
	err = dev->netdev_ops->ndo_flow_table_get_flows(skb, dev,
							table, min, max);
	if (err < 0)
		goto out;
	nla_nest_end(skb, flows);
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static const
struct nla_policy net_flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1] = {
	[NET_FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
	[NET_FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

static int net_flow_table_cmd_get_flows(struct sk_buff *skb,
				    struct genl_info *info)
{
	struct nlattr *tb[NET_FLOW_TABLE_FLOWS_MAX+1];
	int err, table, min = -1, max = -1;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_flows) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	if (!info->attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !info->attrs[NET_FLOW_IDENTIFIER] ||
	    !info->attrs[NET_FLOW_FLOWS])
		goto out;

	err = nla_parse_nested(tb, NET_FLOW_TABLE_FLOWS_MAX,
			       info->attrs[NET_FLOW_FLOWS],
			       net_flow_table_flows_policy);
	if (err)
		goto out;

	table = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_TABLE]);

	if (tb[NET_FLOW_TABLE_FLOWS_MINPRIO])
		min = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_MINPRIO]);
	if (tb[NET_FLOW_TABLE_FLOWS_MAXPRIO])
		max = nla_get_u32(tb[NET_FLOW_TABLE_FLOWS_MAXPRIO]);

	msg = net_flow_table_build_flows_msg(dev, 
					 info->snd_portid,
					 info->snd_seq,
					 NET_FLOW_TABLE_CMD_GET_FLOWS,
					 min, max, table);
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
out:
	dev_put(dev);
	return -EINVAL;
}

static int net_flow_table_cmd_set_flows(struct sk_buff *skb,
				    struct genl_info *info)
{
	struct nlattr *tb[NET_FLOW_TABLE_FLOWS_MAX+1];
	struct nlattr *flow;
	int rem, err;
	struct net_device *dev;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_set_flows) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	if (!info->attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !info->attrs[NET_FLOW_IDENTIFIER] ||
	    !info->attrs[NET_FLOW_FLOWS]) {
		printk("%s: received flows set cmd without preamble\n", __func__);
		goto out;
	}

	err = nla_parse_nested(tb, NET_FLOW_TABLE_FLOWS_MAX,
			       info->attrs[NET_FLOW_FLOWS],
			       net_flow_table_flows_policy);
	if (err) {
		printk("%s: table flows parse error\n", __func__);
		goto out;
	}

	nla_for_each_nested(flow, tb[NET_FLOW_TABLE_FLOWS_FLOWS], rem) {
		struct net_flow_flow this;

		err = nl_to_sw_flow(&this, flow);
		if (err)
			goto out;

		dev->netdev_ops->ndo_flow_table_set_flows(dev, &this);

		/* Cleanup flow */
		kfree(this.matches);
		kfree(this.actions);
	}

	dev_put(dev);
	return 0;
out:
	dev_put(dev);
	return -EINVAL;
}

static const struct genl_ops net_flow_table_nl_ops[] = {
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_TABLES,
		.doit = net_flow_table_cmd_get_tables,
		//policy = net_flow_table_get_tables_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_HEADERS,
		.doit = net_flow_table_cmd_get_headers,
		//.policy = net_flow_table_cmd_get_headers,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_ACTIONS,
		.doit = net_flow_table_cmd_get_actions,
		//.policy = net_flow_table_cmd_get_actions,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_PARSE_GRAPH,
		.doit = net_flow_table_cmd_get_parse_graph,
		//.policy = net_flow_table_cmd_get_parse_graph,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH,
		.doit = net_flow_table_cmd_get_table_graph,
		//.policy = net_flow_table_cmd_get_table_graph,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_GET_FLOWS,
		.doit = net_flow_table_cmd_get_flows,
		//.policy = net_flow_table_cmd_get_flows,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_SET_FLOWS,
		.doit = net_flow_table_cmd_set_flows,
		//.policy = net_flow_table_cmd_set_flows_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

static int __init net_flow_nl_module_init(void)
{
	return genl_register_family_with_ops(&net_flow_nl_family, net_flow_table_nl_ops);
}

static void net_flow_nl_module_fini(void)
{
	genl_unregister_family(&net_flow_nl_family);
}

module_init(net_flow_nl_module_init);
module_exit(net_flow_nl_module_fini);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("John Fastabend <john.r.fastabend@intel.com>");
MODULE_DESCRIPTION("Netlink interface to Flow Tables");
MODULE_ALIAS_GENL_FAMILY(NET_FLOW_GENL_NAME);

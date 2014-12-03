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
struct nla_policy net_flow_flow_policy[NET_FLOW_ATTR_MAX + 1] = {
	[NET_FLOW_ATTR_TABLE]	= { .type = NLA_U32 },
	[NET_FLOW_ATTR_UID]		= { .type = NLA_U32 },
	[NET_FLOW_ATTR_PRIORITY]	= { .type = NLA_U32 },
	[NET_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED },
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
};

static int net_flow_put_act_types(struct sk_buff *skb,
				  struct net_flow_action_arg *args)
{
	int i, err;

	for (i = 0; args[i].type; i++) {
		err = nla_put(skb, NET_FLOW_ACTION_ARG,
			      sizeof(struct net_flow_action_arg), &args[i]);
		if (err)
			return -EMSGSIZE;
	}
	return 0;
}

static const
struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME]	 = {.type = NLA_STRING, .len = IFNAMSIZ-1 },
	[NET_FLOW_ACTION_ATTR_UID]	 = {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

static int net_flow_put_action(struct sk_buff *skb, struct net_flow_action *a)
{
	struct net_flow_action_arg *this;
	struct nlattr *nest;
	int err, args = 0;

	if (a->name && nla_put_string(skb, NET_FLOW_ACTION_ATTR_NAME, a->name))
		return -EMSGSIZE;

	if (nla_put_u32(skb, NET_FLOW_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	for (this = &a->args[0]; strlen(this->name) > 0; this++)
		args++;

	if (args) {
		nest = nla_nest_start(skb, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!nest)
			goto nest_put_failure;

		err = net_flow_put_act_types(skb, a->args);
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

static int net_flow_put_actions(struct sk_buff *skb, struct net_flow_action **acts)
{
	struct nlattr *actions;
	int err, i;

	actions = nla_nest_start(skb, NET_FLOW_ACTIONS);
	if (!actions)
		return -EMSGSIZE;
		
	for (i = 0; acts[i]->uid; i++) {
		struct nlattr *action = nla_nest_start(skb, NET_FLOW_ACTION);

		if (!action)
			goto action_put_failure;

		err = net_flow_put_action(skb, acts[i]);
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

int net_flow_put_flow_action(struct sk_buff *skb, struct net_flow_action *a)
{
	struct nlattr *action, *sigs;
	int i, err = 0;

	action = nla_nest_start(skb, NET_FLOW_ACTION);
	if (!action)
		return -EMSGSIZE;

	if (nla_put_u32(skb, NET_FLOW_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	for (i = 0; a[i].uid; i++) {
		sigs = nla_nest_start(skb, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!sigs) {
			nla_nest_cancel(skb, action);
			return -EMSGSIZE;
		}

		err = net_flow_put_act_types(skb, a[i].args);
		if (err) {
			nla_nest_cancel(skb, action);
			nla_nest_cancel(skb, sigs);
			return err;
		}
		nla_nest_end(skb, sigs);
	}

	nla_nest_end(skb, action);
	return 0;
}

int net_flow_put_flow(struct sk_buff *skb, struct net_flow_flow *flow)
{
	struct nlattr *flows, *matches;
	struct nlattr *actions = NULL; /* must be null to unwind */
	int err, j, i = 0;

	flows = nla_nest_start(skb, NET_FLOW_FLOW);
	if (!flows)
		goto put_failure;

	if (nla_put_u32(skb, NET_FLOW_ATTR_TABLE, flow->table_id) ||
	    nla_put_u32(skb, NET_FLOW_ATTR_UID, flow->uid) ||
	    nla_put_u32(skb, NET_FLOW_ATTR_PRIORITY, flow->priority))
		goto flows_put_failure;

	matches = nla_nest_start(skb, NET_FLOW_ATTR_MATCHES);
	if (!matches)
		goto flows_put_failure;
	for (j = 0; flow->matches[j].header; j++) {
		struct net_flow_field_ref *f = &flow->matches[j];

		if (!f->header)
			continue;

		nla_put(skb, NET_FLOW_FIELD_REF, sizeof(*f), f);
	}
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, NET_FLOW_ATTR_ACTIONS);
	if (!actions)
		goto flows_put_failure;

	for (i = 0; flow->actions[i].uid; i++) {
		err = net_flow_put_flow_action(skb, &flow->actions[i]);
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
EXPORT_SYMBOL(net_flow_put_flow);

static int net_flow_put_table(struct net_device *dev,
			      struct sk_buff *skb,
			      struct net_flow_table *t)
{
	struct nlattr *matches, *actions;
	int i;

	if (nla_put_string(skb, NET_FLOW_TABLE_ATTR_NAME, t->name) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_UID, t->uid) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_SOURCE, t->source) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_ATTR_SIZE, t->size))
		return -EMSGSIZE;

	matches = nla_nest_start(skb, NET_FLOW_TABLE_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (i = 0; t->matches[i].instance; i++)
		nla_put(skb, NET_FLOW_FIELD_REF,
			sizeof(struct net_flow_field_ref),
			&t->matches[i]);
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, NET_FLOW_TABLE_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (i = 0; t->actions[i]; i++) {
		if (nla_put_u32(skb,
				NET_FLOW_ACTION_ATTR_UID,
				t->actions[i])) {
			nla_nest_cancel(skb, actions);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, actions);

	return 0;
}

int net_flow_put_tables(struct net_device *dev,
			struct sk_buff *skb,
			struct net_flow_table **tables)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(skb, NET_FLOW_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; tables[i]->uid; i++) {
		t = nla_nest_start(skb, NET_FLOW_TABLE);
		if (!t) {
			err = -EMSGSIZE;
			goto errout;
		}

		err = net_flow_put_table(dev, skb, tables[i]);
		if (err) {
			nla_nest_cancel(skb, t);
			goto errout;
		}
		nla_nest_end(skb, t);
	}
	nla_nest_end(skb, nest);
	return 0;
errout:
	nla_nest_cancel(skb, nest);
	return err;
}
EXPORT_SYMBOL(net_flow_put_tables);

struct sk_buff *net_flow_build_tables_msg(struct net_flow_table **t,
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

	err = net_flow_put_tables(dev, skb, t);
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

int net_flow_put_fields(struct sk_buff *skb, const struct net_flow_header *h)
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

int net_flow_put_headers(struct sk_buff *skb,
			 struct net_flow_header **headers)
{
	struct nlattr *nest, *hdr, *fields;
	struct net_flow_header *h;
	int i, err;

	nest = nla_nest_start(skb, NET_FLOW_HEADERS);
	if (!nest)
		return -EMSGSIZE;
		
	for (i = 0; headers[i]->uid; i++) {
		err = -EMSGSIZE;
		h = headers[i];
 
		hdr = nla_nest_start(skb, NET_FLOW_HEADER);
		if (!hdr)
			goto hdr_put_failure;

		if (nla_put_string(skb, NET_FLOW_HEADER_ATTR_NAME, h->name) ||
		    nla_put_u32(skb, NET_FLOW_HEADER_ATTR_UID, h->uid))
			goto attr_put_failure;

		fields = nla_nest_start(skb, NET_FLOW_HEADER_ATTR_FIELDS);
		if (!fields)
			goto attr_put_failure;

		err = net_flow_put_fields(skb, h);
		if (err)
			goto fields_put_failure;

		nla_nest_end(skb, fields);

		nla_nest_end(skb, hdr);
	}
	nla_nest_end(skb, nest);

	return 0;
fields_put_failure:
	nla_nest_cancel(skb, fields);
attr_put_failure:
	nla_nest_cancel(skb, hdr);
hdr_put_failure:
	nla_nest_cancel(skb, nest);
	return err;
}

struct sk_buff *net_flow_build_headers_msg(struct net_flow_header **h,
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

	err = net_flow_put_headers(skb, h);
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

static int net_flow_get_field(struct net_flow_field_ref *field,
			      struct nlattr *nla)
{
	if (nla_type(nla) != NET_FLOW_FIELD_REF)
		return -EINVAL;

	if (nla_len(nla) < sizeof(*field))
		return -EINVAL;

	*field = *(struct net_flow_field_ref *) nla_data(nla);
	return 0;
}

static int net_flow_get_action(struct net_flow_action *a, struct nlattr *attr)
{
	struct nlattr *act[NET_FLOW_ACTION_ATTR_MAX+1];
	struct nlattr *args;
	int rem;
	int err, count = 0;

	if (nla_type(attr) != NET_FLOW_ACTION) {
		pr_warn("%s: expected NET_FLOW_ACTION\n", __func__);
		return 0;
	}

	err = nla_parse_nested(act, NET_FLOW_ACTION_ATTR_MAX,
			       attr, net_flow_action_policy);
	if (err < 0)
		return err;

	a->uid = nla_get_u32(act[NET_FLOW_ACTION_ATTR_UID]);

	nla_for_each_nested(args, act[NET_FLOW_ACTION_ATTR_SIGNATURE], rem)
		count++; /* unoptimized max possible */

	a->args = kcalloc(count + 1, sizeof(struct net_flow_action_arg), GFP_KERNEL);
	count = 0;

	nla_for_each_nested(args, act[NET_FLOW_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(args) != NET_FLOW_ACTION_ARG)
			continue;

		if (nla_len(args) < sizeof(struct net_flow_action_arg)) {
			kfree(a->args);
			return -EINVAL;
		}

		a->args[count] = *(struct net_flow_action_arg *) nla_data(args);
	}
	return 0;
}

static int net_flow_get_flow(struct net_flow_flow *flow, struct nlattr *attr)
{
	struct nlattr *f[NET_FLOW_ATTR_MAX+1];
	struct nlattr *attr2;
	int rem, err;
	int count = 0;

	err = nla_parse_nested(f, NET_FLOW_ATTR_MAX, attr, net_flow_flow_policy);
	if (err < 0)
		return -EINVAL;

	flow->table_id = nla_get_u32(f[NET_FLOW_ATTR_TABLE]);
	flow->uid = nla_get_u32(f[NET_FLOW_ATTR_UID]);
	flow->priority = nla_get_u32(f[NET_FLOW_ATTR_PRIORITY]);

	flow->matches = NULL;
	flow->actions = NULL;

	if (f[NET_FLOW_ATTR_MATCHES]) {
		nla_for_each_nested(attr2, f[NET_FLOW_ATTR_MATCHES], rem)
			count++;

		/* Null terminated list of matches */
		flow->matches = kcalloc(count + 1,
					sizeof(struct net_flow_field_ref), GFP_KERNEL);
		if (!flow->matches)
			return -ENOMEM;

		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_ATTR_MATCHES], rem) {
			err = net_flow_get_field(&flow->matches[count], attr2);
			if (err) {
				kfree(flow->matches);
				return err;
			}
			count++;
		}
	}

	if (f[NET_FLOW_ATTR_ACTIONS]) {
		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_ATTR_ACTIONS], rem)
			count++;

		/* Null terminated list of actions */
		flow->actions = kcalloc(count + 1, sizeof(struct net_flow_action), GFP_KERNEL);
		if (!flow->actions) {
			kfree(flow->matches);
			return -ENOMEM;
		}

		count = 0;
		nla_for_each_nested(attr2, f[NET_FLOW_ATTR_ACTIONS], rem) {
			err = net_flow_get_action(&flow->actions[count], attr2);
			if (err) {
				kfree(flow->matches);
				kfree(flow->actions);
				return err;
			}
			count++;
		}
	}

	return 0;
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

static int net_flow_get_table(struct net_flow_table *table, struct nlattr *nla)
{
	struct nlattr *tbl[NET_FLOW_TABLE_ATTR_MAX+1];
	struct nlattr *i;
	int cnt, rem, err;

	err = nla_parse_nested(tbl, NET_FLOW_TABLE_ATTR_MAX, nla, net_flow_table_policy);
	if (err)
		return err;

	if (tbl[NET_FLOW_TABLE_ATTR_NAME])
		nla_strlcpy(table->name, tbl[NET_FLOW_TABLE_ATTR_NAME], IFNAMSIZ - 1);

	table->uid = tbl[NET_FLOW_TABLE_ATTR_UID] ?
		     nla_get_u32(tbl[NET_FLOW_TABLE_ATTR_UID]) : 0;

	table->source = tbl[NET_FLOW_TABLE_ATTR_SOURCE] ?
			nla_get_u32(tbl[NET_FLOW_TABLE_ATTR_SOURCE]) : 0;

	table->size = tbl[NET_FLOW_TABLE_ATTR_SIZE] ?
		      nla_get_u32(tbl[NET_FLOW_TABLE_ATTR_SIZE]) : 0;

	if (tbl[NET_FLOW_TABLE_ATTR_MATCHES]) {
		cnt = 0;
		nla_for_each_nested(i, tbl[NET_FLOW_TABLE_ATTR_MATCHES], rem)
			cnt++;

		/* Null terminated list of matches */
		table->matches = kcalloc(cnt + 1,
					 sizeof(struct net_flow_field_ref), GFP_KERNEL);
		if (!table->matches)
			return -ENOMEM;

		cnt = 0;
		nla_for_each_nested(i, tbl[NET_FLOW_TABLE_ATTR_MATCHES], rem) {
			err = net_flow_get_field(&table->matches[cnt], i);
			if (err)
				goto matches_err_out;
			cnt++;
		}
	}

	if (tbl[NET_FLOW_TABLE_ATTR_ACTIONS]) {
		cnt = 0;
		nla_for_each_nested(i, tbl[NET_FLOW_TABLE_ATTR_ACTIONS], rem)
			cnt++;

		table->actions = kzalloc((cnt + 1) * sizeof (struct net_flow_field_ref), GFP_KERNEL);
		if (!table->actions) {
			err = -ENOMEM;
			goto matches_err_out;
		}

		cnt = 0;
		err = -EINVAL;

		nla_for_each_nested(i, tbl[NET_FLOW_TABLE_ATTR_ACTIONS], rem) {
			if (nla_type(i) != NET_FLOW_ACTION_ATTR_UID)
				continue;
			if (nla_len(nla) < sizeof(u32))
				goto action_err_out;
			table->actions[cnt] = nla_get_u32(i);
			cnt++;
		}
	}

	return 0;
action_err_out:
	kfree(table->actions);
matches_err_out:
	kfree(table->matches);
	return err;
}

static int net_flow_table_cmd_create_tables(struct sk_buff *skb,
					    struct genl_info *info)
{
	struct net_device *dev;
	struct nlattr *tattr;
	int rem, err;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_create_table) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	if (!info->attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !info->attrs[NET_FLOW_IDENTIFIER] ||
	    !info->attrs[NET_FLOW_TABLES]) {
		printk("%s: received table set cmd without preamble\n", __func__);
		goto out;
	}

	nla_for_each_nested(tattr, info->attrs[NET_FLOW_TABLES], rem) {
		struct net_flow_table this = {.name = "", .uid = 0,};

		if (nla_type(tattr) != NET_FLOW_TABLE)
			continue;

		err = net_flow_get_table(&this, tattr);
		if (err)
			goto out;

		err = dev->netdev_ops->ndo_flow_table_create_table(dev, &this);

		/* Cleanup table */
		kfree(this.matches);
		kfree(this.actions);

		if (err)
			return err;
	}

	dev_put(dev);
	return 0;
out:
	dev_put(dev);
	return -EINVAL;
}

static int net_flow_table_cmd_destroy_tables(struct sk_buff *skb,
					     struct genl_info *info)
{
	return -EOPNOTSUPP;
}

static int net_flow_table_cmd_get_tables(struct sk_buff *skb,
					 struct genl_info *info)
{
	struct net_flow_table **tables;
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

	msg = net_flow_build_tables_msg(tables, dev,
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
	struct net_flow_header **h;
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

	msg = net_flow_build_headers_msg(h, dev,
					 info->snd_portid,
					 info->snd_seq,
					 NET_FLOW_TABLE_CMD_GET_HEADERS); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

struct sk_buff *net_flow_build_actions_msg(struct net_flow_action **a,
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

	err = net_flow_put_actions(skb, a);
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
	struct net_flow_action **a;
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

	msg = net_flow_build_actions_msg(a, dev,
					 info->snd_portid,
					 info->snd_seq,
					 NET_FLOW_TABLE_CMD_GET_ACTIONS); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_put_header_node(struct sk_buff *skb,
				    struct net_flow_header_node *node)
{
	struct nlattr *hdrs, *jumps;
	int i, err;

	if (nla_put_string(skb, NET_FLOW_HEADER_NODE_NAME, node->name) ||
	    nla_put_u32(skb, NET_FLOW_HEADER_NODE_UID, node->uid))
		return -EMSGSIZE;

	/* Insert the set of headers that get extracted at this node */
	hdrs = nla_nest_start(skb, NET_FLOW_HEADER_NODE_HDRS);
	if (!hdrs)
		return -EMSGSIZE;
	for (i = 0; node->hdrs[i]; i++) {
		if (nla_put_u32(skb, NET_FLOW_HEADER_NODE_HDRS_VALUE,
				node->hdrs[i])) {
			nla_nest_cancel(skb, hdrs);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, hdrs);

	/* Then give the jump table to find next header node in graph */
	jumps = nla_nest_start(skb, NET_FLOW_HEADER_NODE_JUMP);
	if (!jumps)
		return -EMSGSIZE;	

	for (i = 0; node->jump[i].node; i++) {
		err = nla_put(skb, NET_FLOW_JUMP_TABLE_ENTRY,
			      sizeof(struct net_flow_jump_table),
			      &node->jump[i]);
		if (err) {
			nla_nest_cancel(skb, jumps);	
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, jumps);

	return 0;
}

static int net_flow_put_header_graph(struct sk_buff *skb,
				     struct net_flow_header_node **g)
{
	struct nlattr *nodes, *node;
	int err, i;

	nodes = nla_nest_start(skb, NET_FLOW_HEADER_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; g[i]->uid; i++) {
		node = nla_nest_start(skb, NET_FLOW_HEADER_GRAPH_NODE);
		if (!node) {
			err = -EMSGSIZE;
			goto nodes_put_error;
		}

		err = net_flow_put_header_node(skb, g[i]);
		if (err)
			goto node_put_error;

		nla_nest_end(skb, node);
	}

	nla_nest_end(skb, nodes);
	return 0;
node_put_error:
	nla_nest_cancel(skb, node);
nodes_put_error:
	nla_nest_cancel(skb, nodes);	
	return err;
}

static
struct sk_buff *net_flow_build_header_graph_msg(struct net_flow_header_node **g,
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

	err = net_flow_put_header_graph(skb, g);
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


static int net_flow_table_cmd_get_header_graph(struct sk_buff *skb,
					       struct genl_info *info)
{
	struct net_flow_header_node **h;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!dev->netdev_ops->ndo_flow_table_get_hdr_graph) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	h = dev->netdev_ops->ndo_flow_table_get_hdr_graph(dev);
	if (!h)
		return -EBUSY;

	msg = net_flow_build_header_graph_msg(h, dev,
					      info->snd_portid,
					      info->snd_seq,
					      NET_FLOW_TABLE_CMD_GET_HEADER_GRAPH); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_put_table_node(struct sk_buff *skb,
				    struct net_flow_table_graph_node *node)
{
	struct nlattr *nest, *jump;
	int i, err = -EMSGSIZE;

	nest = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH_NODE);
	if (!nest)
		return err;

	if (nla_put_u32(skb, NET_FLOW_TABLE_GRAPH_NODE_UID, node->uid) ||
	    nla_put_u32(skb, NET_FLOW_TABLE_GRAPH_NODE_FLAGS, node->flags))
		goto node_put_failure;

	jump = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH_NODE_JUMP);
	if (!jump)
		goto node_put_failure;	

	for (i = 0; node->jump[i].node; i++) {
		err = nla_put(skb, NET_FLOW_JUMP_TABLE_ENTRY,
			      sizeof(struct net_flow_jump_table),
			      &node->jump[i]);
		if (err)
			goto jump_put_failure;
	}

	nla_nest_end(skb, jump);
	nla_nest_end(skb, nest);
	return 0;
jump_put_failure:
	nla_nest_cancel(skb, jump);
node_put_failure:
	nla_nest_cancel(skb, nest);
	return err;
}

static int net_flow_put_table_graph(struct sk_buff *skb,
				    struct net_flow_table_graph_node **nodes)
{
	struct nlattr *graph;
	int err, i = 0;

	graph = nla_nest_start(skb, NET_FLOW_TABLE_GRAPH);
	if (!graph)
		return -EMSGSIZE;

	for (i = 0; nodes[i]->uid; i++) {
		err = net_flow_put_table_node(skb, nodes[i]);	
		if (err) {
			nla_nest_cancel(skb, graph);
			return -EMSGSIZE;
		}
	}

	nla_nest_end(skb, graph);
	return 0;
}

static
struct sk_buff *net_flow_build_table_graph_msg(struct net_flow_table_graph_node **g,
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

	err = net_flow_put_table_graph(skb, g);
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
	struct net_flow_table_graph_node **g;
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

	msg = net_flow_build_table_graph_msg(g, dev,
					     info->snd_portid,
					     info->snd_seq,
					     NET_FLOW_TABLE_CMD_GET_TABLE_GRAPH); 
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

struct sk_buff *net_flow_build_flows_msg(struct net_device *dev,
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
	if (!flows) {
		err = -EMSGSIZE;
		goto out;
	}

	err = dev->netdev_ops->ndo_flow_table_get_flows(skb, dev,
							table, min, max);
	if (err < 0)
		goto out_cancel;

	nla_nest_end(skb, flows);
	
	err = genlmsg_end(skb, hdr);
	if (err < 0)
		goto out;

	return skb;
out_cancel:
	nla_nest_cancel(skb, flows);
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
	int table, min = -1, max = -1;
	struct net_device *dev;
	struct sk_buff *msg;
	int err = -EINVAL;

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

	msg = net_flow_build_flows_msg(dev, 
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
	return err;
}

struct sk_buff *net_flow_start_flow_errmsg(struct net_device *dev,
					   struct genlmsghdr **hdr,
					   u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *h;
	struct sk_buff *skb;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-EMSGSIZE);

	h = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!h)
		return ERR_PTR(-EMSGSIZE);

	if (nla_put_u32(skb, NET_FLOW_IDENTIFIER_TYPE, NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NET_FLOW_IDENTIFIER, dev->ifindex))
		return ERR_PTR(-EMSGSIZE);

	*hdr = h;
	return skb;
}

struct sk_buff *net_flow_end_flow_errmsg(struct sk_buff *skb,
					 struct genlmsghdr *hdr)
{
	int err;

	err = genlmsg_end(skb, hdr);
	if (err < 0) {
		nlmsg_free(skb);
		return ERR_PTR(err);
	}

	return skb;
}

static int net_flow_table_cmd_flows(struct sk_buff *recv_skb,
				    struct genl_info *info)
{
	int rem, err_handle = NET_FLOW_FLOWS_ERROR_ABORT;
	struct sk_buff *skb = NULL;
	struct net_flow_flow this;
	struct genlmsghdr *hdr;
	struct net_device *dev;
	struct nlattr *flow, *flows;
	int cmd = info->genlhdr->cmd;
	int err = -EOPNOTSUPP;

	dev = net_flow_table_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (cmd == NET_FLOW_TABLE_CMD_UPDATE_FLOWS)
		goto out; /* TBD Update */

	if (!dev->netdev_ops->ndo_flow_table_set_flows)
		goto out;

	if (!info->attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !info->attrs[NET_FLOW_IDENTIFIER] ||
	    !info->attrs[NET_FLOW_FLOWS]) {
		err = -EINVAL;
		goto out;
	}

	if (info->attrs[NET_FLOW_FLOWS_ERROR])
		err_handle = nla_get_u32(info->attrs[NET_FLOW_FLOWS_ERROR]);

	nla_for_each_nested(flow, info->attrs[NET_FLOW_FLOWS], rem) {
		if (nla_type(flow) != NET_FLOW_FLOW)
			continue;

		err = net_flow_get_flow(&this, flow);
		if (err)
			goto out;

		switch (cmd) {
		case NET_FLOW_TABLE_CMD_SET_FLOWS:
			err = dev->netdev_ops->ndo_flow_table_set_flows(dev, &this);
			break;
		case NET_FLOW_TABLE_CMD_DEL_FLOWS:
			err = dev->netdev_ops->ndo_flow_table_del_flows(dev, &this);
			break;
		default:
			err = -EOPNOTSUPP;
			break;
		}

		if (err && err_handle != NET_FLOW_FLOWS_ERROR_CONTINUE) {
			if (!skb) {
				skb = net_flow_start_flow_errmsg(dev, &hdr,
								 info->snd_portid,
								 info->snd_seq,
								 NET_FLOW_TABLE_CMD_SET_FLOWS);
				if (IS_ERR(skb)) {
					err = PTR_ERR(skb);
					goto out_plus_free;	
				}

				flows = nla_nest_start(skb, NET_FLOW_FLOWS);
				if (!flows) {
					err = -EMSGSIZE;
					goto out_plus_free;
				}
			}

			net_flow_put_flow(skb, &this);
		}

		/* Cleanup flow */
		kfree(this.matches);
		kfree(this.actions);

		if (err && err_handle == NET_FLOW_FLOWS_ERROR_ABORT)
			goto out;
	}

	dev_put(dev);

	if (skb) {
		nla_nest_end(skb, flows);
		net_flow_end_flow_errmsg(skb, hdr);
		return genlmsg_reply(skb, info);
	}
	return 0;

out_plus_free:
	kfree(this.matches);
	kfree(this.actions);
out:
	if (!IS_ERR(skb))
		nlmsg_free(skb);
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
		.cmd = NET_FLOW_TABLE_CMD_GET_HEADER_GRAPH,
		.doit = net_flow_table_cmd_get_header_graph,
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
		.doit = net_flow_table_cmd_flows,
		//.policy = net_flow_table_cmd_set_flows_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_DEL_FLOWS,
		.doit = net_flow_table_cmd_flows,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_UPDATE_FLOWS,
		.doit = net_flow_table_cmd_flows,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_CREATE_TABLE,
		.doit = net_flow_table_cmd_create_tables,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NET_FLOW_TABLE_CMD_DESTROY_TABLE,
		.doit = net_flow_table_cmd_destroy_tables,
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

#ifndef _LINUX_IF_FLOW_H
#define _LINUX_IF_FLOW_H

#include <uapi/linux/if_flow.h>

int hw_flow_tables_to_nl(struct net_device *dev,
			 struct sk_buff *,
			 const struct hw_flow_tables *);
int hw_flow_headers_to_nl(struct sk_buff *, const struct hw_flow_headers *);

int nl_to_sw_tables(struct hw_flow_tables *hw_flow, struct nlattr *t);
int hw_flow_headers_to_nl(struct sk_buff *skb,
			  const struct hw_flow_headers *headers);
int hw_flow_flow_to_nl(struct sk_buff *skb, struct hw_flow_flow *flow);
#endif

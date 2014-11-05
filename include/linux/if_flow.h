#ifndef _LINUX_IF_FLOW_H
#define _LINUX_IF_FLOW_H

#include <uapi/linux/if_flow.h>
int net_flow_flow_to_nl(struct sk_buff *skb, struct net_flow_flow *flow, int, int, int);
#endif

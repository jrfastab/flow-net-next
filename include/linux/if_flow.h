#ifndef _LINUX_IF_FLOW_H
#define _LINUX_IF_FLOW_H

#include <uapi/linux/if_flow.h>

int net_flow_put_flow(struct sk_buff *skb, struct net_flow_flow *flow);
#endif

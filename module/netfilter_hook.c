#include <linux/netfilter.h>

#include "netfilter_hook.h"

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    return NF_ACCEPT;
}

static const struct nf_hook_ops forward_hook = {
    .hook = forward_hook_func,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
};

int init_netfilter_hook(void) {
    int res;
    res = nf_register_net_hook(&init_net, &forward_hook);
    if (res < 0) {
        return res;
    }

    return 0;
}

void destroy_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &forward_hook);
}

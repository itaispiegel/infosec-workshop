#include <linux/ip.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "logs.h"
#include "netfilter_hook.h"
#include "parser.h"
#include "proxy.h"
#include "rules.h"
#include "tcp_conntrack.h"
#include "types.h"

static unsigned int netfilter_hook_func(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state);

static const struct nf_hook_ops nf_prerouting_op = {
    .hook = netfilter_hook_func,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static const struct nf_hook_ops nf_local_out_op = {
    .hook = netfilter_hook_func,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

static unsigned int netfilter_hook_func(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    __u8 i, verdict;
    packet_t packet;
    bool matched;
    enum proxy_response proxy_response;
    rule_t *matching_rule;

    parse_packet(&packet, skb, state);

    switch (packet.type) {
    case PACKET_TYPE_LOOPBACK:
    case PACKET_TYPE_UNHANDLED_PROTOCOL:
        // In this case we want to accept the packet without logging it.
        return NF_ACCEPT;
    case PACKET_TYPE_XMAS:
        update_log_entry_by_packet(&packet, REASON_XMAS_PACKET, NF_DROP);
        return NF_DROP;
    default:
        break;
    }

    if (packet.direction == DIRECTION_ANY) {
        printk(KERN_WARNING "Dropping packet with unknown direction\n");
        return NF_DROP;
    }

    // In these cases, the packet must be a normal packet.
    proxy_response = handle_proxy_packet(&packet, skb, state);
    if (proxy_response == ACCEPT_IMMEDIATELY) {
        return NF_ACCEPT;
    } else if (proxy_response == DROP_IMMEDIATELY) {
        return NF_DROP;
    }

    if (packet.protocol == PROT_TCP && (packet.ack || packet.tcp_header->rst)) {
        matched = match_connection_and_update_state(packet);
        verdict = matched ? NF_ACCEPT : NF_DROP;
        update_established_tcp_conn_log(&packet);
        return verdict;
    }

    if ((matching_rule = lookup_matching_rule(&packet)) == NULL) {
        update_log_entry_by_packet(&packet, REASON_NO_MATCHING_RULE, FW_POLICY);
        return FW_POLICY;
    }

    verdict = matching_rule->action;
    update_log_entry_by_packet(&packet, i, verdict);
    if (verdict == NF_ACCEPT && packet.protocol == PROT_TCP) {
        track_two_sided_connection(&packet);
    }
    return verdict;
}

int init_netfilter_hook(void) {
    int res;
    if ((res = nf_register_net_hook(&init_net, &nf_prerouting_op)) != 0) {
        return res;
    }
    if ((res = nf_register_net_hook(&init_net, &nf_local_out_op)) != 0) {
        nf_unregister_net_hook(&init_net, &nf_prerouting_op);
        return res;
    }
    return res;
}

void destroy_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &nf_local_out_op);
    nf_unregister_net_hook(&init_net, &nf_prerouting_op);
}

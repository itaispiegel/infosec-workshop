#include <linux/ip.h>
#include <linux/netfilter.h>

#include "fw.h"
#include "netfilter_hook.h"

extern rule_t rules[MAX_RULES];
extern __u8 rules_count;

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state);

static const struct nf_hook_ops forward_hook = {
    .hook = forward_hook_func,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_FORWARD,
};

static inline bool match_direction(rule_t *rule, struct sk_buff *skb) {
    // This is a bit confusing, but the packets that are going outside are
    // received on the IN device and vice versa, so the direction is reversed.
    return rule->direction == DIRECTION_ANY ||
           (rule->direction == DIRECTION_IN &&
            strcmp(skb->dev->name, OUT_NET_DEVICE_NAME) == 0) ||
           (rule->direction == DIRECTION_OUT &&
            strcmp(skb->dev->name, IN_NET_DEVICE_NAME) == 0);
}

static inline bool match_rule_ports(__be16 rule_port, __be16 skb_port) {
    // The port numbers are in big endian, so we need to convert them to host
    // byte order.
    return (rule_port == PORT_ANY || rule_port == skb_port ||
            (rule_port == PORT_ABOVE_1023_BE && be16_to_cpu(skb_port) > 1023));
}

static inline bool match_ip_addrs(rule_t *rule, struct iphdr *ip_header) {
    return (rule->src_ip == 0 ||
            (rule->src_prefix_size != 0 &&
             (rule->src_ip & rule->src_prefix_mask) ==
                 (ip_header->saddr & rule->src_prefix_mask))) &&
           (rule->dst_ip == 0 ||
            (rule->dst_prefix_size != 0 &&
             (rule->dst_ip & rule->dst_prefix_mask) ==
                 (ip_header->daddr & rule->dst_prefix_mask)));
}

static inline bool match_ports(rule_t *rule, struct sk_buff *skb) {
    char *transport_header = skb_transport_header(skb);
    return (rule->protocol == PROT_UDP &&
            match_rule_ports(rule->src_port,
                             ((struct udphdr *)transport_header)->source) &&
            match_rule_ports(rule->dst_port,
                             ((struct udphdr *)transport_header)->dest)) ||
           (rule->protocol == PROT_TCP &&
            match_rule_ports(rule->src_port,
                             ((struct tcphdr *)transport_header)->source) &&
            match_rule_ports(rule->dst_port,
                             ((struct tcphdr *)transport_header)->dest));
}

static inline bool match_protocol(rule_t *rule, struct iphdr *ip_header) {
    return rule->protocol == PROT_ANY || rule->protocol == ip_header->protocol;
}

static inline bool match_ack(rule_t *rule, struct iphdr *ip_header,
                             struct tcphdr *tcp_header) {
    return rule->ack == ACK_ANY ||
           (ip_header->protocol == PROT_TCP &&
            ((rule->ack == ACK_YES && tcp_header->ack) ||
             (rule->ack == ACK_NO && !tcp_header->ack)));
}

static inline bool match_rule_skb(__u8 i, rule_t *rule, struct sk_buff *skb) {
    struct iphdr *ip_header = ip_hdr(skb);
    return match_direction(rule, skb) && match_ip_addrs(rule, ip_header) &&
           match_ports(rule, skb) && match_protocol(rule, ip_header) &&
           match_ack(rule, ip_header, tcp_hdr(skb));
}

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    __u8 i;
    for (i = 0; i < rules_count; i++) {
        if (match_rule_skb(i, &rules[i], skb)) {
            return rules[i].action;
        }
    }

    return NF_DROP;
}

int init_netfilter_hook(void) {
    return nf_register_net_hook(&init_net, &forward_hook);
}

void destroy_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &forward_hook);
}

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

#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1023)
#define PORT_ABOVE_1023_BE (be16_to_cpu(PORT_ABOVE_1023))

extern struct list_head logs_list;
extern size_t logs_count;

extern rule_t rules[MAX_RULES];
extern __u8 rules_count;

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

static inline bool match_direction(rule_t *rule, packet_t *packet) {
    return rule->direction == DIRECTION_ANY ||
           rule->direction == packet->direction;
}

static inline bool match_rule_ports(__be16 rule_port, __be16 skb_port) {
    // The port numbers are in big endian, so we need to convert them to host
    // byte order.
    // Notice that we assume non UDP and non TCP packets have 0 as their ports.
    return (rule_port == PORT_ANY || rule_port == skb_port ||
            (rule_port == PORT_ABOVE_1023_BE && be16_to_cpu(skb_port) > 1023));
}

static inline bool match_ip_addrs(rule_t *rule, packet_t *packet) {
    return (rule->src_ip == 0 ||
            (rule->src_prefix_size != 0 &&
             (rule->src_ip & rule->src_prefix_mask) ==
                 (packet->src_ip & rule->src_prefix_mask))) &&
           (rule->dst_ip == 0 ||
            (rule->dst_prefix_size != 0 &&
             (rule->dst_ip & rule->dst_prefix_mask) ==
                 (packet->dst_ip & rule->dst_prefix_mask)));
}

static inline bool match_ports(rule_t *rule, packet_t *packet) {
    return match_rule_ports(rule->src_port, packet->src_port) &&
           match_rule_ports(rule->dst_port, packet->dst_port);
}

static inline bool match_protocol(rule_t *rule, packet_t *packet) {
    return rule->protocol == PROT_ANY || rule->protocol == packet->protocol;
}

static inline bool match_ack(rule_t *rule, packet_t *packet) {
    return rule->ack == ACK_ANY || (packet->protocol == PROT_TCP &&
                                    ((rule->ack == ACK_YES && packet->ack) ||
                                     (rule->ack == ACK_NO && !packet->ack)));
}

static inline bool match_rule_packet(rule_t *rule, packet_t *packet) {
    return match_direction(rule, packet) && match_ip_addrs(rule, packet) &&
           match_ports(rule, packet) && match_protocol(rule, packet) &&
           match_ack(rule, packet);
}

static inline bool log_match_rule(log_row_t *log_row, rule_t *rule) {
    return log_row->protocol == rule->protocol &&
           log_row->action == rule->action && log_row->src_ip == rule->src_ip &&
           log_row->dst_ip == rule->dst_ip &&
           log_row->src_port == rule->src_port &&
           log_row->dst_port == rule->dst_port;
}

static inline log_row_t new_log_row_by_packet(packet_t *packet, reason_t reason,
                                              __u8 verdict) {
    return (log_row_t){
        .timestamp = ktime_get_real_seconds(),
        .protocol = packet->protocol,
        .action = verdict,
        .src_ip = packet->src_ip,
        .dst_ip = packet->dst_ip,
        .src_port = packet->src_port,
        .dst_port = packet->dst_port,
        .reason = reason,
        .count = 1,
    };
}

static inline bool log_entry_matches_packet(struct log_entry *log_entry,
                                            packet_t *packet) {
    return log_entry->log_row.protocol == packet->protocol &&
           log_entry->log_row.src_ip == packet->src_ip &&
           log_entry->log_row.dst_ip == packet->dst_ip &&
           log_entry->log_row.src_port == packet->src_port &&
           log_entry->log_row.dst_port == packet->dst_port;
}

static void update_log_entry_by_packet(packet_t *packet, reason_t reason,
                                       __u8 verdict) {
    struct log_entry *log_entry;
    struct list_head *pos;
    list_for_each(pos, &logs_list) {
        log_entry = list_entry(pos, struct log_entry, list);
        if (log_entry->log_row.reason == reason &&
            log_entry_matches_packet(log_entry, packet)) {
            log_entry->log_row.count++;
            log_entry->log_row.timestamp = ktime_get_real_seconds();
            return;
        }
    }

    printk(KERN_INFO "Creating a new log entry for packet\n");
    log_entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
    if (log_entry == NULL) {
        printk(KERN_WARNING
               "Failed to allocate memory for log entry, so ignoring it\n");
        return;
    }

    log_entry->log_row = new_log_row_by_packet(packet, reason, verdict);
    list_add_tail(&log_entry->list, &logs_list);
    logs_count++;
}

static unsigned int netfilter_hook_func(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    __u8 i, verdict;
    packet_t packet;
    bool matched;

    parse_packet(&packet, skb, state);

    // TODO: Handle local packets
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

    // In these cases, the packet must be a normal packet.
    // TODO: Need to update log
    if (packet.protocol == PROT_TCP) {
        switch (state->hook) {
        case NF_INET_PRE_ROUTING:
            proxy_client_request(&packet, skb);

            // Handle packets received from the external network.
            if (packet.direction == DIRECTION_IN &&
                packet.dst_ip == FW_EXTERNAL_PROXY_IP) {
                return NF_ACCEPT;
            }
        case NF_INET_LOCAL_OUT:
            proxy_server_response(&packet, skb);

            // Handle packets sent to the external network.
            if (packet.direction == DIRECTION_OUT &&
                packet.src_ip == FW_EXTERNAL_PROXY_IP) {
                return NF_ACCEPT;
            }
        }

        if (packet.ack) {
            matched = match_connection_and_update_state(packet);
            verdict = matched ? NF_ACCEPT : NF_DROP;
            // update_log_entry_by_packet(&packet, i, verdict);
            return verdict;
        }
    }

    for (i = 0; i < rules_count; i++) {
        if (match_rule_packet(&rules[i], &packet)) {
            verdict = rules[i].action;
            update_log_entry_by_packet(&packet, i, verdict);
            if (verdict == NF_ACCEPT && packet.protocol == PROT_TCP) {
                track_two_sided_connection(&packet);
            }
            return verdict;
        }
    }

    update_log_entry_by_packet(&packet, REASON_NO_MATCHING_RULE, FW_POLICY);
    return FW_POLICY;
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

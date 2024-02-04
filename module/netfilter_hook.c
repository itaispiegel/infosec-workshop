#include <linux/ip.h>
#include <linux/list.h>
#include <linux/netfilter.h>

#include "fw.h"
#include "logs.h"
#include "netfilter_hook.h"
#include "parser.h"

extern struct list_head logs_list;
extern size_t logs_count;

extern rule_t rules[MAX_RULES];
extern __u8 rules_count;

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state);

static const struct nf_hook_ops forward_hook = {
    .hook = forward_hook_func,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_FORWARD,
};

static inline bool match_direction(rule_t *rule, packet_t *packet) {
    // This is a bit confusing, but the packets going outside are received
    // on the IN device and vice versa, so the direction is reversed.
    return rule->direction == DIRECTION_ANY ||
           (rule->direction == DIRECTION_IN &&
            strcmp(packet->dev_name, OUT_NET_DEVICE_NAME) == 0) ||
           (rule->direction == DIRECTION_OUT &&
            strcmp(packet->dev_name, IN_NET_DEVICE_NAME) == 0);
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

static inline log_row_t new_log_row_by_packet(packet_t *packet,
                                              reason_t reason) {
    return (log_row_t){
        .timestamp = ktime_get_real_seconds(),
        .protocol = packet->protocol,
        .action = FW_POLICY,
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

static void update_log_entry_by_packet(packet_t *packet, reason_t reason) {
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

    log_entry->log_row = new_log_row_by_packet(packet, reason);
    list_add_tail(&log_entry->list, &logs_list);
    logs_count++;
}

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    __u8 i;
    packet_t packet;

    parse_packet(&packet, skb);

    if (packet.type == PACKET_TYPE_LOOPBACK ||
        packet.type == PACKET_TYPE_UNHANDLED_PROTOCOL) {
        // In this case we want to accept the packet without logging it.
        return NF_ACCEPT;
    } else if (packet.type == PACKET_TYPE_XMAS) {
        update_log_entry_by_packet(&packet, REASON_XMAS_PACKET);
        return NF_DROP;
    }

    // In this case the packet must be a normal packet.
    for (i = 0; i < rules_count; i++) {
        if (match_rule_packet(&rules[i], &packet)) {
            update_log_entry_by_packet(&packet, i);
            return rules[i].action;
        }
    }

    update_log_entry_by_packet(&packet, REASON_NO_MATCHING_RULE);
    return FW_POLICY;
}

int init_netfilter_hook(void) {
    return nf_register_net_hook(&init_net, &forward_hook);
}

void destroy_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &forward_hook);
}

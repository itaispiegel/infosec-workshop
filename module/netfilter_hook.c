#include <linux/ip.h>
#include <linux/list.h>
#include <linux/netfilter.h>

#include "fw.h"
#include "logs.h"
#include "netfilter_hook.h"

extern struct list_head logs_list;
extern size_t logs_count;

extern rule_t rules[MAX_RULES];
extern __u8 rules_count;

struct ports_tuple {
    __be16 sport;
    __be16 dport;
};

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state);

static const struct nf_hook_ops forward_hook = {
    .hook = forward_hook_func,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_FORWARD,
};

static inline bool match_direction(rule_t *rule, struct sk_buff *skb) {
    // This is a bit confusing, but the packets going outside are received
    // on the IN device and vice versa, so the direction is reversed.
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

static inline bool match_rule_skb(rule_t *rule, struct sk_buff *skb) {
    struct iphdr *ip_header = ip_hdr(skb);
    return match_direction(rule, skb) && match_ip_addrs(rule, ip_header) &&
           match_ports(rule, skb) && match_protocol(rule, ip_header) &&
           match_ack(rule, ip_header, tcp_hdr(skb));
}

static inline bool log_match_rule(log_row_t *log_row, rule_t *rule) {
    return log_row->protocol == rule->protocol &&
           log_row->action == rule->action && log_row->src_ip == rule->src_ip &&
           log_row->dst_ip == rule->dst_ip &&
           log_row->src_port == rule->src_port &&
           log_row->dst_port == rule->dst_port;
}

static inline struct ports_tuple ports_from_skb(struct sk_buff *skb) {
    struct ports_tuple p;
    struct iphdr *ip_header = ip_hdr(skb);

    // TODO what happens if the ports are >1023?
    // should we store the specific port or PORT_ABOVE_1023?
    if (ip_header->protocol == PROT_UDP) {
        p.sport = udp_hdr(skb)->source;
        p.dport = udp_hdr(skb)->dest;
    } else if (ip_header->protocol == PROT_TCP) {
        p.sport = tcp_hdr(skb)->source;
        p.dport = tcp_hdr(skb)->dest;
    } else {
        p.sport = 0;
        p.dport = 0;
    }
    return p;
}

static inline log_row_t new_log_row_by_rule(rule_t *rule, reason_t reason) {
    return (log_row_t){
        .timestamp = ktime_get_real_seconds(),
        .protocol = rule->protocol,
        .action = rule->action,
        .src_ip = rule->src_ip,
        .dst_ip = rule->dst_ip,
        .src_port = rule->src_port,
        .dst_port = rule->dst_port,
        .reason = reason,
        .count = 1,
    };
}

static inline log_row_t new_log_row_by_skb(struct sk_buff *skb,
                                           reason_t reason) {
    struct ports_tuple ports = ports_from_skb(skb);
    struct iphdr *ip_header = ip_hdr(skb);

    return (log_row_t){
        .timestamp = ktime_get_real_seconds(),
        .protocol = ip_header->protocol,
        .action = FW_POLICY,
        .src_ip = ip_header->saddr,
        .dst_ip = ip_header->daddr,
        .src_port = ports.sport,
        .dst_port = ports.dport,
        .reason = reason,
        .count = 1,
    };
}

static void update_log_entry_by_matching_rule(rule_t *rule, reason_t reason) {
    struct log_entry *log_entry;
    struct list_head *pos;
    list_for_each(pos, &logs_list) {
        log_entry = list_entry(pos, struct log_entry, list);
        if (log_entry->log_row.reason == reason) {
            log_entry->log_row.count++;
            log_entry->log_row.timestamp = ktime_get_real_seconds();
            return;
        }
    }

    printk(KERN_INFO "Creating a new log entry for rule #%d\n", reason);
    log_entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
    if (log_entry == NULL) { // TODO decide what to do here
        printk(KERN_WARNING
               "Failed to allocate memory for log entry, so ignoring it\n");
        return;
    }

    log_entry->log_row = new_log_row_by_rule(rule, reason);
    list_add_tail(&log_entry->list, &logs_list);
    logs_count++;
}

static bool log_entry_matches_skb(struct log_entry *log_entry,
                                  struct sk_buff *skb) {
    struct ports_tuple ports = ports_from_skb(skb);
    struct iphdr *ip_header = ip_hdr(skb);

    return log_entry->log_row.protocol == ip_header->protocol &&
           log_entry->log_row.src_ip == ip_header->saddr &&
           log_entry->log_row.dst_ip == ip_header->daddr &&
           log_entry->log_row.src_port == ports.sport &&
           log_entry->log_row.dst_port == ports.dport;
}

static void update_log_entry_by_skb(struct sk_buff *skb, reason_t reason) {
    struct log_entry *log_entry;
    struct list_head *pos;
    list_for_each(pos, &logs_list) {
        log_entry = list_entry(pos, struct log_entry, list);
        if (log_entry->log_row.reason == reason &&
            log_entry_matches_skb(log_entry, skb)) {
            log_entry->log_row.count++;
            log_entry->log_row.timestamp = ktime_get_real_seconds();
            return;
        }
    }

    printk(KERN_INFO
           "Creating a new log entry for skb without a matching rule\n");
    log_entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
    if (log_entry == NULL) { // TODO decide what to do here
        printk(KERN_WARNING
               "Failed to allocate memory for log entry, so ignoring it\n");
        return;
    }

    log_entry->log_row = new_log_row_by_skb(skb, reason);
    list_add_tail(&log_entry->list, &logs_list);
    logs_count++;
}

static unsigned int forward_hook_func(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    __u8 i;
    for (i = 0; i < rules_count; i++) {
        if (match_rule_skb(&rules[i], skb)) {
            update_log_entry_by_matching_rule(&rules[i], i);
            return rules[i].action;
        }
    }

    // TODO handle XMAS packets
    // TODO accept any non TCP, UDP and ICMP and IPv6 packets without logging
    // TODOD Accept any loopback packet without logging
    update_log_entry_by_skb(skb, REASON_NO_MATCHING_RULE);
    return FW_POLICY;
}

int init_netfilter_hook(void) {
    return nf_register_net_hook(&init_net, &forward_hook);
}

void destroy_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &forward_hook);
}

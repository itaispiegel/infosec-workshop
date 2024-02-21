#include <linux/inetdevice.h>

#include "parser.h"

static const __be32 LOOPBACK_PREFIX = 0x7f000000;
static const __be32 LOOPBACK_MASK = 0xff000000;

static inline bool is_loopback_addr(__be32 addr) {
    return (addr & LOOPBACK_MASK) == LOOPBACK_PREFIX;
}

void parse_packet(packet_t *packet, struct sk_buff *skb) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    struct in_ifaddr *ifa;
    struct in_device *in_dev;

    ip_header = ip_hdr(skb);

    packet->src_ip = ip_header->saddr;
    packet->dst_ip = ip_header->daddr;
    packet->dev_name = skb->dev->name;
    packet->protocol = ip_header->protocol;

    // Notice that we the store the exact ports, even if they're above 1023.
    if (packet->protocol == PROT_TCP) {
        tcp_header = tcp_hdr(skb);
        packet->src_port = tcp_header->source;
        packet->dst_port = tcp_header->dest;
        packet->ack = tcp_header->ack;
        if (tcp_header->fin && tcp_header->psh && tcp_header->urg) {
            packet->type = PACKET_TYPE_XMAS;
            return;
        } else {
            packet->type = PACKET_TYPE_NORMAL;
        }
    } else if (ip_header->protocol == PROT_UDP) {
        udp_header = udp_hdr(skb);
        packet->type = PACKET_TYPE_NORMAL;
        packet->src_port = udp_header->source;
        packet->dst_port = udp_header->dest;
    } else if (ip_header->protocol == PROT_ICMP) {
        packet->type = PACKET_TYPE_NORMAL;
        packet->src_port = 0;
        packet->dst_port = 0;
    } else {
        packet->type = PACKET_TYPE_UNHANDLED_PROTOCOL;
        // In this case we don't care about the ports and they might contain
        // garbage.
    }

    // TODO: Verify this implementation
    if (is_loopback_addr(packet->src_ip) || is_loopback_addr(packet->dst_ip)) {
        packet->type = PACKET_TYPE_LOOPBACK;
    }

    in_dev = __in_dev_get_rtnl(skb->dev);
    for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_local == ip_header->saddr ||
            ifa->ifa_local == ip_header->daddr) {
            packet->type = PACKET_TYPE_LOCAL;
        }
    }
}

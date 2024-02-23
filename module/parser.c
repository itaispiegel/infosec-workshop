#include <linux/inetdevice.h>

#include "parser.h"
#include "types.h"

#define IN_NET_DEVICE_NAME "enp0s8"
#define OUT_NET_DEVICE_NAME "enp0s9"

static const __be32 LOOPBACK_PREFIX = 0x7f000000;
static const __be32 LOOPBACK_MASK = 0xff000000;

static inline bool is_loopback_addr(__be32 addr) {
    return (addr & LOOPBACK_MASK) == LOOPBACK_PREFIX;
}

static inline direction_t parse_direction(const struct nf_hook_state *state) {
    char *in_dev_name = state->in->name;
    char *out_dev_name = state->out->name;

    if ((in_dev_name != NULL &&
         strcmp(in_dev_name, OUT_NET_DEVICE_NAME) == 0) ||
        (out_dev_name != NULL &&
         strcmp(out_dev_name, IN_NET_DEVICE_NAME) == 0)) {
        return DIRECTION_IN;
    } else if ((in_dev_name != NULL &&
                strcmp(in_dev_name, IN_NET_DEVICE_NAME) == 0) ||
               (out_dev_name != NULL &&
                strcmp(out_dev_name, OUT_NET_DEVICE_NAME) == 0)) {
        return DIRECTION_OUT;
    } else {
        return DIRECTION_ANY;
    }
}

void parse_packet(packet_t *packet, const struct sk_buff *skb,
                  const struct nf_hook_state *state) {

    packet->ip_header = ip_hdr(skb);

    packet->src_ip = packet->ip_header->saddr;
    packet->dst_ip = packet->ip_header->daddr;
    packet->protocol = packet->ip_header->protocol;
    packet->direction = parse_direction(state);

    // TODO: Support local packets.
    // Notice that we the store the exact ports, even if they're above 1023.
    if (packet->protocol == PROT_TCP) {
        packet->tcp_header = tcp_hdr(skb);
        packet->src_port = packet->tcp_header->source;
        packet->dst_port = packet->tcp_header->dest;
        packet->ack = packet->tcp_header->ack;
        if (packet->tcp_header->fin && packet->tcp_header->psh &&
            packet->tcp_header->urg) {
            packet->type = PACKET_TYPE_XMAS;
            return;
        } else {
            packet->type = PACKET_TYPE_NORMAL;
        }
    } else if (packet->ip_header->protocol == PROT_UDP) {
        packet->udp_header = udp_hdr(skb);
        packet->type = PACKET_TYPE_NORMAL;
        packet->src_port = packet->udp_header->source;
        packet->dst_port = packet->udp_header->dest;
    } else if (packet->ip_header->protocol == PROT_ICMP) {
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
}

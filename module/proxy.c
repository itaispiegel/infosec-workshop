#include <net/tcp.h>

#include "fw.h"
#include "proxy.h"

static void fix_checksum(struct sk_buff *skb, struct iphdr *ip_header,
                         struct tcphdr *tcp_header) {
    // Fix TCP header checksum
    int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check =
        tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,
                     csum_partial((char *)tcp_header, tcplen, 0));

    // Fix IP header checksum
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    skb->ip_summed = CHECKSUM_NONE;

    // Fix packet linearization
    // skb->csum_valid = 0;
    // if (skb_linearize(skb) < 0)
    // {
    //     /* Handle error
    // }
}

void proxy_client_request(packet_t *packet, struct sk_buff *skb) {
    if (packet->direction == DIRECTION_OUT &&
        packet->dst_port == HTTP_PORT_BE) {
        packet->tcp_header->dest = HTTP_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
}

void proxy_server_response(packet_t *packet, struct sk_buff *skb) {
    if (packet->direction == DIRECTION_IN &&
        packet->src_port == HTTP_PROXY_PORT_BE) {
        packet->src_port = HTTP_PORT_BE;
        packet->tcp_header->source = HTTP_PORT_BE;
        packet->src_ip = 0x0202010a;
        packet->ip_header->saddr = 0x0202010a;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
}

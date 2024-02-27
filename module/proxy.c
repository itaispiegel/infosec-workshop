#include <net/tcp.h>

#include "proxy.h"
#include "tcp_conntrack.h"

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

enum proxy_response handle_proxy_packet(packet_t *packet, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    if (packet->protocol != PROT_TCP) {
        return NOT_PROXY_PACKET;
    }

    switch (state->hook) {
    case NF_INET_PRE_ROUTING:
        switch (packet->direction) {
        case DIRECTION_OUT:
            reroute_client_to_server_packet(packet, skb);
            return CONTINUE;
        case DIRECTION_IN:
            if (is_server_to_proxy_response(packet, skb)) {
                return ACCEPT_IMMEDIATELY;
            }
            // This case might handle packets designated to the firewall host,
            // and according to the guidelines we can ignore them.
            return CONTINUE;
        case DIRECTION_ANY:
            return DROP_IMMEDIATELY;
        }
    case NF_INET_LOCAL_OUT:
        switch (packet->direction) {
        case DIRECTION_OUT:
            if (is_proxy_to_server_request(packet, skb)) {
                return ACCEPT_IMMEDIATELY;
            }
            printk(KERN_DEBUG
                   "Dropping packet that wasn't sent by the proxy\n");
            return DROP_IMMEDIATELY;
        case DIRECTION_IN:
            reroute_proxy_to_client_packet(packet, skb);
            if (packet->src_ip == 0 && packet->src_port) {
                printk("Dropping packet with unknown source\n");
                return DROP_IMMEDIATELY;
            }
            return CONTINUE;
        case DIRECTION_ANY:
            return DROP_IMMEDIATELY;
        }
    }
    return CONTINUE; // This line is never reached
}

void reroute_client_to_server_packet(packet_t *packet, struct sk_buff *skb) {
    __be16 proxy_port = 0;
    if (packet->dst_port == HTTP_PORT_BE) {
        proxy_port = HTTP_PROXY_PORT_BE;
    } else if (packet->dst_port == FTP_PORT_BE) {
        proxy_port = FTP_PROXY_PORT_BE;
    }
    if (proxy_port != 0) {
        packet->tcp_header->dest = proxy_port;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
}

void reroute_proxy_to_client_packet(packet_t *packet, struct sk_buff *skb) {
    struct socket_address server_addr;
    struct socket_address client_addr = {.addr = packet->dst_ip,
                                         .port = packet->dst_port};
    if (packet->src_port == HTTP_PROXY_PORT_BE ||
        packet->src_port == FTP_PROXY_PORT_BE) {
        server_addr = lookup_server_address_by_client_address(client_addr);
        packet->src_ip = server_addr.addr;
        packet->ip_header->saddr = server_addr.addr;
        packet->src_port = server_addr.port;
        packet->tcp_header->source = server_addr.port;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
}

bool is_server_to_proxy_response(packet_t *packet, struct sk_buff *skb) {
    __be16 proxy_port = packet->dst_port;
    struct tcp_connection *tcp_conn =
        lookup_tcp_connection_by_proxy_port(proxy_port);
    return packet->dst_ip == FW_EXTERNAL_PROXY_IP && tcp_conn != NULL;
}

bool is_proxy_to_server_request(packet_t *packet, struct sk_buff *skb) {
    __be16 proxy_port = packet->src_port;
    struct tcp_connection *tcp_conn =
        lookup_tcp_connection_by_proxy_port(proxy_port);
    return packet->src_ip == FW_EXTERNAL_PROXY_IP && tcp_conn != NULL;
}

#include <net/tcp.h>

#include "proxy.h"
#include "tcp_conntrack.h"

static inline void _fix_tcp_checksum(struct iphdr *ip_header,
                                     struct tcphdr *tcp_header) {
    int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check =
        tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,
                     csum_partial((char *)tcp_header, tcplen, 0));
}

static inline void _fix_ip_checksum(struct sk_buff *skb,
                                    struct iphdr *ip_header) {
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    skb->ip_summed = CHECKSUM_NONE;
}

static void fix_checksum(struct sk_buff *skb, struct iphdr *ip_header,
                         struct tcphdr *tcp_header) {
    _fix_tcp_checksum(ip_header, tcp_header);
    _fix_ip_checksum(skb, ip_header);
}

enum proxy_response handle_proxy_packet(packet_t *packet, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    if (packet->protocol != PROT_TCP) {
        return CONTINUE;
    }

    switch (state->hook) {
    case NF_INET_POST_ROUTING:
        return handle_ftp_data_connection_snat(packet, skb);
    case NF_INET_PRE_ROUTING:
        switch (packet->direction) {
        case DIRECTION_OUT:
            return reroute_client_to_server_packet(packet, skb);
        case DIRECTION_IN:
            if (is_server_to_proxy_response(packet, skb)) {
                return ACCEPT_IMMEDIATELY;
            }
            // This case might handle packets designated to the firewall host,
            // and according to the guidelines we can ignore them.
            return reroute_server_to_client_ftp_data(packet, skb);
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

enum proxy_response reroute_client_to_server_packet(packet_t *packet,
                                                    struct sk_buff *skb) {
    if (packet->dst_port == HTTP_PORT_BE) {
        packet->tcp_header->dest = HTTP_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    } else if (packet->dst_port == FTP_CONTROL_PORT_BE) {
        packet->tcp_header->dest = FTP_CONTROL_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
    return CONTINUE;
}

enum proxy_response reroute_proxy_to_client_packet(packet_t *packet,
                                                   struct sk_buff *skb) {
    struct socket_address server_addr;
    struct socket_address client_addr = {.addr = packet->dst_ip,
                                         .port = packet->dst_port};
    if (packet->src_port == HTTP_PROXY_PORT_BE ||
        packet->src_port == FTP_CONTROL_PROXY_PORT_BE) {
        if ((server_addr = lookup_server_address_by_client_address(client_addr))
                .addr == 0) {
            printk(KERN_DEBUG "Dropping unrelated packet\n");
            return DROP_IMMEDIATELY;
        }
        packet->src_ip = packet->ip_header->saddr = server_addr.addr;
        packet->src_port = packet->tcp_header->source = server_addr.port;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
    return CONTINUE;
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

enum proxy_response reroute_server_to_client_ftp_data(packet_t *packet,
                                                      struct sk_buff *skb) {
    struct socket_address server_addr = {.addr = packet->src_ip,
                                         .port = packet->src_port};
    struct socket_address client_addr;
    if (packet->src_port == FTP_DATA_PORT_BE) {
        client_addr = lookup_server_address_by_client_address(server_addr);
        if (client_addr.addr == 0) {
            printk(KERN_DEBUG "Dropping unrelated FTP data packet\n");
            return DROP_IMMEDIATELY;
        }

        packet->dst_ip = client_addr.addr;
        packet->dst_port = client_addr.port;
        packet->tcp_header->dest = client_addr.port;
        packet->ip_header->daddr = client_addr.addr;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
    }
    return CONTINUE;
}

enum proxy_response handle_ftp_data_connection_snat(packet_t *packet,
                                                    struct sk_buff *skb) {
    if (packet->direction == DIRECTION_OUT &&
        packet->dst_port == FTP_DATA_PORT_BE) {
        packet->ip_header->saddr = FW_EXTERNAL_PROXY_IP;
        fix_checksum(skb, packet->ip_header, packet->tcp_header);
        return CONTINUE;
    }
    return ACCEPT_IMMEDIATELY; // In this case we can safely assume that the
                               // packet was already accepted by the
                               // prerouting hook.
}

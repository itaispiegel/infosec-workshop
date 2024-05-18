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
        return CONTINUE;
    case NF_INET_PRE_ROUTING:
        switch (packet->direction) {
        case DIRECTION_OUT:
            return handle_internal_to_external_packet(packet, skb);
        case DIRECTION_IN:
            return handle_external_to_internal_packet(packet, skb);
        case DIRECTION_ANY:
            return DROP_IMMEDIATELY;
        }
    case NF_INET_LOCAL_OUT:
        switch (packet->direction) {
        case DIRECTION_OUT:
            return handle_out_to_external_packet(packet, skb);
        case DIRECTION_IN:
            return handle_out_to_internal_packet(packet, skb);
        case DIRECTION_ANY:
            return DROP_IMMEDIATELY;
        }
    case NF_INET_LOCAL_IN:
        break;
    }
    return CONTINUE; // This line is never reached
}

enum proxy_response handle_internal_to_external_packet(packet_t *packet,
                                                       struct sk_buff *skb) {
    struct tcp_connection_node *conn_node;
    if (packet->dst_port == HTTP_PORT_BE) {
        packet->tcp_header->dest = HTTP_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        goto fix_checksum_and_continue;
    } else if (packet->dst_port == FTP_CONTROL_PORT_BE) {
        packet->tcp_header->dest = FTP_CONTROL_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        goto fix_checksum_and_continue;
    } else if (packet->dst_port == SMTP_PORT_BE) {
        packet->tcp_header->dest = SMTP_PROXY_PORT_BE;
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        goto fix_checksum_and_continue;
    } else if (packet->src_port == NIFI_PORT_BE) {
        conn_node = lookup_tcp_connection_node(
            (struct socket_address){.addr = packet->dst_ip,
                                    .port = packet->dst_port},
            (struct socket_address){.addr = packet->src_ip,
                                    .port = packet->src_port});
        if (conn_node == NULL) {
            return DROP_IMMEDIATELY; // Drop unrelated packet
        }
        packet->ip_header->daddr = FW_INTERNAL_PROXY_IP;
        packet->tcp_header->dest = conn_node->conn.proxy_port;
        goto fix_checksum_and_continue;
    }
    return CONTINUE;
fix_checksum_and_continue:
    fix_checksum(skb, packet->ip_header, packet->tcp_header);
    return CONTINUE;
}

enum proxy_response handle_external_to_internal_packet(packet_t *packet,
                                                       struct sk_buff *skb) {
    struct tcp_connection_node *conn_node;
    if (packet->dst_port == NIFI_PORT_BE) {
        packet->ip_header->daddr = FW_EXTERNAL_PROXY_IP;
        packet->tcp_header->dest = NIFI_PROXY_PORT_BE;
        goto fix_checksum_and_continue;
    } else if (packet->src_port == HTTP_PORT_BE ||
               packet->src_port == SMTP_PORT_BE ||
               packet->src_port == FTP_CONTROL_PORT_BE) {
        conn_node = lookup_tcp_connection_node(
            (struct socket_address){.addr = packet->dst_ip,
                                    .port = packet->dst_port},
            (struct socket_address){.addr = packet->src_ip,
                                    .port = packet->src_port});
        if (conn_node == NULL) {
            return DROP_IMMEDIATELY; // Drop unrelated packet
        }
        packet->ip_header->daddr = FW_EXTERNAL_PROXY_IP;
        packet->tcp_header->dest = conn_node->conn.proxy_port;
        goto fix_checksum_and_continue;
    }
    return CONTINUE;
fix_checksum_and_continue:
    fix_checksum(skb, packet->ip_header, packet->tcp_header);
    return CONTINUE;
}

enum proxy_response handle_out_to_external_packet(packet_t *packet,
                                                  struct sk_buff *skb) {
    struct tcp_connection *conn;
    struct socket_address internal_addr;
    struct socket_address external_addr = {.addr = packet->dst_ip,
                                           .port = packet->dst_port};

    if (packet->src_port == NIFI_PROXY_PORT_BE) {
        if ((internal_addr = lookup_peer_address(external_addr)).addr == 0) {
            return DROP_IMMEDIATELY;
        }
        packet->src_ip = packet->ip_header->saddr = internal_addr.addr;
        packet->src_port = packet->tcp_header->source = internal_addr.port;
        goto fix_checksum_and_continue;
    } else if (packet->src_ip == FW_EXTERNAL_PROXY_IP) {
        if ((conn = lookup_tcp_connection_by_proxy_port(packet->src_port)) ==
            NULL) {
            return DROP_IMMEDIATELY; // Drop unrelated packet
        }
        packet->ip_header->saddr = packet->src_ip = conn->saddr.addr;
        packet->tcp_header->source = packet->src_port = conn->saddr.port;
        goto fix_checksum_and_continue;
    }
    return CONTINUE;
fix_checksum_and_continue:
    fix_checksum(skb, packet->ip_header, packet->tcp_header);
    return CONTINUE;
}

enum proxy_response handle_out_to_internal_packet(packet_t *packet,
                                                  struct sk_buff *skb) {
    struct tcp_connection *conn;
    struct socket_address external_addr;
    struct socket_address internal_addr = {.addr = packet->dst_ip,
                                           .port = packet->dst_port};
    if (packet->src_port == HTTP_PROXY_PORT_BE ||
        packet->src_port == FTP_CONTROL_PROXY_PORT_BE ||
        packet->src_port == SMTP_PROXY_PORT_BE) {
        if ((external_addr = lookup_peer_address(internal_addr)).addr == 0) {
            return DROP_IMMEDIATELY; // Drop unrelated packet
        }
        packet->src_ip = packet->ip_header->saddr = external_addr.addr;
        packet->src_port = packet->tcp_header->source = external_addr.port;
        goto fix_checksum_and_continue;
    } else if (packet->dst_port == NIFI_PORT_BE) {
        if ((conn = lookup_tcp_connection_by_proxy_port(packet->src_port)) ==
            NULL) {
            return DROP_IMMEDIATELY; // Drop unrelated packet
        }
        packet->ip_header->saddr = packet->src_ip = conn->saddr.addr;
        packet->tcp_header->source = packet->src_port = conn->saddr.port;
        goto fix_checksum_and_continue;
    }
    return CONTINUE;
fix_checksum_and_continue:
    fix_checksum(skb, packet->ip_header, packet->tcp_header);
    return CONTINUE;
}

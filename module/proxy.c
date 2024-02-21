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

void proxy_packet(packet_t *packet, struct sk_buff *skb) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    if (packet->dst_port == HTTP_PORT_BE) {
        printk(KERN_DEBUG
               "(No ACK) Changing destination port from 80 to 800\n");
        tcp_header->dest = HTTP_PROXY_PORT_BE;
        ip_header->daddr = 0x0301010a;
    } else if (packet->src_port == HTTP_PROXY_PORT_BE) {
        printk(KERN_DEBUG "(No ACK) Changing source port from 800 to 80\n");
        tcp_header->source = HTTP_PORT_BE;
        ip_header->saddr = 0x0202010a;
    }
    fix_checksum(skb, ip_header, tcp_header);
}

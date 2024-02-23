#ifndef _PROXY_H
#define _PROXY_H

#include <linux/ip.h>

#include "parser.h"

#define HTTP_PORT_BE (be16_to_cpu(80))
#define HTTP_PROXY_PORT_BE (be16_to_cpu(800))
#define FTP_PORT_BE (be16_to_cpu(21))
#define FTP_PROXY_PORT_BE (be16_to_cpu(210))

#define FW_INTERNAL_PROXY_IP 0x0301010a
#define FW_EXTERNAL_PROXY_IP 0x0302010a

/**
 * Receives a TCP packet sent from a client in the internal network, to a server
 * in the external network.
 * If the packet is an HTTP or FTP packet, the destination IP and port will be
 * changed to the proxy process running in the userspace. The SKB's addresses
 * will change to the new addresses, but the packet struct will not. The IPv4
 * and TCP checksums are guaranteed to be fixed by the function.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
void reroute_client_to_server_packet(packet_t *packet, struct sk_buff *skb);

/**
 * Receives a TCP packet sent from the firewall host to a client in the internal
 * network. If this packet is from one of the userspace proxy, the source
 * address and port will be changed to the address and port of the server in the
 * external network that sent the packet. The server address is matched by the
 * connection table. Both the SKB and packet structs will be changed, and the
 * IPv4 and TCP checksums are guaranteed to be fixed.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
void reroute_proxy_to_client_packet(packet_t *packet, struct sk_buff *skb);

/**
 * Receives a packet sent from the external network to the firewall host, and
 * returns whether it's designated to the proxy.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @return Whether the packet is designated to the proxy.
 */
bool is_server_to_proxy_response(packet_t *packet, struct sk_buff *skb);

/**
 * Receives a packet sent from firewall host to the external network, and
 * returns whether it was sent from the proxy.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @return Whether the packet is sent from the proxy.
 */
bool is_proxy_to_server_request(packet_t *packet, struct sk_buff *skb);

#endif // _PROXY_H

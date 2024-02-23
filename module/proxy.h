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
 * Receives a TCP packet received by the PRE_ROUTING hook.
 * If the packet is an HTTP or FTP packet sent from a client in the internal
 * network, to a server in the external network, the destination IP and port
 * will be changed to the proxy process running in the userspace. The SKB's
 * addresses will change to the new addresses, but the packet struct will not.
 * The IPv4 and TCP checksums are guaranteed to be fixed by the function.
 */
void proxy_client_request(packet_t *packet, struct sk_buff *skb);

/**
 * Receives a TCP packet received by the LOCAL_OUT hook.
 * If the packet is from one of the userspace proxy processes to a client in the
 * internal network, the source address and port will be changed to the address
 * and port of the server in the external network that sent the packet.
 * Both the SKB and packet structs will be changed, and the IPv4 and TCP
 * checksums are guaranteed to be fixed.
 */
void proxy_server_response(packet_t *packet, struct sk_buff *skb);

#endif // _PROXY_H

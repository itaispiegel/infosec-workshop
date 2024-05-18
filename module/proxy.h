#ifndef _PROXY_H
#define _PROXY_H

#include <linux/ip.h>

#include "parser.h"

#define HTTP_PORT_BE (be16_to_cpu(80))
#define HTTP_PROXY_PORT_BE (be16_to_cpu(800))
#define FTP_DATA_PORT_BE (be16_to_cpu(20))
#define FTP_CONTROL_PORT_BE (be16_to_cpu(21))
#define FTP_CONTROL_PROXY_PORT_BE (be16_to_cpu(210))
#define NIFI_PORT_BE (be16_to_cpu(8443))
#define NIFI_PROXY_PORT_BE (be16_to_cpu(8444))
#define SMTP_PORT_BE (be16_to_cpu(25))
#define SMTP_PROXY_PORT_BE (be16_to_cpu(250))

#define FW_INTERNAL_PROXY_IP 0x0301010a
#define FW_EXTERNAL_PROXY_IP 0x0302010a

/**
 * The possible responses to a packet that is handled by the proxy.
 * ACCEPT_IMMEDIATELY: The packet is accepted and the connection isn't tracked.
 * DROP_IMMEDIATELY: The packet is dropped and the connection isn't tracked.
 * CONTINUE: Continue processing the packet.
 */
enum proxy_response { ACCEPT_IMMEDIATELY, DROP_IMMEDIATELY, CONTINUE };

/**
 * Receives any type of packet and handles it according to the proxy, and
 * returns the verdict. This function modifies the packet and skb structs
 * according to the verdict, but keeps the invariant that the addresses
 * in the packet struct are of the client and the server.
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @param state The state of the Netfilter hook.
 * @return The verdict.
 */
enum proxy_response handle_proxy_packet(packet_t *packet, struct sk_buff *skb,
                                        const struct nf_hook_state *state);

/**
 * Receives a TCP packet sent from a host in the internal network, to a host
 * in the external network.
 * If the packet is an HTTP, FTP or SMTP packet, the destination IP and port
 * will be changed to the proxy process running in the userspace. The SKB's
 * addresses will change to the new addresses, but the packet struct will not.
 * The IPv4 and TCP checksums are guaranteed to be fixed by the function. On the
 * other hand, if the packet is sent from a Nifi server, we change the
 * destination to the proxy.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
enum proxy_response handle_internal_to_external_packet(packet_t *packet,
                                                       struct sk_buff *skb);

/**
 * Receives a TCP packet sent from a host in the external network, to a
 * host in the internal network.
 * If the packet is a Nifi packet, we re-route it to the proxy.
 * Otherwise, if the packet is sent from an HTTP, FTP or SMTP server,
 * we re-route it to the proxy.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
enum proxy_response handle_external_to_internal_packet(packet_t *packet,
                                                       struct sk_buff *skb);

/**
 * Receives a TCP packet sent from the firewall host to a host in the external
 * network.
 * If the packet is sent from one of the proxied protocols, we lookup the
 * client's address and change the source to it.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
enum proxy_response handle_out_to_external_packet(packet_t *packet,
                                                  struct sk_buff *skb);

/**
 * Receives a TCP packet sent from the firewall host to a host in the internal
 * network. If this packet is from one of the userspace proxies, the source
 * address and port will be changed to the address and port of the server in the
 * external network that sent the packet. The server address is matched by the
 * connection table. Both the SKB and packet structs will be changed, and the
 * IPv4 and TCP checksums are guaranteed to be fixed.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 */
enum proxy_response handle_out_to_internal_packet(packet_t *packet,
                                                  struct sk_buff *skb);

#endif // _PROXY_H

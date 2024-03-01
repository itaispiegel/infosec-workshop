#ifndef _PROXY_H
#define _PROXY_H

#include <linux/ip.h>

#include "parser.h"

#define HTTP_PORT_BE (be16_to_cpu(80))
#define HTTP_PROXY_PORT_BE (be16_to_cpu(800))
#define FTP_DATA_PORT_BE (be16_to_cpu(20))
#define FTP_CONTROL_PORT_BE (be16_to_cpu(21))
#define FTP_CONTROL_PROXY_PORT_BE (be16_to_cpu(210))

#define FW_INTERNAL_PROXY_IP 0x0301010a
#define FW_EXTERNAL_PROXY_IP 0x0302010a

/**
 * The possible responses to a packet that is handled by the proxy.
 * ACCEPT_IMMEDIATELY: The packet is accepted and the connection isn't tracked.
 * DROP_IMMEDIATELY: The packet is dropped and the connection isn't tracked.
 * CONTINUE: The packet isn't handled by the proxy.
 */
enum proxy_response {
    ACCEPT_IMMEDIATELY,
    DROP_IMMEDIATELY,
    CONTINUE,
};

/**
 * Receives any type of packet and handle it according to the proxy, and returns
 * the action to be taken. This function modifies the packet and skb structs
 * according to the action it takes, but keeps the invariant that the addresses
 * in the packet struct are of the client and the server.
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @param state The state of the Netfilter hook.
 * @return The action to be taken.
 */
enum proxy_response handle_proxy_packet(packet_t *packet, struct sk_buff *skb,
                                        const struct nf_hook_state *state);

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
enum proxy_response reroute_client_to_server_packet(packet_t *packet,
                                                    struct sk_buff *skb);

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
enum proxy_response reroute_proxy_to_client_packet(packet_t *packet,
                                                   struct sk_buff *skb);

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

/**
 * Receives a packet sent from the external network to the firewall host, and
 * if it's an FTP data packet (port 20), the destination IP and port will be
 * changed from the proxy's to the client's. The addresses will be changed both
 * in the SKB and the packet struct.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @return The action to be taken.
 */
enum proxy_response reroute_server_to_client_ftp_data(packet_t *packet,
                                                      struct sk_buff *skb);

/**
 * Receives a packet sent forwarded from the client to an external server, and
 * changes the source IP to be the proxy's, if it's an FTP data packet (dest
 * port 20). The address will be changed in the SKB and not in the packet
 * struct.
 *
 * @param packet The packet struct that represents the packet.
 * @param skb The SKB struct that represents the packet.
 * @return The action to be taken.
 */
enum proxy_response handle_ftp_data_connection_snat(packet_t *packet,
                                                    struct sk_buff *skb);

#endif // _PROXY_H

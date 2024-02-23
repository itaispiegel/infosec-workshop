#ifndef _TCP_CONNECTIONS_H
#define _TCP_CONNECTIONS_H

#include <linux/hash.h>
#include <linux/hashtable.h>

#include "parser.h"
#include "types.h"

#define DEVICE_NAME_CONNTRACK "conn"
#define DEVICE_NAME_PROXY_PORT "proxy_port"

struct socket_address {
    __be32 addr;
    __be16 port;
} __attribute__((packed));

struct tcp_connection {
    struct socket_address saddr;
    struct socket_address daddr;
    __be16 proxy_port; // Deprecated: defined only for proxied connections, and
                       // set by the userspace.
    __u8 state;        // Use the states from <net/tcp_states.h>
} __attribute__((packed));

/**
 * A TCP connection node in the connections hash table.
 */
struct tcp_connection_node {
    struct tcp_connection conn;
    struct hlist_node node;
};

/**
 * Looks up the connection node in the connections hash table.
 * @param saddr The source address of the connection.
 * @param daddr The destination address of the connection.
 * @return The connection node if found, NULL otherwise.
 */
struct tcp_connection_node *
lookup_tcp_connection_node(struct socket_address saddr,
                           struct socket_address daddr);

/**
 * @deprecated
 */
struct socket_address
lookup_client_address_by_proxy_port(__be16 proxy_port); // Deprecated

/**
 * Looks up the server address in a session with the given client.
 * @param client_addr The client address.
 * @return The server address if found, 0 otherwise.
 */
struct socket_address
lookup_server_address_by_client_address(struct socket_address client_addr);

/**
 * Extracts a one-sided session from the packet and persists it in the hash
 * table. If the direction is OUTGOING, the direction is src-->dest. If it's
 * INCOMING, the direction is dest-->src.
 * @param packet The packet to extract the session from.
 * @param direction The direction of the packet.
 */
void track_one_sided_connection(packet_t *packet, direction_t direction);

/**
 * Persists two connections in the hash table: src --> dest and dest --> src.
 */
void track_two_sided_connection(packet_t *packet);

/**
 * Matches the packet to a connection in the hash table and updates the
 * connection's state according to the TCP FSM.
 * @param packet The packet to match.
 * @return True if the packet matches a connection in the hash table, false
 * otherwise.
 */
bool match_connection_and_update_state(packet_t packet);

/**
 * Initializes the TCP connections hash table and devices.
 * @param fw_sysfs_class The class to create the devices in.
 */
int init_tcp_conntrack(struct class *fw_sysfs_class);

/**
 * Destroys the TCP connections hash table and devices.
 * @param fw_sysfs_class The class to destroy the devices from.
 */
void destroy_tcp_conntrack(struct class *fw_sysfs_class);

#endif // _TCP_CONNECTIONS_H

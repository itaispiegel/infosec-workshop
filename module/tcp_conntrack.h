#ifndef _TCP_CONNECTIONS_H
#define _TCP_CONNECTIONS_H

#include <linux/hash.h>
#include <linux/hashtable.h>

#include "parser.h"
#include "types.h"

#define DEVICE_NAME_CONNTRACK "conn"
#define DEVICE_NAME_PROXY_PORT "proxy_port"
#define DEVICE_NAME_RELATED_CONNS "related_conns"

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
 * The function looks up the address pair in the hash table, so the runtime is
 * O(1).
 * @param saddr The source address of the connection.
 * @param daddr The destination address of the connection.
 * @return The connection node if found, NULL otherwise.
 */
struct tcp_connection_node *
lookup_tcp_connection_node(struct socket_address saddr,
                           struct socket_address daddr);

/**
 * Looks up the connection in the connections hash table by the TCP port used by
 * the proxy to communicate with the server.
 * The key of the hash table is the hash of the addresses, so in this function
 * we have to iterate all items of the table to find the relevant connection, so
 * the runtime is O(n).
 * TODO: Optimize this function to run in O(1) time.
 * @param proxy_port The proxy port.
 * @return The connection if found, NULL otherwise.
 */
struct tcp_connection *lookup_tcp_connection_by_proxy_port(__be16 proxy_port);

/**
 * Looks up the server address in a session with the given client.
 * The key of the hash table is the hash of both addresses, so to find the
 * connection we have to iterate all items and find the matching one, so the
 * runtime is O(n).
 * TODO: Optimize this function to run in O(1) time.
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
 * @param packet The packet to extract the sessions from.
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

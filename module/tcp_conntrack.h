#ifndef _TCP_CONNECTIONS_H
#define _TCP_CONNECTIONS_H

#include <linux/hash.h>
#include <linux/hashtable.h>

#include "parser.h"

#define DEVICE_NAME_CONNTRACK "conn"
#define DEVICE_NAME_PROXY_PORT "proxy_port"

enum connection_direction {
    NONE = 0,
    INCOMING = 1,
    OUTGOING = 2,
} __attribute__((packed));

struct socket_address {
    __be32 addr;
    __be16 port;
} __attribute__((packed));

struct tcp_connection {
    struct socket_address saddr;
    struct socket_address daddr;
    __be16 proxy_port; // Defined only for proxied connections, and set by the
                       // userspace.
    __u8 state;        // Use the states from <net/tcp_states.h>
} __attribute__((packed));

struct tcp_connection_node {
    struct tcp_connection conn;
    struct hlist_node node;
};

void track_connection(packet_t *packet);
bool match_connection_and_update_state(packet_t packet);
int init_tcp_conntrack(struct class *fw_sysfs_class);
void destroy_tcp_conntrack(struct class *fw_sysfs_class);

#endif // _TCP_CONNECTIONS_H

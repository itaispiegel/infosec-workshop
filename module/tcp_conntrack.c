#include "tcp_conntrack.h"

#include <linux/jhash.h>
#include <linux/siphash.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "fw.h"

static DECLARE_HASHTABLE(tcp_connections, 8);

static int conns_dev_major;
static struct device *conns_dev;

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static ssize_t conns_table_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
    struct tcp_connection_node *cur;
    unsigned i;
    __u16 offset = 0;
    hash_for_each(tcp_connections, i, cur, node) {
        memcpy(buf + offset, &cur->conn, sizeof(struct tcp_connection));
        offset += sizeof(struct tcp_connection);
    }
    return offset;
}

static DEVICE_ATTR(conns, S_IRUSR, conns_table_show, NULL);

static inline bool match_conn_addrs(struct tcp_connection *conn,
                                    struct socket_address *saddr,
                                    struct socket_address *daddr) {
    return conn->saddr.addr == saddr->addr && conn->saddr.port == saddr->port &&
           conn->daddr.addr == daddr->addr && conn->daddr.port == daddr->port;
}

static void tcp_fsm_step(struct tcp_connection *conn,
                         enum connection_direction direction,
                         struct tcphdr *tcp_header) {
    if (direction == INCOMING) {
        switch (conn->state) {
        case TCP_CLOSE:
            // Originally this is TCP_LISTEN, but we don't handle this state,
            // since the firewall runs in the middle
            if (tcp_header->syn) {
                conn->state = TCP_SYN_RECV;
                return;
            }
            break;
        case TCP_SYN_SENT:
            if (tcp_header->syn && tcp_header->ack) {
                conn->state = TCP_ESTABLISHED;
                return;
            }
            if (tcp_header->syn) { // Simultaneous open
                conn->state = TCP_SYN_RECV;
                return;
            }
            break;
        case TCP_SYN_RECV:
            if (tcp_header->ack) {
                conn->state = TCP_ESTABLISHED;
                return;
            }
            break;
        case TCP_ESTABLISHED:
            if (tcp_header->fin) {
                conn->state = TCP_CLOSE_WAIT;
                return;
            }
            break;
        case TCP_FIN_WAIT1:
            if (tcp_header->fin && tcp_header->ack) {
                conn->state = TCP_CLOSE; // Originally this goes to TIME_WAIT,
                                         // but we don't handle this state
                return;
            }
            if (tcp_header->ack) {
                conn->state = TCP_FIN_WAIT2;
                return;
            }
            if (tcp_header->fin) {
                conn->state = TCP_CLOSING;
                return;
            }
            break;
        case TCP_FIN_WAIT2:
            if (tcp_header->fin) {
                conn->state = TCP_CLOSE; // Originally this goes to TIME_WAIT,
                                         // but we don't handle this state
                return;
            }
            break;
        case TCP_CLOSING:
            if (tcp_header->ack) {
                conn->state = TCP_CLOSE; // Originally this goes to TIME_WAIT,
                                         // but we don't handle this state
                return;
            }
            break;
        case TCP_LAST_ACK:
            if (tcp_header->ack) {
                conn->state = TCP_CLOSE;
                return;
            }
            break;
        }
    } else if (direction == OUTGOING) {
        switch (conn->state) {
        case TCP_CLOSE:
            if (tcp_header->syn) {
                conn->state = TCP_SYN_SENT;
                return;
            }
            break;
        case TCP_SYN_RECV:
            if (tcp_header->syn && tcp_header->ack) {
                conn->state = TCP_ESTABLISHED;
                return;
            }
            break;
        case TCP_ESTABLISHED:
            if (tcp_header->fin) {
                conn->state = TCP_FIN_WAIT1;
                return;
            }
            break;
        case TCP_CLOSE_WAIT:
            if (tcp_header->fin) {
                conn->state = TCP_LAST_ACK;
                return;
            }
            break;
        }
    }
}

bool init_connection(struct socket_address saddr, struct socket_address daddr,
                     struct tcphdr *tcp_header, __u32 hash,
                     enum connection_direction direction) {
    struct tcp_connection_node *conn =
        kmalloc(sizeof(struct tcp_connection_node), GFP_KERNEL);
    if (!conn) {
        return false;
    }

    conn->conn = (struct tcp_connection){
        .state = TCP_CLOSE,
        .saddr = saddr,
        .daddr = daddr,
    };
    tcp_fsm_step(&conn->conn, direction, tcp_header);
    hash_add(tcp_connections, &conn->node, hash);
    return true;
}

static inline void close_connection(struct tcp_connection_node *conn) {
    hash_del(&conn->node);
    kfree(conn);
}

static inline __u32 hash_conn_addrs(struct socket_address saddr,
                                    struct socket_address daddr) {
    return jhash2((u32[4]){saddr.addr, saddr.port, daddr.addr, daddr.port}, 4,
                  0);
}

static inline bool update_connection_state(struct tcphdr *tcp_header,
                                           struct socket_address saddr,
                                           struct socket_address daddr,
                                           direction_t direction) {
    struct tcp_connection_node *conn;
    __u32 hash = hash_conn_addrs(saddr, daddr);

    hash_for_each_possible(tcp_connections, conn, node, hash) {
        if (match_conn_addrs(&conn->conn, &saddr, &daddr)) {
            tcp_fsm_step(&conn->conn, direction, tcp_header);
            if (conn->conn.state == TCP_CLOSE) {
                printk(KERN_DEBUG "Removing closed connection from table "
                                  "%pI4:%u --> %pI4:%u\n",
                       &saddr.addr, saddr.port, &daddr.addr, daddr.port);
                close_connection(conn);
            }
            return true;
        }
    }
    return false;
}

void track_connection(packet_t *packet) {
    struct tcp_connection_node *conn, *inverse_conn;
    struct socket_address saddr = {.addr = packet->src_ip,
                                   .port = packet->src_port};
    struct socket_address daddr = {.addr = packet->dst_ip,
                                   .port = packet->dst_port};
    __u32 hash = hash_conn_addrs(saddr, daddr);
    __u32 inverse_hash = hash_conn_addrs(daddr, saddr);

    bool outgoing_match = false, incoming_match = false;

    hash_for_each_possible(tcp_connections, conn, node, hash) {
        if (match_conn_addrs(&conn->conn, &saddr, &daddr)) {
            outgoing_match = true;
            break;
        }
    }

    if (!outgoing_match) {
        conn = kmalloc(sizeof(struct tcp_connection_node), GFP_KERNEL);
        if (!conn) {
            printk(KERN_ERR "Failed to allocate memory for connection\n");
            return;
        }

        conn->conn = (struct tcp_connection){
            .state = TCP_CLOSE,
            .saddr = saddr,
            .daddr = daddr,
        };
        tcp_fsm_step(&conn->conn, OUTGOING, packet->tcp_header);
        hash_add(tcp_connections, &conn->node, hash);
        printk(KERN_DEBUG
               "Tracking new TCP connection %pI4:%u --> %pI4:%u, hash=%u\n",
               &saddr.addr, be16_to_cpu(saddr.port), &daddr.addr,
               be16_to_cpu(daddr.port), hash);
    }

    hash_for_each_possible(tcp_connections, conn, node, hash) {
        if (match_conn_addrs(&conn->conn, &daddr, &saddr)) {
            incoming_match = true;
            break;
        }
    }

    if (!incoming_match) {
        inverse_conn = kmalloc(sizeof(struct tcp_connection_node), GFP_KERNEL);
        if (!inverse_conn) {
            printk(KERN_ERR "Failed to allocate memory for connection\n");
            return;
        }

        inverse_conn->conn = (struct tcp_connection){
            .state = TCP_CLOSE,
            .saddr = daddr,
            .daddr = saddr,
        };
        tcp_fsm_step(&inverse_conn->conn, INCOMING, packet->tcp_header);
        hash_add(tcp_connections, &inverse_conn->node, inverse_hash);
        printk(KERN_DEBUG
               "Tracking new TCP connection %pI4:%u --> %pI4:%u, hash=%u\n",
               &daddr.addr, be16_to_cpu(daddr.port), &saddr.addr,
               be16_to_cpu(saddr.port), inverse_hash);
    }
}

bool match_connection_and_update_state(packet_t packet) {
    bool matched = false;
    struct socket_address saddr = {.addr = packet.src_ip,
                                   .port = packet.src_port};
    struct socket_address daddr = {.addr = packet.dst_ip,
                                   .port = packet.dst_port};

    matched =
        update_connection_state(packet.tcp_header, saddr, daddr, OUTGOING);
    matched |=
        update_connection_state(packet.tcp_header, daddr, saddr, INCOMING);
    return matched;
}

int init_tcp_conntrack(struct class *fw_sysfs_class) {
    hash_init(tcp_connections);

    conns_dev_major = register_chrdev(0, DEVICE_NAME_CONNTRACK, &fops);
    if (conns_dev_major < 0) {
        return conns_dev_major;
    }

    conns_dev = device_create(fw_sysfs_class, NULL, MKDEV(conns_dev_major, 0),
                              NULL, DEVICE_NAME_CONNTRACK);
    if (IS_ERR(conns_dev)) {
        goto unregister_chrdev;
    }

    if (device_create_file(
            conns_dev, (const struct device_attribute *)&dev_attr_conns.attr)) {
        goto device_destroy;
    }
    return 0;

device_destroy:
    device_destroy(fw_sysfs_class, MKDEV(conns_dev_major, 0));
unregister_chrdev:
    unregister_chrdev(conns_dev_major, DEVICE_NAME_RULES);
    return -1;
}

void destroy_tcp_conntrack(struct class *fw_sysfs_class) {
    unsigned i;
    struct tcp_connection_node *cur;

    device_remove_file(conns_dev,
                       (const struct device_attribute *)&dev_attr_conns.attr);
    device_destroy(fw_sysfs_class, MKDEV(conns_dev_major, 0));
    unregister_chrdev(conns_dev_major, DEVICE_NAME_RULES);

    hash_for_each(tcp_connections, i, cur, node) { close_connection(cur); }
}

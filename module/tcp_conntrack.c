#include "tcp_conntrack.h"

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/jhash.h>
#include <linux/timer.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#define GC_INTERVAL_MS 5000

static DECLARE_HASHTABLE(tcp_connections, 8);

static int conns_dev_major;
static struct device *conns_dev;

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static struct timer_list gc_timer;

static inline bool match_conn_addrs(struct tcp_connection *conn,
                                    struct socket_address *saddr,
                                    struct socket_address *daddr) {
    return conn->saddr.addr == saddr->addr && conn->saddr.port == saddr->port &&
           conn->daddr.addr == daddr->addr && conn->daddr.port == daddr->port;
}

static inline __u32 hash_conn_addrs(struct socket_address saddr,
                                    struct socket_address daddr) {
    return jhash2((u32[4]){saddr.addr, saddr.port, daddr.addr, daddr.port}, 4,
                  0);
}

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

static ssize_t proxy_port_store(struct device *dev,
                                struct device_attribute *attr, const char *buf,
                                size_t count) {
    struct tcp_connection_node *conn_node;
    struct socket_address saddr;
    struct socket_address daddr;
    __be16 proxy_port;

    size_t expected_count = sizeof(struct socket_address) +
                            sizeof(struct socket_address) + sizeof(__be16);

    if (count != expected_count) {
        return -EINVAL;
    }

    memcpy(&saddr, buf, sizeof(struct socket_address));
    memcpy(&daddr, buf + sizeof(struct socket_address),
           sizeof(struct socket_address));
    memcpy(&proxy_port,
           buf + sizeof(struct socket_address) + sizeof(struct socket_address),
           sizeof(__be16));

    if ((conn_node = lookup_tcp_connection_node(saddr, daddr)) == NULL) {
        return -ENOENT;
    }

    conn_node->conn.proxy_port = proxy_port;
    return expected_count;
}

static void *add_connection(struct socket_address saddr,
                            struct socket_address daddr, __u8 state) {
    __u32 hash;
    struct tcp_connection_node *conn_node;
    if (!(conn_node =
              kmalloc(sizeof(struct tcp_connection_node), GFP_KERNEL))) {
        printk(KERN_ERR "Failed to allocate memory for connection\n");
        return conn_node;
    }

    conn_node->conn = (struct tcp_connection){
        .state = state,
        .saddr = saddr,
        .daddr = daddr,
    };
    hash = hash_conn_addrs(saddr, daddr);
    hash_add(tcp_connections, &conn_node->node, hash);
    printk(KERN_DEBUG "Tracking new TCP connection %pI4:%u-->%pI4:%u\n",
           &saddr.addr, ntohs(saddr.port), &daddr.addr, ntohs(daddr.port));
    return conn_node;
}

static ssize_t related_conns_store(struct device *dev,
                                   struct device_attribute *attr,
                                   const char *buf, size_t count) {
    struct socket_address saddr;
    struct socket_address daddr;

    size_t expected_count =
        sizeof(struct socket_address) + sizeof(struct socket_address);
    if (count != expected_count) {
        return -EINVAL;
    }

    memcpy(&saddr, buf, sizeof(struct socket_address));
    memcpy(&daddr, buf + sizeof(struct socket_address),
           sizeof(struct socket_address));

    if (add_connection(saddr, daddr, TCP_CLOSE) == NULL) {
        return -ENOMEM;
    }

    if (add_connection(daddr, saddr, TCP_LISTEN) == NULL) {
        return -ENOMEM;
    }

    return expected_count;
}

static DEVICE_ATTR(conns, S_IRUSR, conns_table_show, NULL);
static DEVICE_ATTR(proxy_port, S_IWUSR, NULL, proxy_port_store);
static DEVICE_ATTR(related_conns, S_IWUSR, NULL, related_conns_store);

static inline void close_connection(struct tcp_connection_node *conn) {
    hash_del(&conn->node);
    kfree(conn);
}

/**
 * A callback function for deleting closed connections from the table.
 * Each connection stays in TIME_WAIT for a period of time, to still be able to
 * respond to late packets. After this period, the connection is removed from
 * the table.
 * Notice that it's possible that the callback is called immediately after a
 * connection transitions to TIME_WAIT.
 */
static void connections_gc(struct timer_list *timer) {
    unsigned i;
    struct tcp_connection_node *conn_node;
    hash_for_each(tcp_connections, i, conn_node, node) {
        if (conn_node->conn.state == TCP_TIME_WAIT) {
            printk(
                KERN_DEBUG "Removing TIME_WAIT connection from table "
                           "%pI4:%u-->%pI4:%u\n",
                &conn_node->conn.saddr.addr, ntohs(conn_node->conn.saddr.port),
                &conn_node->conn.daddr.addr, ntohs(conn_node->conn.daddr.port));
            close_connection(conn_node);
        }
    }
    mod_timer(&gc_timer, jiffies + msecs_to_jiffies(GC_INTERVAL_MS));
}

static void tcp_fsm_step(struct tcp_connection_node *conn_node,
                         direction_t direction, struct tcphdr *tcp_header) {
    struct tcp_connection *conn = &conn_node->conn;
    if (tcp_header->rst) {
        close_connection(conn_node);
        return;
    }
    if (direction == DIRECTION_IN) {
        switch (conn->state) {
        case TCP_CLOSE:
            if (tcp_header->syn) {
                conn->state =
                    TCP_SYN_RECV; // Originally transitions to TCP_LISTEN, but
                                  // we don't handle this state.
                return;
            }
            break;
        case TCP_LISTEN:
            if (tcp_header->syn) {
                conn->state =
                    TCP_SYN_RECV; // Related connections start in this state.
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
                conn->state = TCP_TIME_WAIT;
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
                conn->state = TCP_TIME_WAIT;
                return;
            }
            break;
        case TCP_CLOSING:
            if (tcp_header->ack) {
                conn->state = TCP_TIME_WAIT;
                return;
            }
            break;
        case TCP_LAST_ACK:
            if (tcp_header->ack) {
                close_connection(conn_node);
                return;
            }
            break;
        }
    } else if (direction == DIRECTION_OUT) {
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

static inline bool update_connection_state(struct tcphdr *tcp_header,
                                           struct socket_address saddr,
                                           struct socket_address daddr,
                                           direction_t direction) {
    struct tcp_connection_node *conn_node =
        lookup_tcp_connection_node(saddr, daddr);

    if (conn_node == NULL) {
        return false;
    }
    tcp_fsm_step(conn_node, direction, tcp_header);
    return true;
}

struct tcp_connection_node *
lookup_tcp_connection_node(struct socket_address saddr,
                           struct socket_address daddr) {
    struct tcp_connection_node *conn_node;
    __u32 hash = hash_conn_addrs(saddr, daddr);
    hash_for_each_possible(tcp_connections, conn_node, node, hash) {
        if (match_conn_addrs(&conn_node->conn, &saddr, &daddr)) {
            return conn_node;
        }
    }
    return NULL;
}

struct tcp_connection *lookup_tcp_connection_by_proxy_port(__be16 proxy_port) {
    unsigned i;
    struct tcp_connection_node *conn_node;
    hash_for_each(tcp_connections, i, conn_node, node) {
        if (conn_node->conn.proxy_port == proxy_port) {
            return &conn_node->conn;
        }
    }
    return NULL;
}

struct socket_address lookup_peer_address(struct socket_address addr) {
    unsigned i;
    struct tcp_connection_node *conn_node;
    struct socket_address peer_addr = {.addr = 0, .port = 0};
    hash_for_each(tcp_connections, i, conn_node, node) {
        if (conn_node->conn.saddr.addr == addr.addr &&
            conn_node->conn.saddr.port == addr.port) {
            return conn_node->conn.daddr;
        }
    }
    return peer_addr;
}

void track_one_sided_connection(packet_t *packet, direction_t direction) {
    struct tcp_connection_node *conn;
    struct socket_address saddr, daddr;

    if (direction == DIRECTION_OUT) {
        saddr.addr = packet->src_ip;
        saddr.port = packet->src_port;
        daddr.addr = packet->dst_ip;
        daddr.port = packet->dst_port;
    } else {
        saddr.addr = packet->dst_ip;
        saddr.port = packet->dst_port;
        daddr.addr = packet->src_ip;
        daddr.port = packet->src_port;
    }

    if ((conn = lookup_tcp_connection_node(saddr, daddr)) == NULL) {
        if ((conn = add_connection(saddr, daddr, TCP_CLOSE)) == NULL) {
            return;
        }
        tcp_fsm_step(conn, direction, packet->tcp_header);
    }
}

void track_two_sided_connection(packet_t *packet) {
    track_one_sided_connection(packet, DIRECTION_OUT);
    track_one_sided_connection(packet, DIRECTION_IN);
}

bool match_connection_and_update_state(packet_t packet) {
    struct socket_address saddr = {.addr = packet.src_ip,
                                   .port = packet.src_port};
    struct socket_address daddr = {.addr = packet.dst_ip,
                                   .port = packet.dst_port};
    bool matched = false;

    matched =
        update_connection_state(packet.tcp_header, saddr, daddr, DIRECTION_OUT);
    matched |=
        update_connection_state(packet.tcp_header, daddr, saddr, DIRECTION_IN);
    return matched;
}

int init_tcp_conntrack(struct class *fw_sysfs_class) {
    hash_init(tcp_connections);

    if ((conns_dev_major = register_chrdev(0, DEVICE_NAME_CONNTRACK, &fops)) <
        0) {
        return conns_dev_major;
    }

    conns_dev = device_create(fw_sysfs_class, NULL, MKDEV(conns_dev_major, 0),
                              NULL, DEVICE_NAME_CONNTRACK);
    if (IS_ERR(conns_dev)) {
        goto unregister_conns_chrdev;
    }

    if (device_create_file(
            conns_dev, (const struct device_attribute *)&dev_attr_conns.attr)) {
        goto destroy_conns_dev;
    }

    if (device_create_file(
            conns_dev,
            (const struct device_attribute *)&dev_attr_proxy_port.attr)) {
        goto remove_conns_file;
    }

    if (device_create_file(
            conns_dev,
            (const struct device_attribute *)&dev_attr_related_conns.attr)) {
        goto remove_proxy_port_file;
    }

    timer_setup(&gc_timer, connections_gc, 0);
    mod_timer(&gc_timer, jiffies + msecs_to_jiffies(GC_INTERVAL_MS));

    return 0;

remove_proxy_port_file:
    device_remove_file(
        conns_dev, (const struct device_attribute *)&dev_attr_proxy_port.attr);
remove_conns_file:
    device_remove_file(conns_dev,
                       (const struct device_attribute *)&dev_attr_conns.attr);
destroy_conns_dev:
    device_destroy(fw_sysfs_class, MKDEV(conns_dev_major, 0));
unregister_conns_chrdev:
    unregister_chrdev(conns_dev_major, DEVICE_NAME_CONNTRACK);
    return -1;
}

void destroy_tcp_conntrack(struct class *fw_sysfs_class) {
    unsigned i;
    struct tcp_connection_node *cur;

    device_remove_file(
        conns_dev, (const struct device_attribute *)&dev_attr_proxy_port.attr);

    device_remove_file(
        conns_dev, (const struct device_attribute *)&dev_attr_proxy_port.attr);

    device_remove_file(conns_dev,
                       (const struct device_attribute *)&dev_attr_conns.attr);

    device_destroy(fw_sysfs_class, MKDEV(conns_dev_major, 0));
    unregister_chrdev(conns_dev_major, DEVICE_NAME_CONNTRACK);

    del_timer(&gc_timer);
    hash_for_each(tcp_connections, i, cur, node) { close_connection(cur); }
}

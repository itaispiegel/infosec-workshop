#include "tcp_conntrack.h"

#include <linux/jhash.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "fw.h"

static DECLARE_HASHTABLE(tcp_connections, 8);

static int conns_dev_major;
static struct device *conns_dev;

static int proxy_port_dev_major;
static struct device *proxy_port_dev;

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

static ssize_t proxy_port_store(struct device *dev,
                                struct device_attribute *attr, const char *buf,
                                size_t count) {
    return 0;
}

static DEVICE_ATTR(conns, S_IRUSR, conns_table_show, NULL);
static DEVICE_ATTR(proxy_port, S_IWUSR, NULL, proxy_port_store);

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

static inline void close_connection(struct tcp_connection_node *conn) {
    hash_del(&conn->node);
    kfree(conn);
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

static struct tcp_connection_node *
get_connection_node(struct socket_address saddr, struct socket_address daddr) {
    struct tcp_connection_node *conn_node;
    __u32 hash = hash_conn_addrs(saddr, daddr);
    hash_for_each_possible(tcp_connections, conn_node, node, hash) {
        if (match_conn_addrs(&conn_node->conn, &saddr, &daddr)) {
            return conn_node;
        }
    }
    return NULL;
}

static inline bool update_connection_state(struct tcphdr *tcp_header,
                                           struct socket_address saddr,
                                           struct socket_address daddr,
                                           direction_t direction) {
    struct tcp_connection_node *conn_node = get_connection_node(saddr, daddr);

    if (conn_node == NULL) {
        return false;
    }
    tcp_fsm_step(&conn_node->conn, direction, tcp_header);
    if (conn_node->conn.state == TCP_CLOSE) {
        printk(KERN_DEBUG "Removing closed connection from table "
                          "%pI4:%u --> %pI4:%u\n",
               &saddr.addr, saddr.port, &daddr.addr, daddr.port);
        close_connection(conn_node);
    }
    return true;
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

void track_connection(packet_t *packet) {
    struct tcp_connection_node *conn, *inverse_conn;
    struct socket_address saddr = {.addr = packet->src_ip,
                                   .port = packet->src_port};
    struct socket_address daddr = {.addr = packet->dst_ip,
                                   .port = packet->dst_port};
    __u32 hash = hash_conn_addrs(saddr, daddr);
    __u32 inverse_hash = hash_conn_addrs(daddr, saddr);

    struct tcp_connection_node *existing_conn_node =
        get_connection_node(saddr, daddr);
    if (existing_conn_node == NULL) {
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

    existing_conn_node = get_connection_node(daddr, saddr);
    if (existing_conn_node == NULL) {
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
        goto unregister_conns_chrdev;
    }

    if (device_create_file(
            conns_dev, (const struct device_attribute *)&dev_attr_conns.attr)) {
        goto destroy_conns_dev;
    }

    proxy_port_dev_major = register_chrdev(0, DEVICE_NAME_PROXY_PORT, &fops);
    if (proxy_port_dev_major < 0) {
        goto destroy_conns_dev_file;
    }

    proxy_port_dev =
        device_create(fw_sysfs_class, NULL, MKDEV(proxy_port_dev_major, 0),
                      NULL, DEVICE_NAME_PROXY_PORT);
    if (IS_ERR(proxy_port_dev)) {
        goto ungregister_proxy_port_chrdev;
    }

    if (device_create_file(
            proxy_port_dev,
            (const struct device_attribute *)&dev_attr_proxy_port.attr)) {
        goto destroy_proxy_port_dev;
    }

    return 0;

destroy_proxy_port_dev:
    device_destroy(fw_sysfs_class, MKDEV(proxy_port_dev_major, 0));
ungregister_proxy_port_chrdev:
    unregister_chrdev(conns_dev_major, DEVICE_NAME_PROXY_PORT);
destroy_conns_dev_file:
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
        proxy_port_dev,
        (const struct device_attribute *)&dev_attr_proxy_port.attr);
    device_destroy(fw_sysfs_class, MKDEV(proxy_port_dev_major, 0));
    unregister_chrdev(proxy_port_dev_major, DEVICE_NAME_PROXY_PORT);

    device_remove_file(conns_dev,
                       (const struct device_attribute *)&dev_attr_conns.attr);
    device_destroy(fw_sysfs_class, MKDEV(conns_dev_major, 0));
    unregister_chrdev(conns_dev_major, DEVICE_NAME_CONNTRACK);

    hash_for_each(tcp_connections, i, cur, node) { close_connection(cur); }
}

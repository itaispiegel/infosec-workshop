#include <linux/device.h>
#include <linux/fs.h>

#include "rules.h"

#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1023)
#define PORT_ABOVE_1023_BE (be16_to_cpu(PORT_ABOVE_1023))

rule_t rules[MAX_RULES] = {0};
__u8 rules_count = 0;

static int rules_dev_major;
static struct device *rules_dev;

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static ssize_t rules_table_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
    __u8 i;
    __u16 offset = 0;
    for (i = 0; i < rules_count; i++) {
        memcpy(buf + offset, &rules[i], sizeof(rule_t));
        offset += sizeof(rule_t);
    }
    return offset;
}

static ssize_t rules_table_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {

    // Writing a single NULL byte to the table will reset it.
    if (count == 1 && *buf == 0) {
        memset(rules, 0, sizeof(rules));
        rules_count = 0;
        return count;
    } else if (count > MAX_RULES * sizeof(rule_t)) {
        printk(KERN_WARNING "Can't save rules, since the size is too big\n");
        return -EINVAL;
    } else if (count % sizeof(rule_t) != 0) {
        printk(KERN_WARNING "Can't save rules, since the size is invalid\n");
        return -EINVAL;
    }

    memcpy(&rules, buf, count);
    rules_count = count / sizeof(rule_t);
    return count;
}

static DEVICE_ATTR(rules, S_IRUSR | S_IWUSR, rules_table_show,
                   rules_table_store);

static inline bool match_direction(rule_t *rule, packet_t *packet) {
    return rule->direction == DIRECTION_ANY ||
           rule->direction == packet->direction;
}

static inline bool match_rule_ports(__be16 rule_port, __be16 skb_port) {
    // The port numbers are in big endian, so we need to convert them to host
    // byte order.
    // Notice that we assume non UDP and non TCP packets have 0 as their ports.
    return (rule_port == PORT_ANY || rule_port == skb_port ||
            (rule_port == PORT_ABOVE_1023_BE && be16_to_cpu(skb_port) > 1023));
}

static inline bool match_ip_addrs(rule_t *rule, packet_t *packet) {
    return (rule->src_ip == 0 ||
            (rule->src_prefix_size != 0 &&
             (rule->src_ip & rule->src_prefix_mask) ==
                 (packet->src_ip & rule->src_prefix_mask))) &&
           (rule->dst_ip == 0 ||
            (rule->dst_prefix_size != 0 &&
             (rule->dst_ip & rule->dst_prefix_mask) ==
                 (packet->dst_ip & rule->dst_prefix_mask)));
}

static inline bool match_ports(rule_t *rule, packet_t *packet) {
    return match_rule_ports(rule->src_port, packet->src_port) &&
           match_rule_ports(rule->dst_port, packet->dst_port);
}

static inline bool match_protocol(rule_t *rule, packet_t *packet) {
    return rule->protocol == PROT_ANY || rule->protocol == packet->protocol;
}

static inline bool match_ack(rule_t *rule, packet_t *packet) {
    return rule->ack == ACK_ANY || (packet->protocol == PROT_TCP &&
                                    ((rule->ack == ACK_YES && packet->ack) ||
                                     (rule->ack == ACK_NO && !packet->ack)));
}

inline bool match_rule_packet(rule_t *rule, packet_t *packet) {
    return match_direction(rule, packet) && match_ip_addrs(rule, packet) &&
           match_ports(rule, packet) && match_protocol(rule, packet) &&
           match_ack(rule, packet);
}

int init_rules_table_device(struct class *fw_sysfs_class) {
    rules_dev_major = register_chrdev(0, DEVICE_NAME_RULES, &fops);
    if (rules_dev_major < 0) {
        return rules_dev_major;
    }

    rules_dev = device_create(fw_sysfs_class, NULL, MKDEV(rules_dev_major, 0),
                              NULL, DEVICE_NAME_RULES);
    if (IS_ERR(rules_dev)) {
        goto unregister_chrdev;
    }

    if (device_create_file(
            rules_dev, (const struct device_attribute *)&dev_attr_rules.attr)) {
        goto device_destroy;
    }

    return 0;

device_destroy:
    device_destroy(fw_sysfs_class, MKDEV(rules_dev_major, 0));
unregister_chrdev:
    unregister_chrdev(rules_dev_major, DEVICE_NAME_RULES);
    return -1;
}

void destroy_rules_table_device(struct class *fw_sysfs_class) {
    device_remove_file(rules_dev,
                       (const struct device_attribute *)&dev_attr_rules.attr);
    device_destroy(fw_sysfs_class, MKDEV(rules_dev_major, 0));
    unregister_chrdev(rules_dev_major, DEVICE_NAME_RULES);
}

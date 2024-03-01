#include <linux/device.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "logs.h"

static LIST_HEAD(logs_list);
static size_t logs_count = 0;

static int show_logs_dev_major;
static struct device *show_logs_dev;

static int reset_logs_dev_major;
static struct device *reset_logs_dev;

/**
 * Read the logs from the logs list and write them to the character device.
 * The device supports reading from arbitrary offsets, but they must be a
 * multiple of the log row size.
 * If the offset is greater than the number of logs in the list, or if the read
 * size is less than a single log row, the function will return zero bytes.
 */
ssize_t show_logs_dev_read(struct file *filp, char *buf, size_t len,
                           loff_t *off);

static struct file_operations show_logs_device_fops = {
    .owner = THIS_MODULE,
    .read = show_logs_dev_read,
};

static struct file_operations reset_logs_device_fops = {
    .owner = THIS_MODULE,
};

static ssize_t reset_logs_store(struct device *dev,
                                struct device_attribute *attr, const char *buf,
                                size_t count) {
    if (count == RESET_MAGIC_SIZE &&
        strncmp(buf, RESET_MAGIC, RESET_MAGIC_SIZE) == 0) {
        struct log_entry *log_entry, *tmp;
        list_for_each_entry_safe(log_entry, tmp, &logs_list, list) {
            list_del(&log_entry->list);
            kfree(log_entry);
            logs_count--;
        }
    }

    return count;
}

static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_logs_store);

static inline bool log_match_rule(log_row_t *log_row, rule_t *rule) {
    return log_row->protocol == rule->protocol &&
           log_row->action == rule->action && log_row->src_ip == rule->src_ip &&
           log_row->dst_ip == rule->dst_ip &&
           log_row->src_port == rule->src_port &&
           log_row->dst_port == rule->dst_port;
}

static inline log_row_t new_log_row_by_packet(packet_t *packet, reason_t reason,
                                              __u8 verdict) {
    return (log_row_t){
        .timestamp = ktime_get_real_seconds(),
        .protocol = packet->protocol,
        .action = verdict,
        .src_ip = packet->src_ip,
        .dst_ip = packet->dst_ip,
        .src_port = packet->src_port,
        .dst_port = packet->dst_port,
        .reason = reason,
        .count = 1,
    };
}

static inline void *new_log_entry(packet_t *packet, reason_t reason,
                                  __u8 verdict) {
    struct log_entry *log_entry;
    printk(KERN_INFO "Creating a new log entry for packet\n");
    if ((log_entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL)) == NULL) {
        printk(KERN_WARNING
               "Failed to allocate memory for log entry, so ignoring it\n");
        return log_entry;
    }

    log_entry->log_row = new_log_row_by_packet(packet, reason, verdict);
    list_add_tail(&log_entry->list, &logs_list);
    logs_count++;
    return log_entry;
}

static bool log_entry_matches_packet(struct log_entry *log_entry,
                                     packet_t *packet, direction_t direction) {
    if (direction == DIRECTION_OUT) {
        return log_entry->log_row.protocol == packet->protocol &&
               log_entry->log_row.src_ip == packet->src_ip &&
               log_entry->log_row.dst_ip == packet->dst_ip &&
               log_entry->log_row.src_port == packet->src_port &&
               log_entry->log_row.dst_port == packet->dst_port;
    } else if (direction == DIRECTION_IN) {
        return log_entry->log_row.protocol == packet->protocol &&
               log_entry->log_row.src_ip == packet->dst_ip &&
               log_entry->log_row.src_port == packet->dst_port &&
               log_entry->log_row.dst_ip == packet->src_ip &&
               log_entry->log_row.dst_port == packet->src_port;
    } else {
        return log_entry_matches_packet(log_entry, packet, DIRECTION_IN) ||
               log_entry_matches_packet(log_entry, packet, DIRECTION_OUT);
    }
}

void update_log_entry_by_packet(packet_t *packet, reason_t reason,
                                __u8 verdict) {
    struct log_entry *log_entry;
    struct list_head *pos;
    list_for_each(pos, &logs_list) {
        log_entry = list_entry(pos, struct log_entry, list);
        if (log_entry->log_row.reason == reason &&
            log_entry_matches_packet(log_entry, packet, DIRECTION_OUT)) {
            log_entry->log_row.count++;
            log_entry->log_row.timestamp = ktime_get_real_seconds();
            return;
        }
    }

    log_entry = new_log_entry(packet, reason, verdict);
    return;
}

void update_established_tcp_conn_log(packet_t *packet) {
    struct log_entry *log_entry;
    struct list_head *pos;
    list_for_each(pos, &logs_list) {
        log_entry = list_entry(pos, struct log_entry, list);
        if (log_entry_matches_packet(log_entry, packet, DIRECTION_ANY)) {
            log_entry->log_row.count++;
            log_entry->log_row.timestamp = ktime_get_real_seconds();
            return;
        }
    }

    log_entry = new_log_entry(
        packet, REASON_RELATED_CONNECTION,
        NF_ACCEPT); // In this case the connection is guaranteed to be related.
    return;
}

ssize_t show_logs_dev_read(struct file *filp, char __user *buf, size_t len,
                           loff_t *off) {
    struct log_entry *log_entry;
    struct list_head *pos;
    ssize_t i = 0, skip = 0, bytes_read = 0;

    if (*off >= logs_count * sizeof(log_row_t)) {
        return 0; // EOF
    }

    if ((ssize_t)*off % sizeof(log_row_t) != 0) {
        return -EINVAL;
    }

    skip = (ssize_t)*off / sizeof(log_row_t);
    list_for_each(pos, &logs_list) {
        if (bytes_read + sizeof(log_row_t) > len) {
            break;
        }
        if (i < skip) {
            i++;
            continue;
        }

        log_entry = list_entry(pos, struct log_entry, list);
        if (copy_to_user(buf + bytes_read, &(log_entry->log_row),
                         sizeof(log_row_t)) != 0) {
            return -EFAULT;
        }
        bytes_read += sizeof(log_row_t);
    }

    *off += bytes_read;
    return bytes_read;
}

int init_show_logs_device(struct class *fw_sysfs_class) {
    show_logs_dev_major =
        register_chrdev(0, DEVICE_NAME_SHOW_LOGS, &show_logs_device_fops);
    if (show_logs_dev_major < 0) {
        return show_logs_dev_major;
    }

    show_logs_dev =
        device_create(fw_sysfs_class, NULL, MKDEV(show_logs_dev_major, 0), NULL,
                      DEVICE_NAME_SHOW_LOGS);
    if (IS_ERR(show_logs_dev)) {
        goto unregister_chrdev;
    }

    return 0;

unregister_chrdev:
    unregister_chrdev(show_logs_dev_major, DEVICE_NAME_SHOW_LOGS);
    return -1;
}

int init_reset_logs_device(struct class *fw_sysfs_class) {
    reset_logs_dev_major =
        register_chrdev(0, DEVICE_NAME_RESET_LOGS, &reset_logs_device_fops);
    if (reset_logs_dev_major < 0) {
        return reset_logs_dev_major;
    }

    reset_logs_dev =
        device_create(fw_sysfs_class, NULL, MKDEV(reset_logs_dev_major, 0),
                      NULL, DEVICE_NAME_LOG);
    if (IS_ERR(reset_logs_dev)) {
        goto unregister_chrdev;
    }

    if (device_create_file(
            reset_logs_dev,
            (const struct device_attribute *)&dev_attr_reset.attr)) {
        goto device_destroy;
    }

    return 0;

device_destroy:
    device_destroy(fw_sysfs_class, MKDEV(reset_logs_dev_major, 0));
unregister_chrdev:
    unregister_chrdev(reset_logs_dev_major, DEVICE_NAME_RESET_LOGS);
    return -1;
}

void destroy_show_logs_device(struct class *fw_sysfs_class) {
    device_remove_file(show_logs_dev,
                       (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(show_logs_dev_major, 0));
    unregister_chrdev(show_logs_dev_major, DEVICE_NAME_SHOW_LOGS);
}

void destroy_reset_logs_device(struct class *fw_sysfs_class) {
    device_remove_file(reset_logs_dev,
                       (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(reset_logs_dev_major, 0));
    unregister_chrdev(reset_logs_dev_major, DEVICE_NAME_RESET_LOGS);
}

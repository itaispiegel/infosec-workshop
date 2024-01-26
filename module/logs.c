#include <linux/export.h>
#include <linux/fs.h>

#include "fw.h"
#include "logs.h"

LIST_HEAD(logs_list);
size_t logs_count = 0;

static int show_logs_dev_major;
static struct device *show_logs_dev;

static int reset_logs_dev_major;
static struct device *reset_logs_dev;

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
    return 0;
}

static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_logs_store);

ssize_t show_logs_dev_read(struct file *filp, char __user *buf, size_t len,
                           loff_t *off) {
    struct log_entry *log_entry;
    struct list_head *pos;

    if (*off >= logs_count * sizeof(log_row_t)) {
        return 0;
    }

    // We currently don't support reading from a specific offset.
    if (*off > 0 || len <= sizeof(log_row_t)) {
        return -EINVAL;
    }

    list_for_each(pos, &logs_list) {
        if (*off + sizeof(log_row_t) > len) {
            return -EINVAL;
        }

        log_entry = list_entry(pos, struct log_entry, list);
        if (copy_to_user(buf + *off, &(log_entry->log_row),
                         sizeof(log_row_t))) {
            return -EFAULT;
        }
        *off += sizeof(log_row_t);
    }

    return *off;
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
    unregister_chrdev(show_logs_dev_major, DEVICE_NAME_RULES);
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
    unregister_chrdev(reset_logs_dev_major, DEVICE_NAME_RULES);
    return -1;
}

void destroy_show_logs_device(struct class *fw_sysfs_class) {
    device_remove_file(show_logs_dev,
                       (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(show_logs_dev_major, 0));
    unregister_chrdev(show_logs_dev_major, DEVICE_NAME_RULES);
}

void destroy_reset_logs_device(struct class *fw_sysfs_class) {
    device_remove_file(reset_logs_dev,
                       (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(reset_logs_dev_major, 0));
    unregister_chrdev(reset_logs_dev_major, DEVICE_NAME_RULES);
}

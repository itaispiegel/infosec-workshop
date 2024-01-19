#include <linux/export.h>
#include <linux/fs.h>

#include "fw.h"
#include "logs.h"

static int show_logs_dev_major;
static struct device *show_logs_dev;

static int reset_logs_dev_major;
static struct device *reset_logs_dev;

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static ssize_t reset_logs_store(struct device *dev,
                                struct device_attribute *attr, const char *buf,
                                size_t count) {
    return 0;
}

static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_logs_store);

int init_show_logs_device(struct class *fw_sysfs_class) {
    show_logs_dev_major = register_chrdev(0, DEVICE_NAME_SHOW_LOGS, &fops);
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
    reset_logs_dev_major = register_chrdev(0, DEVICE_NAME_RESET_LOGS, &fops);
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
    device_destroy(fw_sysfs_class, MKDEV(show_logs_dev_major, 0));
    unregister_chrdev(show_logs_dev_major, DEVICE_NAME_RULES);
}

void destroy_reset_logs_device(struct class *fw_sysfs_class) {
    device_remove_file(reset_logs_dev,
                       (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(fw_sysfs_class, MKDEV(reset_logs_dev_major, 0));
    unregister_chrdev(reset_logs_dev_major, DEVICE_NAME_RULES);
}

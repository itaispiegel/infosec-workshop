#include "rules_table.h"

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
    for (i = 0; i < rules_count; i++) {
        memcpy(buf + i * sizeof(rule_t), &rules[i], sizeof(rule_t));
    }

    return rules_count * sizeof(rule_t);
}

static ssize_t rules_table_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {

    if (count > MAX_RULES * sizeof(rule_t)) {
        printk(KERN_WARNING "Can't save rules, since the size is too big\n");
        return -EINVAL;
    }

    if (count % sizeof(rule_t) != 0) {
        printk(KERN_WARNING "Can't save rules, since the size is invalid\n");
        return -EINVAL;
    }

    memcpy(&rules, buf, count);
    rules_count = count / sizeof(rule_t);
    return count;
}

static DEVICE_ATTR(rules, S_IRUSR | S_IWUSR, rules_table_show,
                   rules_table_store);

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
    device_destroy(fw_sysfs_class, MKDEV(rules_dev_major, 0));
    unregister_chrdev(rules_dev_major, DEVICE_NAME_RULES);
}

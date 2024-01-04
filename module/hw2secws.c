#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/device.h>

#define MOD_NAME "hw2secws"

static unsigned int input_pkts_count = 0;
static unsigned int forward_pkts_count = 0;

static unsigned int forward_hook_fn(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    printk(KERN_INFO "Packet Dropped\n");
    ++forward_pkts_count;
    return NF_DROP;
}

static unsigned int input_hook_fn(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
    printk(KERN_INFO "Packet Accepted\n");
    ++input_pkts_count;
    return NF_ACCEPT;
}

static const struct nf_hook_ops hooks[] = {
    {.hook = forward_hook_fn, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD},
    {.hook = input_hook_fn, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_IN}};

static int major;
static struct class *sysfs_class;
static struct file_operations fops = {
    .owner = THIS_MODULE,
};

ssize_t input_pkts_count_show(struct device *dev, struct device_attribute *attr,
                              char *buf) {
    return scnprintf(buf, PAGE_SIZE, "%u\n", input_pkts_count);
}

ssize_t forward_pkts_count_show(struct device *dev, struct device_attribute *attr,
                              char *buf) {
    return scnprintf(buf, PAGE_SIZE, "%u\n", forward_pkts_count);
}

ssize_t reset_counters_store(struct device *dev, struct device_attribute *attr,
                             const char *buf, size_t count) {
    input_pkts_count = 0;
    forward_pkts_count = 0;
    return count;
}

static struct device *sysfs_device;
static DEVICE_ATTR(input_pkts_count, S_IRUGO, input_pkts_count_show, NULL);
static DEVICE_ATTR(forward_pkts_count, S_IRUGO, forward_pkts_count_show, NULL);
static DEVICE_ATTR(reset_counters, S_IWUSR, NULL, reset_counters_store);

static int __init init(void) {
    int ret;

    printk(KERN_INFO "Starting hw2secws kernel module\n");
    ret = nf_register_net_hooks(&init_net, hooks, 2);
    if (ret > 0) {
        printk(KERN_ERR "Failed to register net hooks\n");
    } else {
        printk(KERN_INFO "Successfully registered net hooks\n");
    }

    major = register_chrdev(0, MOD_NAME, &fops);
    if (major < 0) {
        printk(KERN_ERR "Failed to register character device\n");
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }

    sysfs_class = class_create(THIS_MODULE, MOD_NAME);
    if (IS_ERR(sysfs_class)) {
        printk(KERN_ERR "Failed to create sysfs class\n");
        nf_unregister_net_hooks(&init_net, hooks, 2);
        unregister_chrdev(major, MOD_NAME);
        return -1;
    }

    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major, 0), NULL, MOD_NAME);
    if (IS_ERR(sysfs_device)) {
        nf_unregister_net_hooks(&init_net, hooks, 2);
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        return -1;
    }

    if (device_create_file(sysfs_device, (const struct device_attribute *) &dev_attr_input_pkts_count.attr)) {
        nf_unregister_net_hooks(&init_net, hooks, 2);
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        return -1;
    }

    if (device_create_file(sysfs_device, (const struct device_attribute *) &dev_attr_forward_pkts_count.attr)) {
        nf_unregister_net_hooks(&init_net, hooks, 2);
        device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_input_pkts_count.attr);
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        return -1;
    }

    if (device_create_file(sysfs_device, (const struct device_attribute *) &dev_attr_reset_counters.attr)) {
        nf_unregister_net_hooks(&init_net, hooks, 2);
        device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_forward_pkts_count.attr);
        device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_input_pkts_count.attr);
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        return -1;
    }

    return ret;
}

static void __exit exit(void) {
    nf_unregister_net_hooks(&init_net, hooks, 2);
    device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_reset_counters.attr);
    device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_forward_pkts_count.attr);
    device_remove_file(sysfs_device, (const struct device_attribute *) &dev_attr_input_pkts_count.attr);
    device_destroy(sysfs_class, MKDEV(major, 0));
    class_destroy(sysfs_class);
    unregister_chrdev(major, MOD_NAME);
    printk(KERN_INFO "Exiting hw2secws kernel module\n");
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");

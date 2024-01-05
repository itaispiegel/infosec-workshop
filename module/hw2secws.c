#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>

#define MOD_NAME "hw2secws"

static unsigned int accepted_pkts_count = 0;
static unsigned int dropped_pkts_count = 0;

static unsigned int drop_pkt_hook_fn(void *, struct sk_buff *,
                                     const struct nf_hook_state *);

static unsigned int accept_pkt_hook_fn(void *, struct sk_buff *,
                                       const struct nf_hook_state *);

ssize_t accepted_pkts_count_show(struct device *, struct device_attribute *,
                                 char *);

ssize_t dropped_pkts_count_show(struct device *, struct device_attribute *,
                                char *);

ssize_t reset_counters_store(struct device *, struct device_attribute *,
                             const char *, size_t);

static int major;
static struct class *sysfs_class;
static struct device *sysfs_device;

static struct file_operations fops = {
    .owner = THIS_MODULE,
};

static DEVICE_ATTR(accepted_pkts_count, S_IRUGO, accepted_pkts_count_show,
                   NULL);
static DEVICE_ATTR(dropped_pkts_count, S_IRUGO, dropped_pkts_count_show, NULL);
static DEVICE_ATTR(reset_counters, S_IWUSR, NULL, reset_counters_store);

static const struct nf_hook_ops hooks[] = {
    {.hook = drop_pkt_hook_fn, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD},
    {.hook = accept_pkt_hook_fn,
     .pf = NFPROTO_IPV4,
     .hooknum = NF_INET_LOCAL_IN},
    {.hook = accept_pkt_hook_fn,
     .pf = NFPROTO_IPV4,
     .hooknum = NF_INET_LOCAL_OUT}};

static unsigned int drop_pkt_hook_fn(void *priv, struct sk_buff *skb,
                                     const struct nf_hook_state *state) {
    printk(KERN_INFO "*** Packet Dropped ***\n");
    ++dropped_pkts_count;
    return NF_DROP;
}

static unsigned int accept_pkt_hook_fn(void *priv, struct sk_buff *skb,
                                       const struct nf_hook_state *state) {
    printk(KERN_INFO "*** Packet Accepted ***\n");
    ++accepted_pkts_count;
    return NF_ACCEPT;
}

ssize_t accepted_pkts_count_show(struct device *dev,
                                 struct device_attribute *attr, char *buf) {
    return scnprintf(buf, PAGE_SIZE, "%u\n", accepted_pkts_count);
}

ssize_t dropped_pkts_count_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
    return scnprintf(buf, PAGE_SIZE, "%u\n", dropped_pkts_count);
}

ssize_t reset_counters_store(struct device *dev, struct device_attribute *attr,
                             const char *buf, size_t count) {
    accepted_pkts_count = 0;
    dropped_pkts_count = 0;
    return count;
}

static int __init init(void) {
    if (nf_register_net_hooks(&init_net, hooks, 2)) {
        printk(KERN_ERR "Failed to register net hooks\n");
        return -1;
    }
    printk(KERN_INFO "Successfully registered net hooks\n");

    major = register_chrdev(0, MOD_NAME, &fops);
    if (major < 0) {
        printk(KERN_ERR "Failed to register character device\n");
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully registered chrdev\n");

    sysfs_class = class_create(THIS_MODULE, MOD_NAME);
    if (IS_ERR(sysfs_class)) {
        printk(KERN_ERR "Failed to create sysfs class\n");
        unregister_chrdev(major, MOD_NAME);
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully created sysfs class\n");

    sysfs_device =
        device_create(sysfs_class, NULL, MKDEV(major, 0), NULL, MOD_NAME);
    if (IS_ERR(sysfs_device)) {
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully created sysfs device\n");

    if (device_create_file(sysfs_device,
                           (const struct device_attribute
                                *)&dev_attr_accepted_pkts_count.attr)) {
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully created sysfs accepted_pkts_count\n");

    if (device_create_file(sysfs_device,
                           (const struct device_attribute
                                *)&dev_attr_dropped_pkts_count.attr)) {
        device_remove_file(sysfs_device,
                           (const struct device_attribute
                                *)&dev_attr_accepted_pkts_count.attr);
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully created sysfs dropped_pkts_count\n");

    if (device_create_file(
            sysfs_device,
            (const struct device_attribute *)&dev_attr_reset_counters.attr)) {
        device_remove_file(
            sysfs_device,
            (const struct device_attribute *)&dev_attr_dropped_pkts_count.attr);
        device_remove_file(sysfs_device,
                           (const struct device_attribute
                                *)&dev_attr_accepted_pkts_count.attr);
        device_destroy(sysfs_class, MKDEV(major, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major, MOD_NAME);
        nf_unregister_net_hooks(&init_net, hooks, 2);
        return -1;
    }
    printk(KERN_INFO "Successfully created sysfs reset_counters\n");

    return 0;
}

static void __exit exit(void) {
    device_remove_file(
        sysfs_device,
        (const struct device_attribute *)&dev_attr_reset_counters.attr);
    device_remove_file(
        sysfs_device,
        (const struct device_attribute *)&dev_attr_dropped_pkts_count.attr);
    device_remove_file(
        sysfs_device,
        (const struct device_attribute *)&dev_attr_accepted_pkts_count.attr);
    device_destroy(sysfs_class, MKDEV(major, 0));
    class_destroy(sysfs_class);
    unregister_chrdev(major, MOD_NAME);
    nf_unregister_net_hooks(&init_net, hooks, 2);
    printk(KERN_INFO "Exiting hw2secws kernel module\n");
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("Itai Spiegel");
MODULE_LICENSE("GPL");

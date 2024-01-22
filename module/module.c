#include "logs.h"
#include "netfilter_hook.h"
#include "rules_table.h"

MODULE_AUTHOR("Itai Spiegel");
MODULE_LICENSE("GPL");

static struct class *fw_sysfs_class;

static int __init init(void) {
    fw_sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(fw_sysfs_class)) {
        return -1;
    }

    if (init_rules_table_device(fw_sysfs_class) < 0) {
        printk(KERN_ERR "Failed to initialize rules table device\n");
        goto class_destroy;
    }

    if (init_show_logs_device(fw_sysfs_class) < 0) {
        printk(KERN_ERR "Failed to initialize logs device\n");
        goto destroy_rules_table_device;
    }

    if (init_reset_logs_device(fw_sysfs_class) < 0) {
        printk(KERN_ERR "Failed to initialize reset logs device\n");
        goto destroy_show_logs_device;
    }

    if (init_netfilter_hook() < 0) {
        printk(KERN_ERR "Failed to initialize netfilter hook\n");
        goto destroy_reset_logs_device;
    }

    printk(KERN_INFO "Firewall loaded\n");
    return 0;

destroy_reset_logs_device:
    destroy_reset_logs_device(fw_sysfs_class);
destroy_show_logs_device:
    destroy_show_logs_device(fw_sysfs_class);
destroy_rules_table_device:
    destroy_rules_table_device(fw_sysfs_class);
class_destroy:
    class_destroy(fw_sysfs_class);
    return -1;
}

static void __exit exit(void) {
    destroy_netfilter_hook();
    destroy_reset_logs_device(fw_sysfs_class);
    destroy_show_logs_device(fw_sysfs_class);
    destroy_rules_table_device(fw_sysfs_class);
    class_destroy(fw_sysfs_class);
    printk(KERN_INFO "Firewall unloaded\n");
}

module_init(init);
module_exit(exit);

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>

static unsigned int drop_pkt_hook_fn(void *priv, struct sk_buff *skb,
                                     const struct nf_hook_state *state) {
    printk(KERN_INFO "*** Packet Dropped ***\n");
    return NF_DROP;
}

static unsigned int accept_pkt_hook_fn(void *priv, struct sk_buff *skb,
                                       const struct nf_hook_state *state) {
    printk(KERN_INFO "*** Packet Accepted ***\n");
    return NF_ACCEPT;
}

static const struct nf_hook_ops hooks[] = {
    {.hook = drop_pkt_hook_fn, .pf = NFPROTO_IPV4, .hooknum = NF_INET_FORWARD},
    {.hook = accept_pkt_hook_fn,
     .pf = NFPROTO_IPV4,
     .hooknum = NF_INET_LOCAL_IN},
    {.hook = accept_pkt_hook_fn,
     .pf = NFPROTO_IPV4,
     .hooknum = NF_INET_LOCAL_OUT}};

static int __init init(void) {
    int ret;

    printk(KERN_INFO "Starting hw1secws kernel module\n");
    ret = nf_register_net_hooks(&init_net, hooks, 2);
    if (ret > 0) {
        printk(KERN_ERR "Failed to register net hooks\n");
    } else {
        printk(KERN_INFO "Successfully registered net hooks\n");
    }

    return ret;
}

static void __exit exit(void) {
    nf_unregister_net_hooks(&init_net, hooks, 2);
    printk(KERN_INFO "Exiting hw1secws kernel module\n");
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("Itai Spiegel");
MODULE_LICENSE("GPL");

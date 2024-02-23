#ifndef _NETFILTER_HOOK_H_
#define _NETFILTER_HOOK_H_

#define FW_POLICY NF_DROP

/**
 * Initialize the netfilter hook.
 */
int init_netfilter_hook(void);

/**
 * Destroy the netfilter hook.
 */
void destroy_netfilter_hook(void);

#endif // _NETFILTER_HOOK_H_

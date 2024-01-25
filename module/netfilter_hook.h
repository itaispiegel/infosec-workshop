#ifndef _NETFILTER_HOOK_H_
#define _NETFILTER_HOOK_H_

#define FW_POLICY NF_DROP

int init_netfilter_hook(void);
void destroy_netfilter_hook(void);

#endif // _NETFILTER_HOOK_H_

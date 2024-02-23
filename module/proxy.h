#ifndef _PROXY_H
#define _PROXY_H

#include <linux/ip.h>

#include "parser.h"

void proxy_client_request(packet_t *packet, struct sk_buff *skb);
void proxy_server_response(packet_t *packet, struct sk_buff *skb);

#endif // _PROXY_H

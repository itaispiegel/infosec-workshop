#ifndef _PARSER_H_
#define _PARSER_H_

#include "fw.h"

typedef enum {
    PACKET_TYPE_NORMAL,
    PACKET_TYPE_XMAS,
    PACKET_TYPE_UNHANDLED_PROTOCOL,
    PACKET_TYPE_LOOPBACK
} packet_type;

typedef struct {
    packet_type type;
    char *dev_name;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    unsigned short ack;
} packet_t;

void parse_packet(packet_t *packet, struct sk_buff *skb);

#endif // _PARSER_H_
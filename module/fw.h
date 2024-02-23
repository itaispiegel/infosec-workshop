#ifndef _FW_H_
#define _FW_H_

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// the protocols we will work with
typedef enum {
    PROT_ICMP = 1,
    PROT_TCP = 6,
    PROT_UDP = 17,
    PROT_OTHER = 255,
    PROT_ANY = 143,
} __attribute__((packed)) prot_t;

// various reasons to be registered in each log entry
typedef enum {
    REASON_FW_INACTIVE = -1,
    REASON_NO_MATCHING_RULE = -2,
    REASON_XMAS_PACKET = -4,
    REASON_ILLEGAL_VALUE = -6,
} __attribute__((packed)) reason_t;

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES "rules"
#define DEVICE_NAME_LOG "log"
#define DEVICE_NAME_CONNTRACK "conn"
#define DEVICE_NAME_PROXY_PORT "proxy_port"
#define DEVICE_NAME_SHOW_LOGS "fw_log"
#define DEVICE_NAME_RESET_LOGS "reset"
#define CLASS_NAME "fw"
#define LOOPBACK_NET_DEVICE_NAME "lo"
#define IN_NET_DEVICE_NAME "enp0s8"
#define OUT_NET_DEVICE_NAME "enp0s9"

// auxiliary values, for your convenience
#define IP_VERSION (4)
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1023)
#define PORT_ABOVE_1023_BE (be16_to_cpu(PORT_ABOVE_1023))
#define HTTP_PORT_BE (be16_to_cpu(80))
#define HTTP_PROXY_PORT_BE (be16_to_cpu(800))
#define FTP_PORT_BE (be16_to_cpu(21))
#define FTP_PROXY_PORT_BE (be16_to_cpu(210))
#define MAX_RULES (50)

typedef enum {
    ACK_NO = 0x01,
    ACK_YES = 0x02,
    ACK_ANY = ACK_NO | ACK_YES,
} __attribute__((packed)) ack_t;

typedef enum {
    DIRECTION_IN = 0x01,
    DIRECTION_OUT = 0x02,
    DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
} __attribute__((packed)) direction_t;

typedef struct {
    char rule_name[20]; // names will be no longer than 20 chars
    direction_t direction;
    __be32 src_ip;
    __be32
        src_prefix_mask;  // e.g., 255.255.255.0 as int in the local endianness
    __u8 src_prefix_size; // valid values: 0-32, e.g., /24 for the example above
                          // (the field is redundant - easier to print)
    __be32 dst_ip;
    __be32 dst_prefix_mask; // as above
    __u8 dst_prefix_size;   // as above
    __be16 src_port; // number of port or 0 for any or port 1023 for any port
                     // number > 1023
    __be16 dst_port; // number of port or 0 for any or port 1023 for any port
                     // number > 1023
    __u8 protocol;   // values from: prot_t
    ack_t ack;       // values from: ack_t
    __u8 action;     // valid values: NF_ACCEPT, NF_DROP
} __attribute__((packed)) rule_t;

typedef struct {
    unsigned long timestamp; // time of creation/update
    unsigned char protocol;  // values from: prot_t
    unsigned char action;    // valid values: NF_ACCEPT, NF_DROP
    __be32 src_ip;   // if you use this struct in userspace, change the type to
                     // unsigned int
    __be32 dst_ip;   // if you use this struct in userspace, change the type to
                     // unsigned int
    __be16 src_port; // if you use this struct in userspace, change the type to
                     // unsigned short
    __be16 dst_port; // if you use this struct in userspace, change the type to
                     // unsigned short
    reason_t reason; // rule#index, or values from: reason_t
    unsigned int count; // counts this line's hits
} __attribute__((packed)) log_row_t;

#endif // _FW_H_

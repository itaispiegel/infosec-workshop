#ifndef _RULES_H
#define _RULES_H

#include "parser.h"
#include "types.h"

#define MAX_RULES (50)
#define DEVICE_NAME_RULES "rules"

typedef enum {
    ACK_NO = 0x01,
    ACK_YES = 0x02,
    ACK_ANY = ACK_NO | ACK_YES,
} __attribute__((packed)) ack_t;

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

/**
 * Looks up the first rule matching the given packet and returns it.
 * If no matching rule is found, the function returns NULL.
 * @param packet The packet to match.
 * @return The first matching rule, or NULL if no matching rule is found.
 */
rule_t *lookup_matching_rule(packet_t *packet);

/**
 * Initialize the rules table device.
 * @param fw_sysfs_class The class to which the device will belong.
 */
int init_rules_table_device(struct class *fw_sysfs_class);

/**
 * Destroy the rules table device.
 * @param fw_sysfs_class The class to which the device belongs.
 */
void destroy_rules_table_device(struct class *fw_sysfs_class);

#endif // _RULES_H

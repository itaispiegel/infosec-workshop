#ifndef _LOGS_H_
#define _LOGS_H_

#include <linux/device.h>
#include <linux/list.h>

#include "parser.h"
#include "rules.h"
#include "types.h"

#define DEVICE_NAME_LOG "log"
#define DEVICE_NAME_SHOW_LOGS "fw_log"
#define DEVICE_NAME_RESET_LOGS "reset"

#define RESET_MAGIC "reset"
#define RESET_MAGIC_SIZE sizeof(RESET_MAGIC)

typedef enum {
    REASON_FW_INACTIVE = -1,
    REASON_NO_MATCHING_RULE = -2,
    REASON_XMAS_PACKET = -4,
    REASON_ILLEGAL_VALUE = -6,
    REASON_RELATED_CONNECTION = -8,
} __attribute__((packed)) reason_t;

typedef struct {
    unsigned long timestamp; // time of creation/update
    prot_t protocol;         // values from: prot_t
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

struct log_entry {
    log_row_t log_row;
    struct list_head list;
};

/**
 * Update the log entry matching a given packet, reason and verdict pair.
 * @param packet The packet to match.
 * @param reason The reason to match.
 * @param verdict The packet's verdict.
 */
void update_log_entry_by_packet(packet_t *packet, reason_t reason,
                                __u8 verdict);

/**
 * Updates the log for TCP packets with ACK or RST flags.
 * As opposed to @ref update_log_entry_by_packet, this function ignores the
 * direction of the packet.
 * Specifically related connections might have a connection entry in the table,
 * but not a log. In case that we don't find a log entry, we assume the given
 * packet is related to an established connection, so we create a log entry for
 * it with the reason REASON_RELATED_CONNECTION and with the verdict accept.
 * @param packet The packet to match.
 */
void update_established_tcp_conn_log(packet_t *packet);

/**
 * Initialize the device that shows the logs.
 * @param fw_sysfs_class The class to which the device will belong.
 * @return 0 on success, a negative value on failure.
 */
int init_show_logs_device(struct class *fw_sysfs_class);

/**
 * Initialize the device that resets the logs.
 * @param fw_sysfs_class The class to which the device will belong.
 * @return 0 on success, a negative value on failure.
 */
int init_reset_logs_device(struct class *fw_sysfs_class);

/**
 * Destroy the device that shows the logs.
 * @param fw_sysfs_class The class to which the device belongs.
 */
void destroy_show_logs_device(struct class *fw_sysfs_class);

/**
 * Destroy the device that resets the logs.
 * @param fw_sysfs_class The class to which the device belongs.
 */
void destroy_reset_logs_device(struct class *fw_sysfs_class);

#endif // _LOGS_H_

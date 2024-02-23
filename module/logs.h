#ifndef _LOGS_H_
#define _LOGS_H_

#include <linux/device.h>
#include <linux/list.h>

#include "types.h"

#define DEVICE_NAME_LOG "log"
#define DEVICE_NAME_SHOW_LOGS "fw_log"
#define DEVICE_NAME_RESET_LOGS "reset"

#define RESET_MAGIC "reset"
#define RESET_MAGIC_SIZE sizeof(RESET_MAGIC)

extern struct list_head logs_list;
extern size_t logs_count;
typedef enum {
    REASON_FW_INACTIVE = -1,
    REASON_NO_MATCHING_RULE = -2,
    REASON_XMAS_PACKET = -4,
    REASON_ILLEGAL_VALUE = -6,
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

#ifndef _LOGS_H_
#define _LOGS_H_

#include <linux/device.h>
#include <linux/list.h>

#include "fw.h"

static LIST_HEAD(logs_list);

struct log_entry {
    log_row_t log_row;
    struct list_head list;
};

// extern LIST_HEAD(logs_list);

int init_show_logs_device(struct class *fw_sysfs_class);
int init_reset_logs_device(struct class *fw_sysfs_class);
void destroy_show_logs_device(struct class *fw_sysfs_class);
void destroy_reset_logs_device(struct class *fw_sysfs_class);

#endif // _LOGS_H_

#ifndef _LOGS_H_
#define _LOGS_H_

#include <linux/device.h>

int init_show_logs_device(struct class *fw_sysfs_class);
int init_reset_logs_device(struct class *fw_sysfs_class);
void destroy_show_logs_device(struct class *fw_sysfs_class);
void destroy_reset_logs_device(struct class *fw_sysfs_class);

#endif // _LOGS_H_

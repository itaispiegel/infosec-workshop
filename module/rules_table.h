#ifndef _RULES_TABLE_H_
#define _RULES_TABLE_H_

#include "fw.h"

extern rule_t rules[MAX_RULES];
extern __u8 rules_count;

int init_rules_table_device(struct class *fw_sysfs_class);
void destroy_rules_table_device(struct class *fw_sysfs_class);

#endif // _RULES_TABLE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "hw2secws"
#define SYSFS_BASE_PATH "/sys/class/" MODULE_NAME "/" MODULE_NAME "/"
#define ACCEPTED_PKTS_COUNT_FILENAME SYSFS_BASE_PATH "accepted_pkts_count"
#define DROPPED_PKTS_COUNT_FILENAME SYSFS_BASE_PATH "dropped_pkts_count"
#define RESET_COUNTERS_FILENAME SYSFS_BASE_PATH "reset_counters"

unsigned int read_unsigned_int_from_file(const char *filename) {
    FILE *fp;
    unsigned int value;

    if ((fp = fopen(filename, "r")) == NULL) {
        printf("Error opening file %s\n", RESET_COUNTERS_FILENAME);
        exit(1);
    }
    fscanf(fp, "%u", &value);
    fclose(fp);

    return value;
}

unsigned int get_input_pkts_count() {
    return read_unsigned_int_from_file(ACCEPTED_PKTS_COUNT_FILENAME);
}

unsigned int get_dropped_pkts_count() {
    return read_unsigned_int_from_file(DROPPED_PKTS_COUNT_FILENAME);
}

void reset_counters() {
    FILE *fp;

    if ((fp = fopen(RESET_COUNTERS_FILENAME, "w")) == NULL) {
        printf("Error opening file %s\n", RESET_COUNTERS_FILENAME);
        exit(1);
    }

    fprintf(fp, "1");
    fclose(fp);
}

int main(int argc, char **argv) {
    unsigned int input_pkts_cout;
    unsigned int forward_pkts_cout;
    unsigned int total_pkts;

    if (argc > 2 || (argc == 2 && strncmp(argv[1], "0", 1) != 0)) {
        printf("Usage: %s [arg]\n", argv[0]);
        return 1;
    } else if (argc == 1) {
        input_pkts_cout = get_input_pkts_count();
        forward_pkts_cout = get_dropped_pkts_count();
        total_pkts = input_pkts_cout + forward_pkts_cout;

        printf("Firewall Packets Summary:\n");
        printf("Number of accepted packets: %u\n", input_pkts_cout);
        printf("Number of dropped packets: %u\n", forward_pkts_cout);
        printf("Total number of packets: %u\n", total_pkts);
    } else {
        reset_counters();
    }
    return 0;
}

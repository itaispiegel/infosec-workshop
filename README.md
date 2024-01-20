# infosec-workshop
My homework submission for Infosec Workshop at TAU, 2024 Fall Semester.

## HW1
In this exercise, we implemented a very basic firewall, which uses the [Linux Netfilter](https://en.wikipedia.org/wiki/Netfilter) framework, to hook on FORWARD and INPUT packets, and do:
- Block FORWARD packets, and log the message `*** Packet Dropped ***`.
- Accept local INPUT and OUTPUT packets, and log the message `*** Packet Accepted ***`.

## HW2
In this exercise, we extended the kernel module from the previous step, by adding a [sysfs](https://docs.kernel.org/filesystems/sysfs.html) interface for interacting with the kernel module from the userspace.
Then, we used this interface to implement the tool `fwsummary` which prints the packets counts.
Example:
```bash
./fwsummary
Firewall Packets Summary:
Number of accepted packets: 57
Number of dropped packets: 42
Total number of packets: 99
```

It's also possible to reset the counters by running:
```bash
./fwsummary 0
```

## HW3
In this exercise, we finally started implementing a real and useful firewall, which is stateless.
We received the [fw.h](module/fw.h) header file, which contains the basic definitions for the firewall, such as rules and logs.
Then, we were requested to implement a kernel module, which manages a static rules table (the size is defined in the header file) and accepts/drops FORWARD packets according to the table. The default policy of the firewall is DROP, meaning that every unmatched packet will be dropped.
The firewall also supports logging, such that every packet is added to the log table, which groups similar packets together.
The module exposes the following files:
- `/sys/class/fw/rules/rules` (RW permissions) - for reading and writing rules.
- `/dev/fw_log` (R permissions) - for reading the log.
- `/sys/class/fw/log/reset` (W permissions) for resetting the logs table.

We were also requested to implement a userspace program which interacts with the module through these device files.
The supported commands are:
- show_rules
- load_rules <path_to_rules_file>
- show_log
- clear_log

I chose to implement the userspace program in Go.
To setup Go in your environment, follow the installation instructions [here](https://go.dev/doc/install).

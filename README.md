# infosec-workshop
My homework submission for Infosec Workshop at TAU, 2024 Fall Semester

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

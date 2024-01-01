# infosec-workshop
My homework submission for Infosec Workshop at TAU, 2024 Fall Semester

## HW1
In this exercise, we implemented a very basic firewall, which uses the [Linux Netfilter](https://en.wikipedia.org/wiki/Netfilter) framework, to hook on FORWARD and INPUT packets, and do:
- Block FORWARD packets, and log the message `*** Packet Dropped ***`.
- Accept local INPUT and OUTPUT packets, and log the message `*** Packet Accepted ***`.

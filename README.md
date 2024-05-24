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

## HW4
### Stateful Connection Tracking
In this exercise, we extended the functionality of our firewall from the previous exercise to incorporate stateful features.
Now, it encompasses a TCP connections table, enabling it to track the state of each connection upon its establishment.
The states utilized in our firewall align with those typically employed in TCP, with transitions defined by the [TCP Finite State Machine](http://tcpipguide.com/free/t_TCPOperationalOverviewandtheTCPFiniteStateMachineF-2.htm).
Upon the arrival of a TCP SYN packet, the firewall compares it with the rules, and if a matching rule is found, and its verdict is accept, the connection is added to the table.
Otherwise, the firewall checks if the packet is part of an established session, and the verdict is decided accordingly.
The table is implemented with the kernel's hash table API, where the hash is calculated by the client and server addresses 4-tuple.

### Application Level Gateway
Additionally, we implemented an application level gateway, operating as a userspace program acting as a proxy.
We implemented two modules for it: an HTTP proxy, and an FTP proxy, running on ports 800 and 210 respectively.
When the firewall intercepts a packet destined for port 80 or 21, it forwards it to the corresponding module.
The proxy has an open session with the client, and initiates a new session with the server, thereby facilitating seamless data forwarding while enabling real-time inspection and manipulation of the data for enhanced client experience.

### HTTP Proxy
The HTTP proxy inspects the payload, looks at the `Content-Type` HTTP header, and blocks CSV and ZIP files.
In this case, it'll respond to the client that the content is blocked.

### FTP Proxy
FTP encompasses two operational modes: active and passive.
The classic vsftpd implementation in Linux, defaults to the active mode.
The purpose of the FTP proxy, is to facilitate the operation of this mode through the firewall.
In the active mode, the client connects to the server at port 21, and then sends it a PORT packet of the format: `PORT 10,1,1,1,57,83`.
In this packet the client announces that he'll be expecting the server to connect to the IP address `10.1.1.1` at port $57 * 256 + 83 = 14675$.
The server then connects to this endpoint, from the constant port 20.
This protocol poses challenges for NATs and Firewalls.
Fortunately, our application level gateway enables inspecction of PORT packets, allowing seamless passage of FTP data connections.
Upon establishment of such connections, the proxy writes the addresses to the file `/sys/class/fw/conn/related_conns`, and the kernel module adds the new connection to the table.
The new connection is considered a "related" session, as evidenced in the logs.


## HW5
This exercise consisted of two parts: implementing an IPS and implementing a DLP.
In the IPS part - each student received a CVE published in the last year (2023), and had to implement the firewall to protect from exploiting this CVE.
The CVE I received is [CVE-2023-34468](https://nvd.nist.gov/vuln/detail/CVE-2023-34468), and the implemetation details are described [here](./user/README.md#nifi-proxy).

In the DLP part, we were requested to be able to classify whether a text is C code, and then implement the firewall to block sending C source code outside the network with HTTP and SMTP.
The implementation details are described [here](./user/README.md#c-parser).

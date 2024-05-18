## Introduction
This directory contains the userspace program designed for firewall management.
This tool facilitates rules and log manipulation, and includes the HTTP, FTP, SMTP and NiFi proxies.
Implemented in Go, which can be installed from [here](https://go.dev/doc/install).

### Building & Running
```bash
go generate -v ./...
go build
./user
```

### Debugging
To debug the code, install the [Go Delve debugger](https://github.com/go-delve/delve), by running:
```bash
go install github.com/go-delve/delve/cmd/dlv
```

This will install the debugger by default to `~/go/bin/dlv`.
Then you can execute the following to debug your code:
```bash
sudo ~/go/bin/dlv debug -- <ARGS>
```
Notice that you will probably want to debug this with sudo permissions, since the program needs permissions to interact with the kernel module.
Delve's interface is very similar to GDB, so if you're familiar with it - you should be fine.

## Proxies
Our firewall is designed to be stateful. Meaning, it can manipulate sessions by the payload of the packets sent in the session.
This implementation is incorporated in the core of the firewall's kernel module.
Each packet in one of the supported protocols is routed to a userspace program (listening locally on a pre-known port) which runs as a proxy. This proxy serves as a middleware, allowing full control of the data sent in the session.
More description down below.

### HTTP Proxy
Implemented in stage 4 of the workshop, the HTTP proxy runs by default on port 800, and blocks CSV and ZIP files sent from the internal network, to the external.
The files are blocked according to the HTTP `Content-Type` header.
In stage 5, we added DLP, for disallowing C source code to be sent from the internal network to the external.
The DLP works by blocking packets having the `text/x-chdr` and `text/x-csrc` headers, and by blocking packets that can be parsed with our custom [cparser](#c-parser).

#### Testing the HTTP Server
Install apache2 by running:
```bash
sudo apt install -y apache2
sudo systemctl --now enable apache2
```
Then place the files in `/var/www/html`, and access them from the client by running:
```bash
curl http://10.1.2.2
```


### FTP Proxy
FTP is not very friendly with firewalls...<br/>
Implemented in stage 4, the FTP proxy runs by default on port 210.
In FTP the client first initiates the communication with the server, and then it sends it a port it will listen on ([FTP PORT command](https://www.techtarget.com/searchnetworking/tip/Understanding-the-FTP-PORT-command)).
The server receives this command, and connects to the client in the received port from port 20, and the files are sent this connection.
The purpose of this proxy is to allow this communication to work, and to make the firewall accept the data session.

### NiFi Proxy
Implemented in stage 5, the NiFi proxy runs by default on port 8444.
The purpose of this proxy is to protect from the exploitation of [CVE-2023-34468](https://nvd.nist.gov/vuln/detail/CVE-2023-34468).
This CVE allows an authenticated and authorized user to configure a database URL that enables custom code execution.
The protection works by blocking requests to the endpoint `/nifi-api/controller-services`, trying to set a database URL starting with `jdbc:h2`.
This protection is inspired by the official vulnerability fix that can be found [here](https://github.com/apache/nifi/pull/7349/files).

#### Testing the NiFi Setup
To test the NiFi setup, I installed from scratch an Ubuntu 22.04 VM for running the NiFi server, and a Kali 2024.1 to act as the NiFi client, running Metasploit.
Installation steps:
- Setup IP addresses for both VMs, and make sure they can communicate.
- Add an `/etc/hosts` entry for nifi.com in the Kali VM.
- Download NiFi 1.21.0 from [here](https://archive.apache.org/dist/nifi/1.21.0/nifi-1.21.0-bin.zip) to the Ubuntu VM.
- Extract the downloaded Zip file.
- cd to the directory.
- Change the following lines in `conf/nifi.properties`:
    ```
    nifi.web.https.host = nifi.com
    nifi.web.https.network.interface.default = YOUR_INTERFACE_NAME
    ```
- Run `bin/nifi.sh install`.
- Run `systemctl --now enable nifi`.

The official installation steps can be found [here](https://nifi.apache.org/docs/nifi-docs/html/getting-started.html#for-linuxmacos-users).

### SMTP Proxy
Implemented in stage 5, the SMTP proxy runs by default on port 250.
The purpose of this proxy is to block C source code being sent outside to the external network.
The proxy works by attempting to parse the packet as an SMTP message.
If the message's body can be parsed with our C parser, the packet is dropped.

#### Testing Sending Emails
To test sending emails, follow these steps on both hosts:
- Install the following packages:
    ```bash
    sudo apt install -y mailutils mutt postfix
    ```
    When installing, an ncruses installation menu for postfix will popup. Just use the default settings, but change the domain names to "client" and "server" on the hosts, respectively.

- Add the following host entries in `/etc/hosts`:
    ```
    10.1.1.1 client
    10.1.2.2 server
    ```

- Set the following configurations in `/etc/postfix/main.cf`:
    ```
    myhostname = client (or server, depending on the host)
    disable_dns_lookups = yes
    ```

- Restart postfix:
    ```bash
    systemctl restart postfix
    ```

- Use mutt to send an email from the client to the server, to this address: `fw@server`.
You can also use mutt to read the emails on the server.

### C Parser
In stage 5 we added a DLP protection layer, for blocking C source code being sent outside to the external network, in HTTP and SMTP packets.
A necessary step for adding this layer, is to be able to detect C source code, and this is done with a parser I implemented.
At first I thought about different approaches to tackle this challenge.
My first attempt was to use NLP and Machine Learning. I found some impressive looking open source classifiers for the detection of different programming languages, such as:
- https://guesslang.readthedocs.io/en/latest/
- https://huggingface.co/philomath-1209/programming-language-identification

Unfortunately though, I wasn't able to run them locally, since our VM is 32-bit, and they are supported only on 64-bit systems.

I then decided to go with a completely different approach, and take advantage of the tools I learned this semester, by taking the compilation course (0368-3133) 😎.
I decided to run the first two stages of the C compiler on the text; i.e running the lexer and the syntax analyzer.
I implemented it by defining C's formal grammar, and using [Bison](https://en.wikipedia.org/wiki/GNU_Bison) for generating an [LALR parser](https://en.wikipedia.org/wiki/LALR_parser).
For defining the formal grammar, I took inspiration from [here](https://www.lysator.liu.se/c/ANSI-C-grammar-y.html) and made adjustments.

Some of the considerations behind this approach:
- Running a custom parser with the first two phases is simplistic and yields good performance.

- By design, we don't want to run [semantic analysis](https://en.wikipedia.org/wiki/Semantic_analysis_(compilers)) on the source code.
This step involves type checking, and the management of the symbol table.
We don't want to have a symbol table, since we can receive partial code, and more specifically, we usually usually don't have all of the variables and functions defined in the received scope.
The downside of this approach, is that C code with type errors will pass successfully.
For example, this code will be considered perfectly fine: `int x = 5 + "A";`.

- The preprocessor runs as a separate step in the beginning, and only a small subset of it is implemented.
Our design is that lines ending with `\` are grouped together, and lines starting with `#` are detected as preprocessor directives, and we then check their type by the first word.
If the type is valid, we remove the line from the code and continue. Otherwise, we classify the text as non C code.
This also means that invalid directives of correct types are considered valid.
E.g `#endif aaaaaaaa` will be considered valid, but it isn't.
This was designed on purpose, as it wasn't cost effective to fully handle all the preprocessing cases.

- The preprocessor can use macros for using non-standard C syntax.
For example, consider this function defined in [Git's repository](https://github.com/git/git/tree/master):
    ```c
    static int reject_entry(const struct object_id *oid UNUSED,
                struct strbuf *base,
                const char *filename, unsigned mode,
                void *context)
    {
        ...
    }
    ```
    Notice the use of the `UNUSED` preprocessing macro.
    Our C parser detects this as an identifier token which is unexpected in this context, and therefore will classify this text as non C code.

- A popular C convention is to define typedefs with the `_t` suffix.
Some common typedefs are: `size_t`, `pid_t`, `loff_t`, `time_t`, and etc.
Since this is so common, I decided to define identifiers ending with `_t` as `TYPEDEF_NAME` tokens, instead of `IDENTIFIER` tokens.
This means that code such as: `int x_t = 5;` won't parse successfully, as the parser will parse this `IDENTIFIER TYPEDEF_NAME` which is invalid.
From my oversight, it's uncommon to define variables with this suffix, so it's better to have this tradeoff.

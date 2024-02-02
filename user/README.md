## Introduction
This directory contains the userspace program which is used to manage the firewall - save and load rules.
This program is implemented in Go, which can be installed from [here](https://go.dev/doc/install).

### Debugging
To debug the code, please install the [Go Delve debugger](https://github.com/go-delve/delve), by running:
```bash
go install github.com/go-delve/delve/cmd/dlv
```

This will install the debugger by default to `~/go/bin/dlv`.
Then you can execute the following to debug your code:
```bash
sudo ~/go/bin/dlv debug -- SOME_ARGS
```
Notice that you will probably want to debug this with sudo permissions, since the program needs permissions to interact with the kernel module.
Delve's interface is very similar to GDB, so if you're familiar with it - you should be fine.

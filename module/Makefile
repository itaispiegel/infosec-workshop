obj-m += firewall.o
firewall-objs := module.o rules_table.o logs.o netfilter_hook.o parser.o tcp_conntrack.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

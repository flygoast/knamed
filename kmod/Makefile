obj-m := knamed.o

#KDIR := /lib/modules/$(shell uname -r)/build
#PWD := $(shell pwd)

KDIR := /usr/src/kernels/2.6.32-431.el6.x86_64/

knamed-objs := knamed_main.o   	\
               knamed_procfs.o 	\
               knamed_sysctl.o 	\
               knamed_iptable.o	\
			   knamed_zone.o   	\
               knamed_util.o   	\
			   knamed_memory.o	\
			   knamed_radix.o   \
               knamed_dns.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

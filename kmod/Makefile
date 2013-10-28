obj-m := knamed.o
KDIR := /lib/modules/2.6.32-220.el6.x86_64/build
PWD := $(shell pwd)

knamed-objs := kn_main.o \
	kn_connector.o 		 \
	kn_conf.o 			 \
	kn_worker.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c \
		.tmp_versions *.symvers *.order *.ko.unsigned

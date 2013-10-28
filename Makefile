PREFIX		?= /usr/local
INSTALLDIR	?= $(PREFIX)/knamed
KERNELDIR := /lib/modules/2.6.32-220.el6.x86_64/build
all: utils module

.PHONY: utils
utils:
	$(MAKE) -C usr PWD=$(shell pwd)/usr all

.PHONY: module
module:
	$(MAKE) -C kmod KERNELDIR=$(KERNELDIR) PWD=$(shell pwd)/kmod all

clean:
	$(MAKE) -C usr clean
	$(MAKE) -C kmod clean

install:
	$(MAKE) -C usr INSTALLDIR=$(INSTALLDIR) install
	$(MAKE) -C kmod INSTALLDIR=$(INSTALLDIR) install

uninstall:
	$(MAKE) -C usr INSTALLDIR=$(INSTALLDIR) uninstall
	$(MAKE) -C kmod INSTALLDIR=$(INSTALLDIR) uninstall

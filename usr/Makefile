CC = gcc
CFLAGS = -g -O2 -Wall
LDFLAGS = 

CFLAGS += -I$(PWD)/../mod

knamed-obj = knamed.o 

all: knamed 

knamed: $(knamed-obj)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f knamed *.o

install:
	install -d $(INSTALLDIR)
	install -m 755 knamed $(INSTALLDIR)

uninstall:
	rm -f $(INSTALLDIR)/knamed

PKG_CONFIG ?= pkg-config
INSTALL ?= install

XTABLES_SO_DIR = $(shell $(PKG_CONFIG) xtables --variable xtlibdir)

CFLAGS = -O2 -Wall -I..

objs = libipt_L4SHENANIGAN_INVERT.so

all: $(objs)

.PHONY: install clean

install:
	for i in $(objs); do $(INSTALL) -m 755 $$i $(DESTDIR)${XTABLES_SO_DIR}; done

uninstall:
	for i in $(objs); do rm $(DESTDIR)${XTABLES_SO_DIR}/$$i; done

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean:
	rm -rf *.o *.so

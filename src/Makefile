BIN=\
  config-test\
  auth2cookie\
  oauth-request\
  oauth-receive\
  fetch-html\
  keygen\
  test-cgi\

all: $(BIN)

UTILDIR=../../idanlib/src
UTILSLIB=$(UTILDIR)/utils.a

LUADIR := $(shell $(UTILDIR)/lua-dir.sh)
LUALIB := $(shell $(UTILDIR)/lua-ver.sh)

INCLUDES=$(LUADIR) -I$(UTILDIR)
LIBS=$(UTILSLIB) -lm -lpthread -luuid $(LUALIB) -lcurl


CC=gcc
CFLAGS=-Wall -O2 -g $(INCLUDES)
# CFLAGS=-Wall -g -rdynamic -fsanitize=address $(INCLUDES)

SHAREDOBJ=\
  oauth.o\
  id-map.o\
  config.o\
  url.o\

ALLOBJ=\
  $(SHAREDOBJ)\

%.o: %.c $(wildcard *.h)
	$(CC) $(CFLAGS) -c $<

$(BIN): % : %.o $(ALLOBJ) $(UTILSLIB)
	$(CC) $(CFLAGS) -o $@ $< $(ALLOBJ) $(LIBS)

install: ui.html ui.css install-web.sh
	chmod 755 install-web.sh
	./install-web.sh

clean: NULL
	rm -f $(SHAREDOBJ) $(BIN)
	rm -f *.o

NULL:

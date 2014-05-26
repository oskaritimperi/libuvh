CC = gcc
LD = gcc
AR = ar

CFLAGS += -Wall -Wextra -g -O0
LDFLAGS +=
CPPFLAGS += -Isrc
LDLIBS += -luv

PLATFORM = $(shell uname -s | tr [A-Z] [a-z])

ifeq ($(findstring mingw32,$(PLATFORM)),mingw32)
LDLIBS += -lws2_32 -lpsapi -liphlpapi
else
endif

all: libuvh.a examples

.PHONY: examples
examples: hello chunked fileserver

libuvh.a: src/uvh.o src/http_parser.o src/sds.o
	$(AR) rcs $@ $^

hello: examples/hello.o libuvh.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

chunked: examples/chunked.o libuvh.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

fileserver: examples/fileserver.o libuvh.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f src/*.o
	rm -f examples/*.o
	rm -f libuvh.a
	rm -f hello
	rm -f chunked
	rm -f fileserver

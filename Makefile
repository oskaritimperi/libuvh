CC = gcc
LD = gcc
AR = ar

CFLAGS += -Wall -Wextra -g -O0
LDFLAGS +=
CPPFLAGS += -Isrc
LDLIBS += -luv

SH_LDFLAGS = $(LDFLAGS) -shared
SH_CFLAGS = $(CFLAGS) -DBUILDING_UVH_SHARED

PLATFORM = $(shell uname -s | tr [A-Z] [a-z])

ifeq ($(findstring mingw32,$(PLATFORM)),mingw32)
LDLIBS += -lws2_32 -lpsapi -liphlpapi
SHAREDNAME = libuvh.dll
else
SHAREDNAME = libuvh.so
SH_CFLAGS += -fPIC
endif

SOURCES = uvh.c http_parser.c sds.c
STATIC_OBJS = $(addprefix src/static_,$(SOURCES:.c=.o))
SHARED_OBJS = $(addprefix src/shared_,$(SOURCES:.c=.o))

.PHONY: all
all: static shared examples

.PHONY: static
static: libuvh.a

.PHONY: shared
shared: $(SHAREDNAME)

.PHONY: examples
examples: hello chunked fileserver

src/static_%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

src/shared_%.o: src/%.c
	$(CC) $(SH_CFLAGS) $(CPPFLAGS) -c -o $@ $<

libuvh.a: $(STATIC_OBJS)
	$(AR) rcs $@ $^

$(SHAREDNAME): $(SHARED_OBJS)
	$(LD) $(SH_LDFLAGS) -o $@ $^ $(LDLIBS)

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
	rm -f $(SHAREDNAME)

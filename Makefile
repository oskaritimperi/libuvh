CC = gcc
LD = gcc
AR = ar

CFLAGS += -Wall -g -O0
LDFLAGS +=
CPPFLAGS += -Isrc
LDLIBS += -luv

libuvh.a: src/uvh.o src/http_parser.o src/sds.o
	$(AR) rcs $@ $^

hello: examples/hello.o libuvh.a
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f src/*.o
	rm -f examples/*.o
	rm -f libuvh.a
	rm -f hello
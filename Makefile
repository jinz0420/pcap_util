objects = simple_tcpdump.o

program = simple_tcpdump

CC = gcc
LD = ld
LDFLAGS = -lpcap

all: $(program)

$(objects): %.o: %.c
	clang-format -i $<
	$(CC) -c $(CFLAGS) $< -o $@

$(program): $(objects)
	$(CC) $< -o $@ $(LDFLAGS)

clean:
	rm -f *.o $(program)

all: wvm

CC      = gcc
CFLAGS  = -fno-stack-protector -g -D_GNU_SOURCE

.c.o:   $(CC) $(CFLAGS) \
        -c -o $*.o $<

OBJS =  wvm.o classloader.o interp_engine.o vm_error.o trace.o libelf.o safe_printf.o log.o slab.o garbage_collect.o

wvm: $(OBJS)
	$(CC) -o wvm $(OBJS) -lpthread

clean:
	rm -f wvm *.o


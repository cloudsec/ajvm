ajvm:
	gcc -o ajvm jvm.c classloader.c interp_engine.c vm_error.c trace.c log.c -lpthread -g
clean:
	rm -f ajvm *.o

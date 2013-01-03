jvm:
	gcc -o jvm jvm.c classloader.c interp_engine.c trace.c log.c -lpthread -g
clean:
	rm -f jvm *.o

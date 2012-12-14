jvm:
	gcc -o jvm jvm.c classloader.c interp_engine.c log.c -lpthread -g
clean:
	rm -f jvm *.o

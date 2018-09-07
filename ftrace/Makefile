all: latency libftrace.o

latency: latency.c libftrace.h libftrace.o
	gcc -O2 -o latency latency.c libftrace.o

libftrace.o: libftrace.h libftrace.c
	gcc -O2 -c -o libftrace.o libftrace.c

clean:
	rm -f latency libftrace.o


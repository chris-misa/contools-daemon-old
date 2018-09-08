all: latency libftrace.o tests

tests: test_libftrace

latency: latency.c libftrace.h libftrace.o
	gcc -O2 -o latency latency.c libftrace.o

libftrace.o: libftrace.h libftrace.c
	gcc -O2 -c -o libftrace.o libftrace.c

test_libftrace: test_libftrace.c libftrace.c libftrace.h
	gcc -o test_libftrace test_libftrace.c

clean:
	rm -f latency libftrace.o


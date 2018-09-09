all: latency libftrace.o tests

tests: test_libftrace ftrace_dump

latency: latency.c libftrace.h libftrace.o
	gcc -O2 -o latency latency.c libftrace.o

libftrace.o: libftrace.h libftrace.c
	gcc -O2 -c -o libftrace.o libftrace.c

test_libftrace: test_libftrace.c libftrace.c libftrace.h
	gcc -o test_libftrace test_libftrace.c

ftrace_dump: ftrace_dump.c libftrace.c libftrace.h
	gcc -o ftrace_dump ftrace_dump.c libftrace.o

clean:
	rm -f latency libftrace.o test_libftrace ftrace_dump


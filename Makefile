all: iface_diff show_clock_opts ftrace_test ftrace_raw tests

iface_diff: iface_diff.c time_common.h libpcap_common.c
	gcc -O3 -o iface_diff iface_diff.c -lpcap -pthread

show_clock_opts: show_clock_opts.c
	gcc -o show_clock_opts show_clock_opts.c -lpcap

ftrace_test: ftrace_test.c ftrace_common.c time_common.h
	gcc -o ftrace_test ftrace_test.c

ftrace_raw: ftrace_raw.c
	gcc -o ftrace_raw ftrace_raw.c -lpthread

clean:
	rm -f iface_diff show_clock_opts ftrace_raw

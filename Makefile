all: iface_diff show_clock_opts

iface_diff: iface_diff.c time_common.h libpcap_common.c
	gcc -o iface_diff iface_diff.c -lpcap -pthread

show_clock_opts: show_clock_opts.c
	gcc -o show_clock_opts show_clock_opts.c -lpcap

clean:
	rm -f iface_diff show_clock_opts

//
// First stab at latencies using some absolutely simple heuristics
//
// Basically a state machine with the following states:
//   1) Read ftraces for sendto
//   2) Read echo request packet
//   3) Read ftraces for recvmsg
//   4) Read echo reply packet
//   5) Ignore anything until next sento ftrace
//

#include <stdio.h>
#include <stdlib.h>
#include "time_common.h"
#include "ftrace_common.c"
#include "libpcap_common.c"


static volatile int exiting = 0;
pcap_t *pcap_hdl;

void usage()
{
  printf("Usage: latencies <device> <pid>\n");
}

void do_exit()
{
  exiting = 1;
  pcap_breakloop(pcap_hdl);
}


int main(int argc, char *argv[])
{
  struct packet_event pcap_evt;
  int res;
  const char *ftrace_tracedir = "/sys/kernel/debug/tracing";
  FILE *ftrace_pipe;
  struct trace_event ftrace_evt;

  struct timeval ftrace_offset;
  ftrace_offset.tv_sec = 0;
  ftrace_offset.tv_usec = 0;

  struct timeval ping_send;
  struct timeval ping_recv;
  struct timeval iface_send;
  struct timeval iface_recv;

  if (argc != 3) {
    usage();
    exit(1);
  }

  signal(SIGINT, do_exit);

  // Get ftrace offset
  get_ftrace_ts_offset(ftrace_tracedir, &ftrace_offset);
  printf("Got ftrace offset: %lu.%06lu\n", ftrace_offset.tv_sec,
                                           ftrace_offset.tv_usec);

  // Set up libpcap
  pcap_hdl = get_capture(argv[1]);
  if (pcap_hdl == NULL) {
    printf("Failed to open pcap handle\n");
    exit(1);
  }

  // Set up ftrace
  ftrace_pipe = get_trace_pipe(ftrace_tracedir, argv[2]);
  if (ftrace_pipe == NULL) {
    printf("Failed to open trace pipe\n");
    release_capture(pcap_hdl);
    exit(1);
  }

  // main loop
  while (!exiting) {
    // Read ftrace events until enter sendto 
    do {
      get_trace_event(ftrace_pipe, &ftrace_evt);
    } while (ftrace_evt.type != EVENT_TYPE_ENTER_SENDTO);
    tvadd(&ftrace_evt.ts, &ftrace_offset);
    printf("[%10lu.%06lu] enter sendto\n",
            ftrace_evt.ts.tv_sec,
            ftrace_evt.ts.tv_usec);

    // Read ftrace events until exit sendto
    do {
      get_trace_event(ftrace_pipe, &ftrace_evt);
    } while (ftrace_evt.type != EVENT_TYPE_EXIT_SENDTO);
    tvadd(&ftrace_evt.ts, &ftrace_offset);
    printf("[%10lu.%06lu] exit sendto\n",
            ftrace_evt.ts.tv_sec,
            ftrace_evt.ts.tv_usec);

    // Read packets until echo request
    do {
      res = get_packet_event(pcap_hdl, &pcap_evt);
    } while (pcap_evt.type != PACKET_TYPE_ECHO_REQUEST);
    printf("[%10lu.%06lu] echo request\n",
            pcap_evt.ts.tv_sec,
            pcap_evt.ts.tv_usec);

    // Copy interface send time
    iface_send = pcap_evt.ts;
    

    // Read ftrace events until enter recvmsg
    do {
      get_trace_event(ftrace_pipe, &ftrace_evt);
    } while (ftrace_evt.type != EVENT_TYPE_ENTER_RECVMSG);
    tvadd(&ftrace_evt.ts, &ftrace_offset);
    printf("[%10lu.%06lu] enter recvmsg\n",
            ftrace_evt.ts.tv_sec,
            ftrace_evt.ts.tv_usec);

    // Read ftrace events until exit recvmsg
    do {
      get_trace_event(ftrace_pipe, &ftrace_evt);
    } while (ftrace_evt.type != EVENT_TYPE_EXIT_RECVMSG);
    tvadd(&ftrace_evt.ts, &ftrace_offset);
    printf("[%10lu.%06lu] exit recvmsg\n",
            ftrace_evt.ts.tv_sec,
            ftrace_evt.ts.tv_usec);

    // Read packets until echo reply
    do {
      res = get_packet_event(pcap_hdl, &pcap_evt);
    } while (pcap_evt.type != PACKET_TYPE_ECHO_REPLY);
    printf("[%10lu.%06lu] echo reply\n",
            pcap_evt.ts.tv_sec,
            pcap_evt.ts.tv_usec);

    // Copy interface receive time
    iface_recv = pcap_evt.ts;
    
    // Report actual RTT
    tvsub(&iface_recv, &iface_send);
    printf("Actuall RTT: %lu.%06lu\n",
            iface_recv.tv_sec,
            iface_recv.tv_usec);
  }
  
  // Clean up
  release_capture(pcap_hdl);

  printf("Done.\n");

  return 0;
}

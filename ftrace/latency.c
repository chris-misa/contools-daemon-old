#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "libftrace.h"
#include "../time_common.h"

#define TRACING_FS_PATH "/sys/kernel/debug/tracing"
#define TRACE_BUFFER_SIZE 0x1000
#define SKBADDR_BUFFER_SIZE 256

static volatile int running = 1;

void usage()
{
  fprintf(stdout, "Usage: latency <inner device> <outer device>\n");
}

void do_exit()
{
  running = 0;
}

int main(int argc, char *argv[])
{
  FILE *tp = NULL;
  int nbytes = 0;
  // This must match with events used in libftrace.h
  const char *events = "net:net_dev_queue net:netif_receive_skb";
  const char *inner_iface = NULL;
  const char *outer_iface = NULL;

  char buf[TRACE_BUFFER_SIZE];
  struct trace_event evt;

  struct timeval start_send_time;
  char send_skbaddr[SKBADDR_BUFFER_SIZE];
  struct timeval finish_send_time;
  int send_state = 0;

  struct timeval start_recv_time;
  char recv_skbaddr[SKBADDR_BUFFER_SIZE];
  struct timeval finish_recv_time;
  int recv_state = 0;

  if (argc != 3) {
    usage();
    return 1;
  }
  inner_iface = argv[1];
  outer_iface = argv[2];
  
  signal(SIGINT, do_exit);

  tp = get_trace_pipe(TRACING_FS_PATH, events, NULL);

  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe\n");
    return 1;
  }

  while (running) {
    // Read the next line from the trace pipe
    if (fgets(buf, TRACE_BUFFER_SIZE, tp) != NULL && running) {
      // If there's data, parse it
      trace_event_parse_str(buf, &evt);
      // Branch on event type
      switch (evt.type) {
        case EVENT_TYPE_NET_DEV_QUEUE:
          if (!strncmp(inner_iface, evt.dev, evt.dev_len)) {
            // Remember skbaddr for when we see it later
            memcpy(send_skbaddr, evt.skbaddr, evt.skbaddr_len);
            start_send_time = evt.ts;
          } else if (!strncmp(outer_iface, evt.dev, evt.dev_len)
                  && !strncmp(send_skbaddr, evt.skbaddr, evt.skbaddr_len)) {
            // skbaddr matched, this is same packet on outer iface!
            finish_send_time = evt.ts;
            tvsub(&finish_send_time, &start_send_time);
            fprintf(stdout, "send latency: %lu.%06lu\n", finish_send_time.tv_sec,
                                                         finish_send_time.tv_usec);
          }
          break;
        case EVENT_TYPE_NETIF_RECEIVE_SKB:
          if (!strncmp(outer_iface, evt.dev, evt.dev_len)) {
            // Remember skbaddr for when we see it later
            memcpy(recv_skbaddr, evt.skbaddr, evt.skbaddr_len);
            start_recv_time = evt.ts;
          } else if (!strncmp(inner_iface, evt.dev, evt.dev_len)
                  && !strncmp(recv_skbaddr, evt.skbaddr, evt.skbaddr_len)) {
            // skbaddr matched, this is same packet on inner iface!
            finish_recv_time = evt.ts;
            tvsub(&finish_recv_time, &start_recv_time);
            fprintf(stdout, "recv latency: %lu.%06lu\n", finish_recv_time.tv_sec,
                                                         finish_recv_time.tv_usec);
          }
          break;
      }
    }
  }

  release_trace_pipe(tp, TRACING_FS_PATH);

  fprintf(stdout, "Done.\n");

  return 0;
}

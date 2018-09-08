#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "libftrace.h"
#include "../time_common.h"

#define TRACING_FS_PATH "/sys/kernel/debug/tracing"
#define TRACE_BUFFER_SIZE 0x1000

static volatile int running = 1;

void usage()
{
  fprintf(stdout, "Usage: latency <outer device> <pid_list>\n");
}

void do_exit()
{
  running = 0;
}

// Read a trace_event structure from the given pipe
// Caller is reponsible for freeing the pointer.
struct trace_event *
read_trace_event_from_pipe(FILE *pipe)
{
  char buf[TRACE_BUFFER_SIZE];
  if (fgets(buf, TRACE_BUFFER_SIZE, pipe) != NULL) {
    return trace_event_from_str(buf);
  } else {
    return NULL;
  }
}

int main(int argc, char *argv[])
{
  FILE *tp = NULL;
  int nbytes = 0;
  // This must match with events used in libftrace.h
  const char *events = "net:net_dev_queue net:net_dev_xmit";
  struct trace_event *evt;
  struct timeval start_send_time;
  struct timeval finish_send_time;

  if (argc != 3) {
    usage();
    return 1;
  }
  
  signal(SIGINT, do_exit);

  tp = get_trace_pipe(TRACING_FS_PATH, events, argv[2]);

  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe\n");
    return 1;
  }

  while (running) {
    do {
      evt = read_trace_event_from_pipe(tp);
    } while (evt == NULL || evt->type != EVENT_TYPE_START_SEND);
    start_send_time = evt->ts;

    do {
      evt = read_trace_event_from_pipe(tp);
    } while (evt == NULL
          || evt->type != EVENT_TYPE_FINISH_SEND
          || strcmp(evt->dev, argv[1]));
    finish_send_time = evt->ts;

    tvsub(&finish_send_time, &start_send_time);
    fprintf(stdout, "send: %lu.%06lu seconds\n",
      finish_send_time.tv_sec,
      finish_send_time.tv_usec);
  }

  release_trace_pipe(tp, TRACING_FS_PATH);

  fprintf(stdout, "Done.\n");
}

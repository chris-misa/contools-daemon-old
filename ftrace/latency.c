//
// Measure network latency between devices
// by reading ftrace events
//
// Must be plugged in to devices and events on those devices
// with an understanding of 1) how devices are routed in the kernel
// and 2) how the targeted measurement tool gathers timestamps.
//
// Basically the input is two 4-tuples, one describing the input path
// and one describing the output path.
//
// Input:
//   in_outer_dev:  The wire-facing device as named in the kernel
//   in_outer_func: The name of the event on this outer device which signifies reception of a packet
//   in_inner_dev:  The inner device as named in kernel (or container's netns)
//   in_inner_func: The event on the inner device which signifies reception of a packet (or location of the timestamping)
//
// Output:
//   out_inner_dev:  The inner device where userspace in the container dumps packets
//   out_inner_func: The event on the inner device which signifies sending of a packet
//   out_outer_dev:  The wire-facing device as named in the kernel
//   out_outer_func: The event signifying sending of a packet from the kernel boundary
//
// These fields should all be filled in in a conf file which is pointed to by the only argument
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "libftrace.h"
#include "../time_common.h"

#define TRACING_FS_PATH "/sys/kernel/debug/tracing"
#define CONFIG_LINE_BUFFER 1024
#define TRACE_BUFFER_SIZE 0x1000
#define SKBADDR_BUFFER_SIZE 256

static volatile int running = 1;

char *in_outer_dev = NULL;
char *in_outer_func = NULL;
char *in_inner_dev = NULL;
char *in_inner_func = NULL;

char *out_inner_dev = NULL;
char *out_inner_func = NULL;
char *out_outer_dev = NULL;
char *out_outer_func = NULL;

char *ftrace_set_events = NULL;

void
usage()
{
  fprintf(stdout, "Usage: latency <configuration file>\n");
}

void
do_exit()
{
  running = 0;
}

// Parse the given config file and set globals
// Returns 0 on success, nonzero on error
int
parse_config_file(const char *filepath)
{
  FILE *fp = NULL;
  char buf[CONFIG_LINE_BUFFER];
  char *bufp = NULL,
       *bufp2 = NULL;
  int len;
  char **target = NULL;
  unsigned char complete = 0;

  fp = fopen(filepath, "r");
  if (!fp) {
    fprintf(stderr, "Failed to open config file '%s'\n", filepath);
    return -1;
  }

  while (fgets(buf, CONFIG_LINE_BUFFER, fp) != NULL) {
    bufp = buf;
    while (*bufp != ':' && *bufp != '\0') {
      bufp++;
    }
    if (*bufp == ':') {
      len = bufp - buf;
      if (!strncmp("in_outer_dev", buf, len)) {
        target = &in_outer_dev;
        complete |= 1;
      } else if (!strncmp("in_outer_func", buf, len)) {
        target = &in_outer_func;
        complete |= 1 << 1;
      } else if (!strncmp("in_inner_dev", buf, len)) {
        target = &in_inner_dev;
        complete |= 1 << 2;
      } else if (!strncmp("in_inner_func", buf, len)) {
        target = &in_inner_func;
        complete |= 1 << 3;
      } else if (!strncmp("out_inner_dev", buf, len)) {
        target = &out_inner_dev;
        complete |= 1 << 4;
      } else if (!strncmp("out_inner_func", buf, len)) {
        target = &out_inner_func;
        complete |= 1 << 5;
      } else if (!strncmp("out_outer_dev", buf, len)) {
        target = &out_outer_dev;
        complete |= 1 << 6;
      } else if (!strncmp("out_outer_func", buf, len)) {
        target = &out_outer_func;
        complete |= 1 << 7;
      }

      bufp++;
      bufp2 = bufp;

      while (*bufp2 != '\n' && *bufp2 != '\0') {
        bufp2++;
      }

      len = bufp2 - bufp;

      *target = (char *)malloc(sizeof(char) * (len + 1));
      strncpy(*target, bufp, len);
      (*target)[len] = '\0';
    }
    // Otherwise syntax error, ignore the line
  }

  if (complete != 0xff) {
    fprintf(stderr, "Incomplete config file\n");
    return -2;
  }

  len = strlen(in_outer_func)
      + strlen(in_inner_func)
      + strlen(out_inner_func)
      + strlen(out_outer_func)
      + 4; // add 4: three spaces plus on \0
  ftrace_set_events = (char *)malloc(len);
  *ftrace_set_events = '\0';
  strcat(ftrace_set_events, in_outer_func);
  strcat(ftrace_set_events, " ");
  strcat(ftrace_set_events, in_inner_func);
  strcat(ftrace_set_events, " ");
  strcat(ftrace_set_events, out_inner_func);
  strcat(ftrace_set_events, " ");
  strcat(ftrace_set_events, out_outer_func);

  return 0;
}

void
print_stats(long long unsigned int send_sum,
                 unsigned int send_num,
                 long long unsigned int recv_sum,
                 unsigned int recv_num)
{
  long long unsigned int send_mean;
  long long unsigned int recv_mean;

  if (send_num) {
    send_mean = send_sum / send_num;
  } else {
    send_mean = 0;
  }

  if (recv_num) {
    recv_mean = recv_sum / recv_num;
  } else {
    recv_mean = 0;
  }

  fprintf(stdout, "\nLatency stats:\n");
  fprintf(stdout, "send mean: %f ms\n", (float)send_mean / 1000.0);
  fprintf(stdout, "recv mean: %f ms\n", (float)recv_mean / 1000.0);
  fprintf(stdout, "rtt  mean: %f ms\n",
      (float)(send_mean + recv_mean) / 1000.0);
}

int main(int argc, char *argv[])
{
  FILE *tp = NULL;
  int nbytes = 0;

  char buf[TRACE_BUFFER_SIZE];
  struct trace_event evt;

  char send_skbaddr[SKBADDR_BUFFER_SIZE];
  struct timeval start_send_time;
  struct timeval finish_send_time;
  long long unsigned int send_sum = 0;
  unsigned int send_num = 0;

  char recv_skbaddr[SKBADDR_BUFFER_SIZE];
  struct timeval start_recv_time;
  struct timeval finish_recv_time;
  long long unsigned int recv_sum = 0;
  unsigned int recv_num = 0;

  if (argc != 2) {
    usage();
    return 1;
  }

  parse_config_file(argv[1]);

  fprintf(stdout, "in_outer_dev:   %s\n", in_outer_dev);
  fprintf(stdout, "in_outer_func:  %s\n", in_outer_func);
  fprintf(stdout, "in_inner_dev:   %s\n", in_inner_dev);
  fprintf(stdout, "in_inner_func:  %s\n", in_inner_func);
  fprintf(stdout, "out_inner_dev:  %s\n", out_inner_dev);
  fprintf(stdout, "out_inner_func: %s\n", out_inner_func);
  fprintf(stdout, "out_outer_dev:  %s\n", out_outer_dev);
  fprintf(stdout, "out_outer_func: %s\n", out_outer_func);
  fprintf(stdout, "events: %s\n", ftrace_set_events);
  
  signal(SIGINT, do_exit);

  tp = get_trace_pipe(TRACING_FS_PATH, ftrace_set_events, NULL);

  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe\n");
    return 1;
  }

  while (running) {
    // Read the next line from the trace pipe
    if (fgets(buf, TRACE_BUFFER_SIZE, tp) != NULL && running) {
      // If there's data, parse it
      trace_event_parse_str(buf, &evt);
      // Handle events
      if (!strncmp(in_outer_func, evt.func_name, evt.func_name_len)
       && !strncmp(in_outer_dev, evt.dev, evt.dev_len)) {
        // Got a inbound event on outer dev
        memcpy(recv_skbaddr, evt.skbaddr, evt.skbaddr_len);
        recv_skbaddr[evt.skbaddr_len] = '\0';
        start_recv_time = evt.ts;
      } else
      if (!strncmp(in_inner_func, evt.func_name, evt.func_name_len)
       && !strncmp(in_inner_dev, evt.dev, evt.dev_len)
       && !strncmp(recv_skbaddr, evt.skbaddr, evt.skbaddr_len)) {
        // Got a inbound event on inner dev and the skbaddr matches
        finish_recv_time = evt.ts;
        tvsub(&finish_recv_time, &start_recv_time);
        if (finish_recv_time.tv_usec < 1000) {
          fprintf(stdout, "recv latency: %lu.%06lu\n",
                  finish_recv_time.tv_sec,
                  finish_recv_time.tv_usec);
          recv_sum += finish_recv_time.tv_sec * 1000000
                    + finish_recv_time.tv_usec;
          recv_num++;
        } else {
          fprintf(stdout, "discarded recv: %lu.%06lu\n",
                  finish_recv_time.tv_sec,
                  finish_recv_time.tv_usec);
        }

      } else
      if (!strncmp(out_inner_func, evt.func_name, evt.func_name_len)
       && !strncmp(out_inner_dev, evt.dev, evt.dev_len)) {
        // Got a outbound event on inner dev
        memcpy(send_skbaddr, evt.skbaddr, evt.skbaddr_len);
        send_skbaddr[evt.skbaddr_len] = '\0';
        start_send_time = evt.ts;
      } else
      if (!strncmp(out_outer_func, evt.func_name, evt.func_name_len)
       && !strncmp(out_outer_dev, evt.dev, evt.dev_len)
       && !strncmp(send_skbaddr, evt.skbaddr, evt.skbaddr_len)) {
        // Got a outbound event on outer dev and the skbaddr matches
        finish_send_time = evt.ts;
        tvsub(&finish_send_time, &start_send_time);
        if (finish_send_time.tv_usec < 1000) {
          fprintf(stdout, "send latency: %lu.%06lu\n",
                  finish_send_time.tv_sec,
                  finish_send_time.tv_usec);
          send_sum += finish_send_time.tv_sec * 1000000
                    + finish_send_time.tv_usec;
          send_num++;
        } else {
          fprintf(stdout, "discarded send: %lu.%06lu\n",
                  finish_send_time.tv_sec,
                  finish_send_time.tv_usec);
        }
      
      }
    }
  }

  release_trace_pipe(tp, TRACING_FS_PATH);

  print_stats(send_sum, send_num, recv_sum, recv_num);

  fprintf(stdout, "Done.\n");

  return 0;
}

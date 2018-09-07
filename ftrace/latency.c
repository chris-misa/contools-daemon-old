#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "libftrace.h"

#define TRACING_FS_PATH "/sys/kernel/debug/tracing"
#define TRACE_BUFFER_SIZE 256

static volatile int running = 1;

void usage()
{
  fprintf(stdout, "Usage: latency . . .\n");
}

void do_exit()
{
  running = 0;
}

int main(int argc, char *argv[])
{
  FILE *tp;
  char buf[TRACE_BUFFER_SIZE];
  
  signal(SIGINT, do_exit);

  tp = get_trace_pipe(TRACING_FS_PATH, "net:*", NULL);

  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe\n");
    return 1;
  }

  while (running) {
    fgets(buf, TRACE_BUFFER_SIZE, tp);
    fprintf(stdout, "%s\n", buf);
  }

  release_trace_pipe(tp, TRACING_FS_PATH);

  fprintf(stdout, "Done.\n");
}
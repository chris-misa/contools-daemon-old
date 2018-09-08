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
  fprintf(stdout, "Usage: latency pid_list\n");
}

void do_exit()
{
  running = 0;
}

int main(int argc, char *argv[])
{
  FILE *tp = NULL;
  char buf[TRACE_BUFFER_SIZE];
  int nbytes = 0;

  if (argc != 2) {
    usage();
    return 1;
  }
  
  signal(SIGINT, do_exit);

  tp = get_trace_pipe(TRACING_FS_PATH, "net:*", argv[1]);

  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe\n");
    return 1;
  }

  while (running) {
    // fgets(buf, TRACE_BUFFER_SIZE, tp);
    nbytes = fread(buf, 1, TRACE_BUFFER_SIZE - 1, tp);
    if (nbytes > 0) {
      buf[nbytes] = '\0';
      fprintf(stdout, "%s\n", buf);
    }
  }

  release_trace_pipe(tp, TRACING_FS_PATH);

  fprintf(stdout, "Done.\n");
}

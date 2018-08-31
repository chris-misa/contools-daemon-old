#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <stdint.h>

#define BUF_SIZE 64

static int exiting = 0;

// Structs for parsing raw trace data
struct page_header {
  uint64_t timestamp;
  uint64_t commit;
  uint8_t  overwrite;
  char * data;
};

struct entry_header {
  uint32_t type_len_time_delta;
  uint32_t array;
};
  
struct trace_common {
  uint16_t common_type;
  uint8_t  common_flags;
  uint8_t  common_preempt_count;
  uint32_t common_pid;
};

void usage()
{
  printf("ftrace_test [pid]\n");
}

void stop_running() {
  exiting = 1;
}

// Simply write into the given file and close
void echo_to(const char *file, const char *data)
{
  FILE *fp = fopen(file, "w");
  int res;
  if (fp == NULL) {
    fprintf(stderr, "Failed to open file '%s' for writing\n", file);
    return;
  }
  res = fputs(data, fp);
  if (res == EOF) {
    fprintf(stderr, "Failed writing to '%s'\n", file);
  }
  fclose(fp);
}

// Allocate and open a pipe to each cpu
void get_pipe_per_cpu(FILE **pipes, int ncpus)
{
  int i;
  char path[128];
  
  for (i=0; i<ncpus; i++) {
    sprintf(path, "per_cpu/cpu%d/trace_pipe", i);
    pipes[i] = fopen(path, "r");
    if (!pipes[i]) {
      fprintf(stderr, "Failed to open %s\n", path);
    }
  }
}

// Close pipes
void release_pipe_per_cpu(FILE **pipes, int ncpus)
{
  int i;
  
  for (i=0; i<ncpus; i++) {
    if (pipes[i]) {
      fclose(pipes[i]);
    }
  }
}

void print_bytes(unsigned char *bytes, int nbytes)
{
  int i;
  for (i=0; i<nbytes; i++) {
    printf("%X ", bytes[i]);
    if (!((i+1) % 16)) {
      printf("\n");
    }
  }
}

// Pipe reading thread entrypoint
void *read_pipe(void *pipe)
{
  unsigned char buf[BUF_SIZE];
  size_t nbytes;
  int i;

  // Loop until the main thread kills us
  while (1) {
    nbytes = fread(buf, 1, BUF_SIZE, (FILE *)pipe);
    if (!exiting) {
      fprintf(stderr, "read %lu bytes\n", nbytes);
      print_bytes(buf, nbytes);
    } else {
      break;
    }
  }
}

int main(int argc, char *argv[])
{
  const char *tracefp = "/sys/kernel/debug/tracing";
  int ncpus;
  FILE **trace_pipes = NULL;
  pthread_t *threads = NULL;
  int i;

  ncpus = get_nprocs();
  trace_pipes = (FILE **)malloc(sizeof(FILE *) * ncpus);
  threads = (pthread_t *)malloc(sizeof(pthread_t) * ncpus);

  // Set exit trap
  signal(SIGINT, stop_running);

  // Move into tracing directory
  chdir(tracefp);

  // Enter desired events
  echo_to("current_tracer", "nop");
  echo_to("set_event", "syscalls:sys_enter_sendto syscalls:sys_exit_sendto syscalls:sys_enter_recvmsg syscalls:sys_exit_recvmsg");
  if (argc == 2) {
    echo_to("set_event_pid", argv[1]);
  } else {
    echo_to("set_event_pid", "");
  }

  echo_to("trace", "");
  echo_to("tracing_on", "1");

  get_pipe_per_cpu(trace_pipes, ncpus);
  
  // Spawn threads
  for (i = 0; i < ncpus; i++) {
    pthread_create(&threads[i], NULL, read_pipe, (void *)trace_pipes[i]);
  }

  // Main loop
  while (!exiting) {
    sleep(1);
  }

  // Kill our workers so we can close the files
  for (i = 0; i < ncpus; i++) {
    pthread_kill(threads[i], SIGINT);
  }
  for (i = 0; i < ncpus; i++) {
    pthread_join(threads[i], NULL);
  }

  release_pipe_per_cpu(trace_pipes, ncpus);

  // Reset ftrace state
  echo_to("tracing_on", "0");
  echo_to("set_event_pid", "");
  echo_to("set_event", "");


  printf("Done\n");

  return 0;
}

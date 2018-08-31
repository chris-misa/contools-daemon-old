#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void usage()
{
  printf("ftrace_test pid\n");
}

// Simply write into the given file and close
void echo_to(const char *file, const char *data)
{
  FILE *fp = fopen(file, "w");
  int res;
  if (fp == NULL) {
    printf("Failed to open file: '%s'\n", file);
    return;
  }
  res = fputs(data, fp);
  if (res == EOF) {
    printf("Failed writing to: '%s'\n", file);
  }
  fclose(fp);
}

int main(int argc, char *argv[])
{
  const char *tracefp = "/sys/kernel/debug/tracing";
  FILE *trace_pipe;
  char buf[100];
  int pid;

  if (argc != 2) {
    usage();
    exit(1);
  }

  chdir(tracefp);
  echo_to("current_tracer", "nop");
  echo_to("set_event", "syscalls:sys_enter_sendto syscalls:sys_exit_sendto syscalls:sys_enter_recvmsg syscalls:sys_exit_recvmsg");
  echo_to("set_event_pid", argv[1]);
  echo_to("trace_clock","global");
  echo_to("tracing_on", "1");

  trace_pipe = fopen("trace_pipe","r");

  if (trace_pipe == NULL) {
    printf("Failed to open trace pipe\n");
    exit(1);
  }
  
  while (1) {
    fgets(buf, 100, trace_pipe);
    printf("Read: %s\n", buf);
  }

  echo_to("tracing_on", "0");
  echo_to("set_event_pid", "");
  echo_to("set_event", "");

  return 0;
}

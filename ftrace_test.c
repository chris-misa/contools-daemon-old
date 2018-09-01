#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define READ_BUF_SIZE 256
#define NAME_BUF_SIZE 64

static volatile int running = 1;

void usage()
{
  printf("ftrace_test pid\n");
}

void do_exit()
{
  running = 0;
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


// Ugly parse of text string read from pipe
// In the future this will be replaced by binary reads

enum event_types {
  EVENT_TYPE_NONE,
  EVENT_TYPE_ENTER_SENDTO,
  EVENT_TYPE_EXIT_SENDTO,
  EVENT_TYPE_ENTER_RECVMSG,
  EVENT_TYPE_EXIT_RECVMSG
};

struct trace_event {
  struct timeval   ts;
  enum event_types type;
};

// Parse a string read from pipe into trace_event struct
void parse_trace_event(char *str, struct trace_event *evt)
{
  int dot_count = 0;
  char *end = NULL;
  int name_len = 0;
  char name_buf[NAME_BUF_SIZE];
  
  evt->ts.tv_sec = 0;
  evt->ts.tv_usec = 0; 
  evt->type = EVENT_TYPE_NONE;
  
  // Look for four dot separator
  while (dot_count < 4 && *str != '\0') {
    if (*str != '.') {
      dot_count = 0;
    } else {
      dot_count++;
    }
    str++;
  } 

  // Get seconds and micro seconds
  evt->ts.tv_sec = strtol(str, &end, 10);
  str = end + 1; // skip the decimal point
  evt->ts.tv_usec = strtol(str, &end, 10);
  str = end + 6; // skip the colon, space, and 'sys_' prefix

  // get the event type string
  end = str;
  while (*end != ' ' && *end != '(' && *end != '\0') {
    end++;
  }
  
  name_len = end - str;
  // silently truncate if longer than buffer
  if (name_len > NAME_BUF_SIZE) {
    name_len = NAME_BUF_SIZE;
  }
  memcpy(name_buf, str, name_len);   
  name_buf[name_len] = '\0';

  if (*end == '(') {
    // Entering a syscall, figure out which
    if (!strcmp(name_buf, "sendto")) {
      evt->type = EVENT_TYPE_ENTER_SENDTO;
    } else if (!strcmp(name_buf, "recvmsg")) {
      evt->type = EVENT_TYPE_ENTER_RECVMSG;
    }
  } else {
    // Exiting a syscall, figure out which
    if (!strcmp(name_buf, "sendto")) {
      evt->type = EVENT_TYPE_EXIT_SENDTO;
    } else if (!strcmp(name_buf, "recvmsg")) {
      evt->type = EVENT_TYPE_EXIT_RECVMSG;
    }
  }
}

FILE *get_trace_pipe(const char *debug_fs_path, const char *pid)
{
  chdir(debug_fs_path);
  echo_to("current_tracer", "nop");
  echo_to("set_event", "syscalls:sys_enter_sendto syscalls:sys_exit_sendto syscalls:sys_enter_recvmsg syscalls:sys_exit_recvmsg");
  echo_to("set_event_pid", pid);
  echo_to("trace_clock","global");
  echo_to("tracing_on", "1");

  return fopen("trace_pipe","r");
}

void release_trace_pipe(FILE *tp, const char *debug_fs_path)
{
  fclose(tp);
  chdir(debug_fs_path);
  echo_to("tracing_on", "0");
  echo_to("set_event_pid", "");
  echo_to("set_event", "");
}

void get_trace_event(FILE *tp, struct trace_event *evt)
{
  char buf[READ_BUF_SIZE];
  fgets(buf, READ_BUF_SIZE, tp);
  parse_trace_event(buf, evt);
}

int main(int argc, char *argv[])
{
  const char *tracefp = "/sys/kernel/debug/tracing";
  FILE *trace_pipe;
  struct trace_event evt;

  if (argc != 2) {
    usage();
    exit(1);
  }

  // Set interupt handler
  signal(SIGINT, do_exit);

  // Set up tracing
  trace_pipe = get_trace_pipe(tracefp, argv[1]);
  if (trace_pipe == NULL) {
    printf("Failed to open trace pipe\n");
    exit(1);
  }
  
  // Read trace pipe until interupt
  while (1) {
    // Read the pipe
    get_trace_event(trace_pipe, &evt);
    // Do some stuff
    if (running) {
      printf("[%lu.%06lu] ", evt.ts.tv_sec, evt.ts.tv_usec);
      switch (evt.type) {
        case EVENT_TYPE_ENTER_SENDTO:
          printf("enter_sendto\n");
          break;
        case EVENT_TYPE_EXIT_SENDTO:
          printf("exit_sendto\n");
          break;
        case EVENT_TYPE_ENTER_RECVMSG:
          printf("enter_recvmsg\n");
          break;
        case EVENT_TYPE_EXIT_RECVMSG:
          printf("exit_recvmsg\n");
          break;
      }
    } else {
      break;
    }
  }

  // Clean up a bit
  release_trace_pipe(trace_pipe, tracefp);

  printf("Done.\n");

  return 0;
}

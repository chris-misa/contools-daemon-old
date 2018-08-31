#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READ_BUF_SIZE 256
#define NAME_BUF_SIZE 64

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

struct trace_event *get_trace_event(char *str)
{
  struct trace_event *evt;
  int dot_count = 0;
  char *end = NULL;
  int name_len = 0;
  char name_buf[NAME_BUF_SIZE];
  
  evt = (struct trace_event *)malloc(sizeof(struct trace_event));
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

  fprintf(stderr, "Found dots, ");

  // Get seconds and micro seconds
  evt->ts.tv_sec = strtol(str, &end, 10);
  str = end + 1; // skip the decimal point
  evt->ts.tv_usec = strtol(str, &end, 10);
  str = end + 6; // skip the colon, space, and 'sys_' prefix

  fprintf(stderr, "timestamp: %lu.%06lu, ", evt->ts.tv_sec,
                                              evt->ts.tv_usec);

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

  fprintf(stderr, "event name: %s\n\n", name_buf);

  return evt;
}

void free_trace_event(struct trace_event *evt)
{
  free(evt);
}



int main(int argc, char *argv[])
{
  const char *tracefp = "/sys/kernel/debug/tracing";
  FILE *trace_pipe;
  char buf[READ_BUF_SIZE];
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
    fgets(buf, READ_BUF_SIZE, trace_pipe);
    fprintf(stderr, "Read: %s\n", buf);
    get_trace_event(buf);
  }

  echo_to("tracing_on", "0");
  echo_to("set_event_pid", "");
  echo_to("set_event", "");

  return 0;
}

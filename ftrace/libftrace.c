//
// Helpful functions for dealing with ftrace system
//

#include "libftrace.h"

// Simply write into the given file and close
// Used for controlling ftrace via tracing filesystem
// Returns 1 if the write was successful, otherwise 0
int echo_to(const char *file, const char *data)
{
  FILE *fp = fopen(file, "w");
  if (fp == NULL) {
    return 0;
  }
  if (fputs(data, fp) == EOF) {
    return 0;
  }
  fclose(fp);
  return 1;
}

// Get an open file pointer to the trace_pipe
// and set things up in the tracing filesystem
// If anything goes wrong, returns NULL
FILE *get_trace_pipe(const char *debug_fs_path, const char *target_events, const char *pid)
{
  FILE *tp = NULL;
  if (chdir(debug_fs_path)) {
    fprintf(stderr, "Failed to get into tracing file path.\n");
    return NULL;
  }
  // If the first write fails, we probably don't have permissions so bail
  if (!echo_to("trace", "")) {
    fprintf(stderr, "Failed to write in tracing fs.\n");
    return NULL;
  }
  echo_to("trace_pipe", "");
  echo_to("current_tracer", "nop");
  echo_to("trace_clock", "global");
  if (target_events) {
    echo_to("set_event", target_events);
  }
  if (pid) {
    echo_to("set_event_pid", pid);
  }

  echo_to("tracing_on", "1");

  tp = fopen("trace_pipe","r");
  
  if (!tp) {
    fprintf(stderr, "Failed to open trace pipe.\n");
    release_trace_pipe(NULL, debug_fs_path);
    return NULL;
  }
  
  return tp;
}

// Closes the pipe and turns things off in tracing filesystem
void release_trace_pipe(FILE *tp, const char *debug_fs_path)
{
  if (tp) {
    fclose(tp);
  }
  if (chdir(debug_fs_path)) {
    fprintf(stderr, "Failed to get into tracing file path.\n");
    return;
  }
  echo_to("tracing_on", "0");
  echo_to("set_event_pid", "");
  echo_to("set_event", "");
}



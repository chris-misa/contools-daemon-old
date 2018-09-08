//
// Helpful functions for dealing with ftrace system
//

#include <unistd.h>
#include <stdio.h>

#ifndef LIBFTRACE_H
#define LIBFTRACE_H

#define EVENT_START_SEND_FUNC_NAME "net_dev_queue"
#define EVENT_FINISH_SEND_FUNC_NAME "net_dev_xmit"


// Get an open file pointer to the trace_pipe
// and set things up in the tracing filesystem
// If anything goes wrong, returns NULL
FILE *get_trace_pipe(const char *debug_fs_path, const char *target_events, const char *pid);

// Closes the pipe and turns things off in tracing filesystem
void release_trace_pipe(FILE *tp, const char *debug_fs_path);

// Event types can be mapped to different functions for
// experimental purposes but the general framework stays the same
enum event_type {
  EVENT_TYPE_UNKNOWN,
  EVENT_TYPE_START_SEND,
  EVENT_TYPE_FINISH_SEND,
  EVENT_TYPE_START_RECV,
  EVENT_TYPE_FINISH_RECV
};

// This struct might need to be extended for correlation purposes later
struct trace_event {
  enum event_type type;
  struct timeval ts;
  char *dev;
  char *skbaddr;
};

// Parse a string into a newly allocated trace_event struct
struct trace_event *trace_event_from_str(char *str);

// Free an allocated trace_event struct
void trace_event_free(struct trace_event *evt);

// Print the given event to stdout for debuging
void trace_event_print(struct trace_event *evt);

#endif

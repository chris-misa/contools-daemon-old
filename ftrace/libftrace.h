//
// Helpful functions for dealing with ftrace system
//

#include <unistd.h>
#include <stdio.h>

#ifndef LIBFTRACE_H
#define LIBFTRACE_H


// Get an open file pointer to the trace_pipe
// and set things up in the tracing filesystem
// If anything goes wrong, returns NULL
FILE *get_trace_pipe(const char *debug_fs_path, const char *target_events, const char *pid);

// Closes the pipe and turns things off in tracing filesystem
void release_trace_pipe(FILE *tp, const char *debug_fs_path);

// Parse ftrace report strings into a struct
enum event_type {
  NET_DEV_QUEUE,
  NET_DEV_XMIT,
  NETIF_RECEIVE_SKB_ENTRY,
  NETIF_RECEIVE_SKB
};

struct trace_event {
  enum event_type type;
  struct timeval ts;
  char *dev;
  char *skbaddr;
};

// Parse a string into a newly allocated trace_event struct
struct trace_event * trace_event_from_str(char *str);

// Free an allocated trace_event struct
void trace_event_free(struct trace_event *evt);

#endif

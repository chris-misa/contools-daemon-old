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

// Event types can be mapped to different functions for
// experimental purposes but the general framework stays the same
enum event_type {
  EVENT_TYPE_UNKNOWN,
  EVENT_TYPE_NET_DEV_QUEUE,
  EVENT_TYPE_NETIF_RECEIVE_SKB
};

// This struct might need to be extended for correlation purposes later
struct trace_event {
  enum event_type type;
  struct timeval ts;
  char *dev;
  int dev_len;
  char *skbaddr;
  int skbaddr_len;
};

// Parses the str into a trace_event struct
// The trave_event is a shallow representaiont:
// all strings in the trace_event struct still point to the original.
void trace_event_parse_str(char *str, struct trace_event *evt);

// Print the given event to stdout for debuging
void trace_event_print(struct trace_event *evt);

#endif

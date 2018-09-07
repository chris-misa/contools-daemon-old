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

#endif

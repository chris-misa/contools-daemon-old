//
// Helpful functions for dealing with ftrace system
//
// Using text-based interface as I don't currently have time
// to crack the binary interface and the overheads on packet
// latency seem to be similar anyway.
//
// 2018, Chris Misa
//

#include <stdlib.h>
#include <string.h>

#include "libftrace.h"

// Simply write into the given file and close
// Used for controlling ftrace via tracing filesystem
// Returns 1 if the write was successful, otherwise 0
int
echo_to(const char *file, const char *data)
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
// If anything goes wrong, returns NULL and resets things
FILE *
get_trace_pipe(const char *debug_fs_path, const char *target_events, const char *pid)
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
void
release_trace_pipe(FILE *tp, const char *debug_fs_path)
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

// Skip space characters
void
parse_skip_whitespace(char **str)
{
  while(**str == ' ') {
    (*str)++;
  }
}

// Skip non-space character which we don't care about
void
parse_skip_nonwhitespace(char **str)
{
  while(**str != ' ') {
    (*str)++;
  }
}

// Parse dot-separated time into timeval
void
parse_timestamp(char **str, struct timeval *time)
{
  char *start = *str;
  time->tv_sec = strtoul(start, str, 10);
  start = *str + 1;
  time->tv_usec = strtoul(start, str, 10);
  // Skip trailing colon
  (*str)++;
}

// Parse the given field as a string
void
parse_field(char **str, const char *field_name, char **result)
{
  const char *field_name_ptr = field_name;
  int len = 0;

find_field_name:
  while (*field_name_ptr != '\0' && **str != '\0') {
    if (**str == *field_name_ptr) {
      field_name_ptr++;
    } else {
      field_name_ptr = field_name;
    }
    (*str)++;
  }
  if (**str == '=') {
    (*str)++;
    while ((*str)[len] != '\0' && (*str)[len] != ' ') {
      len++;
    }
    *result = (char *)malloc(sizeof(char) * len + 1);
    if (!*result) {
      return;
    }
    memcpy(*result, *str, len);
    (*result)[len] = '\0';
    (*str) += len;
  } else {
    if (**str != '\0') {
      field_name_ptr = field_name;
      goto find_field_name;
    }
  }
}

// Parse a string into a newly allocated trace_event struct
// Returns NULL if anything goes wrong
struct trace_event *
trace_event_from_str(char *str)
{
  struct trace_event *evt = NULL;

  evt = (struct trace_event *)malloc(sizeof(struct trace_event));
  if (!evt) {
    return NULL;
  }

  parse_skip_whitespace(&str);
  parse_skip_nonwhitespace(&str); // Proc id an number
  parse_skip_whitespace(&str);
  parse_skip_nonwhitespace(&str); // CPU
  parse_skip_whitespace(&str);
  parse_skip_nonwhitespace(&str); // Flags
  parse_skip_whitespace(&str);
  parse_timestamp(&str, &evt->ts);          // Time stamp
  // get Function name here
  parse_field(&str, "dev", &evt->dev); // Device
  parse_field(&str, "skbaddr", &evt->skbaddr); // skb address
  
  return evt;
}


// Free an allocated trace_event struct
void
trace_event_free(struct trace_event *evt)
{
  if (evt) {
    if (evt->dev) free(evt->dev);
    if (evt->skbaddr) free(evt->skbaddr);
    free(evt);
  }
}

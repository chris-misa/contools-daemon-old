#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

#include "time_common.h"
#include "libpcap_common.c"

#define ECHO_EVENT_TABLE_SIZE 128

#define ECHO_EVENT_DEV1_OUTBOUND_FLAG 1
#define ECHO_EVENT_DEV2_OUTBOUND_FLAG (1 << 1)
#define ECHO_EVENT_DEV1_INBOUND_FLAG  (1 << 2)
#define ECHO_EVENT_DEV2_INBOUND_FLAG  (1 << 3)
#define ECHO_EVENT_READY \
    ( ECHO_EVENT_DEV1_OUTBOUND_FLAG \
    | ECHO_EVENT_DEV2_OUTBOUND_FLAG \
    | ECHO_EVENT_DEV1_INBOUND_FLAG \
    | ECHO_EVENT_DEV2_INBOUND_FLAG )

static volatile int running = 1;

// Statically allocated table of echo events
struct echo_event {
  struct {
    struct timeval dev[2];
  } outbound;
  struct {
    struct timeval dev[2];
  } inbound;
  int seq;
  unsigned char flags;
  pthread_mutex_t flags_lock;
} echo_event_table[ECHO_EVENT_TABLE_SIZE];

// Get hash index into above array from seq number.
// Since icmp seq values are a simple increasing sequence,
// use a super simple hash function for now and
// don't worry about collisions.
static inline int echo_event_hash_seq(int seq) {
  return seq % ECHO_EVENT_TABLE_SIZE;
}

// Write some zeros!
void echo_event_table_init()
{
  int i;
  for (i = 0; i < ECHO_EVENT_TABLE_SIZE; i++) {
    echo_event_table[i].seq = 0;
    echo_event_table[i].flags = 0;
  }
}

// Handle finished event
// Assumes that dev1 is closer to ping and dev2 is farther
void echo_event_finish(struct echo_event *evt)
{
  // Compute outbound latency
  tvsub(&evt->outbound.dev[1], &evt->outbound.dev[0]);
  // Compute inbound latency
  tvsub(&evt->inbound.dev[0], &evt->inbound.dev[1]);


  // Dump info to stdout
  fprintf(stdout, "seq: %d, outbound: %lu.%06lu, inbound: %lu.%06lu\n",
    evt->seq,
    evt->outbound.dev[1].tv_sec, evt->outbound.dev[1].tv_usec,
    evt->inbound.dev[0].tv_sec, evt->inbound.dev[0].tv_usec);

  // Reset flags!
  evt->flags = 0;
}

struct dev_cap {
  pcap_t *hdl;
  const char *dev_name;
  int dev_id;
};

void *follow_capture(void *cap)
{
  struct dev_cap *dc = (struct dev_cap *)cap;
  const char *echo_request_str = "echo request";
  const char *echo_reply_str = "echo reply";
  const char *unknown_str = "unknown type";
  const char **msg = &unknown_str;

  struct icmp icmp_hdr;
  struct timeval tstamp;
  struct timeval *tstamp_target;
  unsigned char flag;


  struct echo_event *evt = NULL;

  while (running) {
    if (get_icmp_packet(dc->hdl, &icmp_hdr, &tstamp)) {

      // Get a pointer into the echo events table
      evt = echo_event_table 
        + echo_event_hash_seq(ntohs(icmp_hdr.icmp_hun.ih_idseq.icd_seq));

      // Reset loop variables
      tstamp_target = NULL;
      flag = 0;

      // Add sequence on first access
      if (!evt->flags) {
        evt->seq = ntohs(icmp_hdr.icmp_hun.ih_idseq.icd_seq);
      }

      // Branch on message type
      switch (icmp_hdr.icmp_type) {
        case ICMP_ECHO:
          msg = &echo_request_str;

          // Branch on device
          if (dc->dev_id == 0) {
            tstamp_target = &evt->outbound.dev[0];
            flag = ECHO_EVENT_DEV1_OUTBOUND_FLAG;
          } else {
            tstamp_target = &evt->outbound.dev[1];
            flag = ECHO_EVENT_DEV2_OUTBOUND_FLAG;
          }
          break;
        case ICMP_ECHOREPLY:
          msg = &echo_reply_str;

          // Branch on device
          if (dc->dev_id == 0) {
            tstamp_target = &evt->inbound.dev[0];
            flag = ECHO_EVENT_DEV1_INBOUND_FLAG;
          } else {
            tstamp_target = &evt->inbound.dev[1];
            flag = ECHO_EVENT_DEV2_INBOUND_FLAG;
          }
          break;
        default:
          msg = &unknown_str;
          break;
      }
      
#ifdef DEBUG
      // Dump some info to stdout
      fprintf(stdout, "[%lu.%06lu] %s id: %d seq: %d dev: %d\n",
          tstamp.tv_sec,
          tstamp.tv_usec,
          *msg,
          ntohs(icmp_hdr.icmp_hun.ih_idseq.icd_id),
          ntohs(icmp_hdr.icmp_hun.ih_idseq.icd_seq),
          dc->dev_id);
#endif

      // Only update if one of above cases happened
      // incase we captured a non-echo icmp message
      if (tstamp_target) {
  
        // Atomically update the echo event and check if it is finished
        pthread_mutex_lock(&evt->flags_lock);
        *tstamp_target = tstamp;
        evt->flags |= flag;
        if (evt->flags == ECHO_EVENT_READY) {
          pthread_mutex_unlock(&evt->flags_lock);
          echo_event_finish(evt);
        } else {
          pthread_mutex_unlock(&evt->flags_lock);
        }
      }
    }
  }
}


void do_exit()
{
  running = 0;
}

void usage()
{
  fprintf(stdout, "Usage: iface_diff <dev1> <dev2>\n");
  fprintf(stdout, "  Assumes that dev1 is closer to ping and dev2 is farther\n");
}

int main(int argc, char *argv[])
{
  pthread_t cap1_thread;
  pthread_t cap2_thread;
  struct dev_cap cap1;
  struct dev_cap cap2;

  if (argc != 3) {
    usage();  
    exit(1);
  }

  signal(SIGINT, do_exit);

  echo_event_table_init();

  cap1.hdl = get_capture(argv[1]);
  cap1.dev_name = argv[1];
  cap1.dev_id = 0;
  cap2.hdl = get_capture(argv[2]);
  cap2.dev_name = argv[2];
  cap2.dev_id = 1;

  fprintf(stdout, "Starting capture between %s and %s\n",
      argv[1], argv[2]);

  pthread_create(&cap1_thread, NULL, follow_capture, (void *)&cap1);
  pthread_create(&cap2_thread, NULL, follow_capture, (void *)&cap2);

  while (running) {
    sleep(1);
  }


  fprintf(stdout, "Cleaning up. . .\n");

  pcap_breakloop(cap1.hdl);
  pcap_breakloop(cap2.hdl);
  pthread_kill(cap1_thread, SIGINT);
  pthread_kill(cap2_thread, SIGINT);
  pthread_join(cap1_thread, NULL);
  pthread_join(cap2_thread, NULL);

  release_capture(cap1.hdl);
  release_capture(cap2.hdl);

  fprintf(stdout, "Done.\n");

  return 0;
}

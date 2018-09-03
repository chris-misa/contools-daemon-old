#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "libpcap_common.c"

static volatile int running = 1;

void do_exit()
{
  running = 0;
}

void usage()
{
  fprintf(stdout, "Usage: iface_diff <dev1> <dev2>\n");
}

struct dev_cap {
  pcap_t *hdl;
  const char *name;
};

void *follow_capture(void *cap)
{
  struct packet_event evt;
  struct dev_cap *dc = (struct dev_cap *)cap;
  const char *echo_request_str = "echo request";
  const char *echo_reply_str = "echo reply";
  const char *unknown_str = "unknown type";
  const char **msg = &unknown_str;
  
  while (running) {
    if (get_packet_event(dc->hdl, &evt)) {
      switch (evt.type) {
        case PACKET_TYPE_ECHO_REQUEST:
          msg = &echo_request_str;
          break;
        case PACKET_TYPE_ECHO_REPLY:
          msg = &echo_reply_str;
          break;
        default:
          msg = &unknown_str;
          break;
      }
      fprintf(stdout, "[%lu.%06lu] %s (%s)\n",
          evt.ts.tv_sec,
          evt.ts.tv_usec,
          *msg,
          dc->name);
    }
  }
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

  cap1.hdl = get_capture(argv[1]);
  cap1.name = argv[1];
  cap2.hdl = get_capture(argv[2]);
  cap2.name = argv[2];

  pthread_create(&cap1_thread, NULL, follow_capture, (void *)&cap1);
  pthread_create(&cap2_thread, NULL, follow_capture, (void *)&cap2);

  while (running) {
    sleep(1);
  }

  pthread_kill(cap1_thread, SIGINT);
  pthread_kill(cap2_thread, SIGINT);

  pthread_join(cap1_thread, NULL);
  pthread_join(cap2_thread, NULL);

  fprintf(stdout, "Done.\n");

  return 0;
}
